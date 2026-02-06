# app.py (MySQL + PyMySQL + Flask-WTF CSRF)
# Secure defaults: env-based secrets, parameterized SQL (%s), no hardcoded creds,
# basic login rate-limit, maintenance window, session hardening, audit logging.

from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
import pymysql
import hashlib
import os
import re
from datetime import datetime, timedelta
from functools import wraps
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# =========================
# Security / Session Config
# =========================
app.secret_key = os.getenv("FLASK_SECRET", "dev_fallback_key_do_not_use_in_prod")

# Recommended secure cookie flags (work best when behind HTTPS / ALB)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "true").lower() == "true"

csrf = CSRFProtect(app)

# =========================
# DB Connection (MySQL)
# =========================
def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "StudentProjectDB"),
        port=int(os.getenv("DB_PORT", "3306")),
        cursorclass=pymysql.cursors.Cursor,
        autocommit=False,
        charset="utf8mb4",
    )

# =========================
# Utils
# =========================
def hash_password(password: str, salt: str | None = None):
    """
    Returns (hash, salt). Using SHA-256 + salt to match your current DB style.
    If allowed, upgrade later to bcrypt/argon2.
    """
    if not salt:
        salt = os.urandom(16).hex()
    pw_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    return pw_hash, salt

def is_password_complex(password: str) -> bool:
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*]", password)
    )

def is_login_allowed() -> bool:
    # Maintenance window: 3AM - 5AM
    return not (3 <= datetime.now().hour < 5)

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

# -------------------------
# Basic login rate limiting
# -------------------------
def _client_key():
    # If behind ALB, you can set X-Forwarded-For support safely only if you trust proxy.
    # For now, use remote_addr.
    return request.remote_addr or "unknown"

def _rate_limit_check():
    """
    In-memory per-process rate limit.
    Good enough for assignment/demo. For production, use Redis.
    """
    key = f"login_attempts:{_client_key()}"
    now = datetime.utcnow()

    attempts = session.get(key, [])
    # Keep only last 10 minutes
    attempts = [ts for ts in attempts if now - ts < timedelta(minutes=10)]

    if len(attempts) >= 10:
        return False, int((timedelta(minutes=10) - (now - attempts[0])).total_seconds())

    attempts.append(now)
    session[key] = attempts
    return True, 0

# =========================
# Audit logging helper
# =========================
def audit_log(conn, action_type: str, table_name: str, record_id: str | None, user_id: int | None, details: str):
    """
    Assumes a MySQL table: Sec_AuditLog or Sec.AuditLog equivalent.
    Adjust table/columns to match your schema.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO Sec_AuditLog (ActionType, TableName, RecordID, UserID, UserIP, Details)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (action_type, table_name, record_id, user_id, request.remote_addr, details),
            )
    except Exception:
        # Don't crash the app if audit insert fails (assignment demo stability)
        pass

# =========================
# Global injection
# =========================
@app.context_processor
def inject_globals():
    if "user_id" not in session:
        return {}

    try:
        conn = get_db()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM App_Notifications WHERE UserID = %s AND IsRead = 0",
                (session["user_id"],),
            )
            count = cursor.fetchone()[0]
        conn.close()
        return {
            "notif_count": count,
            "role": session.get("role"),
            "username": session.get("username"),
        }
    except Exception:
        return {}

# =========================
# Routes
# =========================
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not is_login_allowed():
            flash("Maintenance Mode (3AM-5AM)")
            return render_template("login.html")

        ok, wait_s = _rate_limit_check()
        if not ok:
            flash(f"Too many attempts. Try again in {wait_s}s.")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter username and password.")
            return render_template("login.html")

        conn = get_db()
        try:
            with conn.cursor() as cursor:
                # IMPORTANT: Use a stored proc that returns hashed password + salt,
                # NOT decrypted password.
                #
                # Expected returned columns example:
                # (UserID, PasswordHash, Salt, Role)
                #
                # If your procedure name differs, update it here.
                cursor.execute("CALL Sec_sp_GetUserAuth(%s)", (username,))
                user = cursor.fetchone()

                if user:
                    user_id = int(user[0])
                    stored_hash = user[1]
                    stored_salt = user[2]
                    role = int(user[3])

                    if hash_password(password, stored_salt)[0] == stored_hash:
                        session.clear()
                        session["user_id"] = user_id
                        session["role"] = role
                        session["username"] = username

                        audit_log(conn, "LOGIN_SUCCESS", "App_Users", str(user_id), user_id, f"User {username} logged in")
                        conn.commit()
                        conn.close()
                        return redirect(url_for("dashboard"))

                # Invalid
                audit_log(conn, "LOGIN_FAIL", "App_Users", None, None, f"Failed login attempt for {username}")
                conn.commit()
                flash("Invalid Credentials")
        except Exception as e:
            conn.rollback()
            print("Login error:", e)
            flash("Database Error")
        finally:
            conn.close()

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("consent"):
            flash("You must agree to PDPA.")
            return render_template("register.html")

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not phone or not password:
            flash("All fields are required.")
            return render_template("register.html")

        if not is_password_complex(password):
            flash("Weak Password (min 8, uppercase, number, special char).")
            return render_template("register.html")

        # Force role = 3 (Student)
        role = 3
        pwd_hash, salt = hash_password(password)

        conn = get_db()
        try:
            with conn.cursor() as cursor:
                # Use proc to insert user securely
                cursor.execute(
                    "CALL Sec_sp_RegisterUser(%s, %s, %s, %s, %s, %s)",
                    (username, pwd_hash, salt, email, phone, role),
                )
                audit_log(conn, "REGISTER", "App_Users", None, None, f"New registration: {username}")
            conn.commit()
            flash("Registered! Please Login.")
            return redirect(url_for("login"))
        except Exception as e:
            conn.rollback()
            print("Register error:", e)
            flash("Username likely exists (or DB error).")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/dashboard")
@role_required()  # any logged-in
def dashboard():
    conn = get_db()
    audit_logs = []
    feedbacks = []
    milestones = {}
    projects = []

    try:
        with conn.cursor() as cursor:
            # System config
            cursor.execute("SELECT ConfigValue FROM Sec_SystemConfig WHERE ConfigKey = %s", ("AllowUploads",))
            row = cursor.fetchone()
            uploads_allowed = row[0] if row else "FALSE"

            # Projects
            # If you implemented DB-side RLS, keep this query broad.
            # Otherwise, you should filter by user_id when role==3.
            cursor.execute(
                """
                SELECT A.AssignmentID, A.ProjectTitle, A.Description, A.GitHubLink, A.SubmittedBy, U.Username
                FROM App_Assignments A
                JOIN App_Users U ON A.SubmittedBy = U.UserID
                ORDER BY A.AssignmentID DESC
                """
            )
            projects = cursor.fetchall()

            # Admin-only panels
            if session.get("role") == 1:
                cursor.execute(
                    "SELECT * FROM Sec_AuditLog ORDER BY Timestamp DESC LIMIT 15"
                )
                audit_logs = cursor.fetchall()

                cursor.execute(
                    """
                    SELECT F.DateCreated, F.IssueType, F.Message, U.Username
                    FROM App_Feedback F
                    JOIN App_Users U ON F.SubmittedBy = U.UserID
                    ORDER BY F.DateCreated DESC
                    """
                )
                feedbacks = cursor.fetchall()

            # Milestones per assignment
            for p in projects:
                assignment_id = p[0]
                cursor.execute(
                    "SELECT MilestoneID, TaskName, IsCompleted FROM App_Milestones WHERE AssignmentID = %s",
                    (assignment_id,),
                )
                milestones[assignment_id] = cursor.fetchall()

        conn.close()
        return render_template(
            "dashboard.html",
            projects=projects,
            audit_logs=audit_logs,
            feedbacks=feedbacks,
            milestones=milestones,
            uploads_allowed=uploads_allowed,
        )
    except Exception as e:
        print("Dashboard error:", e)
        conn.close()
        flash("Error loading dashboard.")
        return redirect(url_for("login"))

@app.route("/submit", methods=["POST"])
@role_required(3)  # student only
def submit():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT ConfigValue FROM Sec_SystemConfig WHERE ConfigKey = %s", ("AllowUploads",))
            allow = cursor.fetchone()
            if not allow or allow[0] == "FALSE":
                flash("Submissions Disabled")
            else:
                title = request.form.get("title", "").strip()
                desc = request.form.get("desc", "").strip()
                link = request.form.get("link", "").strip()

                if not title or not link:
                    flash("Title and GitHub link are required.")
                    return redirect(url_for("dashboard"))

                cursor.execute(
                    "INSERT INTO App_Assignments (ProjectTitle, Description, GitHubLink, SubmittedBy) VALUES (%s, %s, %s, %s)",
                    (title, desc, link, session["user_id"]),
                )
                audit_log(conn, "SUBMIT_PROJECT", "App_Assignments", None, session["user_id"], f"Submitted: {title}")
                conn.commit()
                flash("Project Submitted")
    except Exception as e:
        conn.rollback()
        print("Submit error:", e)
        flash("Submission failed.")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/delete/<int:assignment_id>", methods=["POST"])
@role_required(1, 2)  # admin/lecturer (adjust roles)
def delete_project(assignment_id):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM App_Assignments WHERE AssignmentID = %s", (assignment_id,))
            audit_log(conn, "DELETE_PROJECT", "App_Assignments", str(assignment_id), session["user_id"], "Deleted assignment")
        conn.commit()
        flash("Project Deleted")
    except Exception as e:
        conn.rollback()
        print("Delete error:", e)
        flash("Delete failed.")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/toggle_security", methods=["POST"])
@role_required(1)  # admin only
def toggle_security():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE Sec_SystemConfig
                SET ConfigValue = CASE WHEN ConfigValue = 'TRUE' THEN 'FALSE' ELSE 'TRUE' END
                WHERE ConfigKey = %s
                """,
                ("AllowUploads",),
            )
            audit_log(conn, "TOGGLE_SECURITY", "Sec_SystemConfig", "AllowUploads", session["user_id"], "Admin toggled upload permission")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("Toggle error:", e)
        flash("Toggle failed.")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/add_milestone", methods=["POST"])
@role_required(3)  # student only
def add_milestone():
    conn = get_db()
    try:
        assign_id = request.form.get("assign_id")
        task = request.form.get("task", "").strip()
        if not assign_id or not task:
            flash("Milestone task required.")
            return redirect(url_for("dashboard"))

        with conn.cursor() as cursor:
            # Optional: enforce student can only add milestone to their own assignment
            cursor.execute(
                "SELECT SubmittedBy FROM App_Assignments WHERE AssignmentID = %s",
                (assign_id,),
            )
            row = cursor.fetchone()
            if not row or int(row[0]) != int(session["user_id"]):
                abort(403)

            cursor.execute(
                "INSERT INTO App_Milestones (AssignmentID, TaskName, IsCompleted) VALUES (%s, %s, 0)",
                (assign_id, task),
            )
            audit_log(conn, "ADD_MILESTONE", "App_Milestones", None, session["user_id"], f"Assignment {assign_id}: {task}")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("Add milestone error:", e)
        flash("Add milestone failed.")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/toggle_milestone/<int:mid>")
@role_required()  # any logged in, but enforce ownership below
def toggle_milestone(mid):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # Join to verify ownership if student
            cursor.execute(
                """
                SELECT M.AssignmentID, A.SubmittedBy
                FROM App_Milestones M
                JOIN App_Assignments A ON A.AssignmentID = M.AssignmentID
                WHERE M.MilestoneID = %s
                """,
                (mid,),
            )
            row = cursor.fetchone()
            if not row:
                abort(404)

            submitted_by = int(row[1])
            role = session.get("role")

            # Students can only toggle their own milestones
            if role == 3 and submitted_by != int(session["user_id"]):
                abort(403)

            cursor.execute(
                "UPDATE App_Milestones SET IsCompleted = 1 - IsCompleted WHERE MilestoneID = %s",
                (mid,),
            )
            audit_log(conn, "TOGGLE_MILESTONE", "App_Milestones", str(mid), session["user_id"], "Toggled completion")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("Toggle milestone error:", e)
        flash("Toggle milestone failed.")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/notifications")
@role_required()
def notifications():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT Message, DateCreated FROM App_Notifications WHERE UserID = %s ORDER BY DateCreated DESC",
                (session["user_id"],),
            )
            data = cursor.fetchall()

            cursor.execute(
                "UPDATE App_Notifications SET IsRead = 1 WHERE UserID = %s",
                (session["user_id"],),
            )
        conn.commit()
        return render_template("notifications.html", notifications=data)
    except Exception as e:
        conn.rollback()
        print("Notifications error:", e)
        flash("Failed to load notifications.")
        return redirect(url_for("dashboard"))
    finally:
        conn.close()

@app.route("/feedback", methods=["GET", "POST"])
@role_required()
def feedback():
    if request.method == "POST":
        issue_type = request.form.get("type", "Suggestion").strip()
        msg = request.form.get("msg", "").strip()

        if not msg:
            flash("Message cannot be empty.")
            return render_template("feedback.html")

        conn = get_db()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO App_Feedback (SubmittedBy, IssueType, Message) VALUES (%s, %s, %s)",
                    (session["user_id"], issue_type, msg),
                )
                audit_log(conn, "FEEDBACK", "App_Feedback", None, session["user_id"], f"Type={issue_type}")
            conn.commit()
            flash("Feedback Sent.")
            return redirect(url_for("dashboard"))
        except Exception as e:
            conn.rollback()
            print("Feedback error:", e)
            flash("Failed to send feedback.")
        finally:
            conn.close()

    return render_template("feedback.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# =========================
# Error handlers (optional)
# =========================
@app.errorhandler(403)
def forbidden(_):
    return "403 Forbidden", 403

@app.errorhandler(404)
def not_found(_):
    return "404 Not Found", 404

if __name__ == "__main__":
    # In AWS, run behind gunicorn instead of debug=True.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
