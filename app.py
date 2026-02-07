#!/usr/bin/env python3
"""
Student Project Portal (Flask) — app.py

Designed for your CloudFormation setup:
- App EC2 (private subnet) runs this Flask app behind the ALB.
- DB EC2 (private subnet) runs MariaDB/MySQL.

Environment variables expected on the App EC2:
  DB_HOST=<DbPrivateIp from stack outputs>   (or injected via CFN UserData)
  DB_NAME=studentdb
  DB_USER=studentuser
  DB_PASSWORD=<your password>
  FLASK_SECRET_KEY=<random-long-string>

Optional:
  PORT=80
  LOG_LEVEL=INFO

Roles:
  1 = Admin
  2 = Supervisor/Lecturer
  3 = Student

Templates expected:
  templates/login.html
  templates/register.html
  templates/dashboard.html
  templates/feedback.html
  templates/notifications.html
"""

import os
import re
import ipaddress
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

import pymysql


# ---------------------------
# Config
# ---------------------------
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_NAME = os.getenv("DB_NAME", "studentdb")
DB_USER = os.getenv("DB_USER", "studentuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
PORT = int(os.getenv("PORT", "80"))
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "CHANGE-ME-VERY-LONG-RANDOM-STRING")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    # Cookie hardening
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # If you enable HTTPS (ACM on ALB), you can uncomment:
    # app.config["SESSION_COOKIE_SECURE"] = True

    CSRFProtect(app)

    with app.app_context():
        init_db()

    # --------------
    # Helpers
    # --------------
    def db_conn():
        return pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.Cursor,
            autocommit=True,
        )

    def client_ip() -> str:
        # Behind ALB: X-Forwarded-For is typically set
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            ip = xff.split(",")[0].strip()
        else:
            ip = request.remote_addr or ""
        try:
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            return "0.0.0.0"

    def require_login(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def require_role(*roles):
        def deco(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not session.get("user_id"):
                    return redirect(url_for("login"))
                if session.get("role") not in roles:
                    abort(403)
                return fn(*args, **kwargs)
            return wrapper
        return deco

    def audit(action: str, details: str = ""):
        try:
            uid = session.get("user_id")
            uname = session.get("username", "anonymous")
            role = session.get("role", 0)
        except Exception:
            uid, uname, role = None, "anonymous", 0

        ip = client_ip()
        ua = request.headers.get("User-Agent", "")[:255]

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_logs (user_id, username, role, action, details, ip, user_agent, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (uid, uname, role, action, details[:500], ip, ua, datetime.utcnow()),
                )

    def get_setting(key: str, default: str = "") -> str:
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM settings WHERE `key`=%s", (key,))
                row = cur.fetchone()
                return row[0] if row else default

    def set_setting(key: str, value: str):
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO settings (`key`, value) VALUES (%s,%s)
                    ON DUPLICATE KEY UPDATE value=VALUES(value)
                    """,
                    (key, value),
                )

    def notif_count_for_user(_user_id: int, role: int) -> int:
        # Everyone sees global notifications (role=0) plus their role notifications
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM notifications
                    WHERE target_role IN (0, %s)
                    """,
                    (role,),
                )
                return int(cur.fetchone()[0])

    def get_notifications(role: int):
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT message, created_at
                    FROM notifications
                    WHERE target_role IN (0, %s)
                    ORDER BY created_at DESC
                    LIMIT 50
                    """,
                    (role,),
                )
                return cur.fetchall()

    def load_dashboard_data(user_id: int, role: int):
        """
        Returns:
          projects: list tuples compatible with your dashboard.html indexing
          milestones_map: { assign_id: [(milestone_id, task, done_bool), ...] }
          feedbacks: list tuples compatible with your dashboard.html indexing
          audit_logs: list tuples compatible with your dashboard.html indexing
        """
        with db_conn() as conn:
            with conn.cursor() as cur:
                # Projects view differs by role
                if role == 3:
                    cur.execute(
                        """
                        SELECT a.id, a.title, a.description, a.repo_link, a.created_at,
                               u.id AS student_id, u.username AS student_username
                        FROM assignments a
                        JOIN users u ON u.id=a.student_id
                        WHERE a.student_id=%s
                        ORDER BY a.created_at DESC
                        """,
                        (user_id,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT a.id, a.title, a.description, a.repo_link, a.created_at,
                               u.id AS student_id, u.username AS student_username
                        FROM assignments a
                        JOIN users u ON u.id=a.student_id
                        ORDER BY a.created_at DESC
                        """
                    )
                projects = cur.fetchall()

                milestones_map = {}
                for p in projects:
                    assign_id = p[0]
                    cur.execute(
                        """
                        SELECT id, task, done
                        FROM milestones
                        WHERE assignment_id=%s
                        ORDER BY id ASC
                        """,
                        (assign_id,),
                    )
                    milestones_map[assign_id] = [(r[0], r[1], bool(r[2])) for r in cur.fetchall()]

                # Feedback reports shown to admins only (template checks role == 1)
                cur.execute(
                    """
                    SELECT created_at, type, message, username
                    FROM feedback
                    ORDER BY created_at DESC
                    LIMIT 100
                    """
                )
                fb = cur.fetchall()

                # Audit logs shown to admins only (template checks role == 1)
                cur.execute(
                    """
                    SELECT id, username, role, action, details, ip, created_at, user_agent
                    FROM audit_logs
                    ORDER BY created_at DESC
                    LIMIT 200
                    """
                )
                logs = cur.fetchall()

                return projects, milestones_map, fb, logs

    # ---------------------------
    # Routes
    # ---------------------------

    # ALB health check endpoint
    @app.get("/health")
    def health():
        return "OK", 200

    @app.get("/")
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/")
    def login_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, password_hash, role FROM users WHERE username=%s",
                    (username,),
                )
                row = cur.fetchone()

        if not row or not check_password_hash(row[2], password):
            flash("Invalid username or password.")
            audit("LOGIN_FAIL", f"username={username}")
            return redirect(url_for("login"))

        session["user_id"] = int(row[0])
        session["username"] = row[1]
        session["role"] = int(row[3])

        audit("LOGIN_OK", "")
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    @require_login
    def logout():
        audit("LOGOUT", "")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/register")
    def register():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    @app.post("/register")
    def register_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        role = int(request.form.get("role") or 3)

        if role != 3:
            flash("Only student self-registration is allowed.")
            return redirect(url_for("register"))

        if not USERNAME_RE.match(username):
            flash("Username must be 3–32 chars (letters/numbers/underscore).")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("register"))

        pwd_hash = generate_password_hash(password)

        try:
            with db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO users (username, password_hash, role, email, phone, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s)
                        """,
                        (username, pwd_hash, role, email, phone, datetime.utcnow()),
                    )
            flash("Account created. Please sign in.")
        except pymysql.err.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

        return redirect(url_for("login"))

    @app.get("/dashboard")
    @require_login
    def dashboard():
        user_id = int(session["user_id"])
        role = int(session["role"])
        username = session.get("username", "user")

        uploads_allowed = get_setting("uploads_allowed", "TRUE")
        notif_count = notif_count_for_user(user_id, role)

        projects, milestones_map, feedbacks, audit_logs = load_dashboard_data(user_id, role)

        return render_template(
            "dashboard.html",
            username=username,
            role=role,
            uploads_allowed=uploads_allowed,
            notif_count=notif_count,
            projects=projects,
            milestones=milestones_map,
            feedbacks=feedbacks,
            audit_logs=audit_logs,
        )

    @app.post("/toggle_security")
    @require_role(1)  # admin only
    def toggle_security():
        cur_val = get_setting("uploads_allowed", "TRUE").upper()
        new_val = "FALSE" if cur_val == "TRUE" else "TRUE"
        set_setting("uploads_allowed", new_val)
        audit("TOGGLE_UPLOADS", f"uploads_allowed={new_val}")
        return redirect(url_for("dashboard"))

    @app.get("/notifications")
    @require_login
    def notifications():
        role = int(session["role"])
        notifs = get_notifications(role)
        return render_template("notifications.html", notifications=notifs)

    @app.get("/feedback")
    @require_login
    def feedback():
        return render_template("feedback.html")

    @app.post("/feedback")
    @require_login
    def feedback_post():
        ftype = (request.form.get("type") or "Suggestion").strip()[:32]
        msg = (request.form.get("msg") or "").strip()

        if not msg:
            flash("Message cannot be empty.")
            return redirect(url_for("feedback"))

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO feedback (user_id, username, type, message, created_at)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (session["user_id"], session["username"], ftype, msg[:2000], datetime.utcnow()),
                )

        audit("FEEDBACK_SUBMIT", f"type={ftype}")
        flash("Thanks — submitted.")
        return redirect(url_for("dashboard"))

    @app.post("/submit")
    @require_role(3)  # student only
    def submit():
        uploads_allowed = get_setting("uploads_allowed", "TRUE").upper()
        if uploads_allowed != "TRUE":
            abort(403)

        title = (request.form.get("title") or "").strip()
        link = (request.form.get("link") or "").strip()
        desc = (request.form.get("desc") or "").strip()

        if not title or not link:
            flash("Title and GitHub Link are required.")
            return redirect(url_for("dashboard"))

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO assignments (student_id, title, repo_link, description, created_at)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (session["user_id"], title[:120], link[:400], desc[:800], datetime.utcnow()),
                )

        audit("PROJECT_SUBMIT", f"title={title}")
        flash("Project submitted.")
        return redirect(url_for("dashboard"))

    @app.post("/delete/<int:assign_id>")
    @require_role(1, 2)  # admin/lecturer
    def delete_assignment(assign_id: int):
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM milestones WHERE assignment_id=%s", (assign_id,))
                cur.execute("DELETE FROM assignments WHERE id=%s", (assign_id,))
        audit("PROJECT_DELETE", f"assignment_id={assign_id}")
        return redirect(url_for("dashboard"))

    @app.get("/toggle_milestone/<int:milestone_id>")
    @require_login
    def toggle_milestone(milestone_id: int):
        role = int(session["role"])
        uid = int(session["user_id"])

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT m.id, m.done, a.student_id
                    FROM milestones m
                    JOIN assignments a ON a.id=m.assignment_id
                    WHERE m.id=%s
                    """,
                    (milestone_id,),
                )
                row = cur.fetchone()
                if not row:
                    abort(404)

                done = bool(row[1])
                student_id = int(row[2])

                if role == 3 and student_id != uid:
                    abort(403)

                new_done = 0 if done else 1
                cur.execute("UPDATE milestones SET done=%s WHERE id=%s", (new_done, milestone_id))

        audit("MILESTONE_TOGGLE", f"milestone_id={milestone_id} new_done={new_done}")
        return redirect(url_for("dashboard"))

    @app.post("/add_milestone")
    @require_role(3)
    def add_milestone():
        uploads_allowed = get_setting("uploads_allowed", "TRUE").upper()
        if uploads_allowed != "TRUE":
            abort(403)

        assign_id = int(request.form.get("assign_id") or 0)
        task = (request.form.get("task") or "").strip()

        if not task:
            flash("Task cannot be empty.")
            return redirect(url_for("dashboard"))

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT student_id FROM assignments WHERE id=%s", (assign_id,))
                row = cur.fetchone()
                if not row:
                    abort(404)
                if int(row[0]) != int(session["user_id"]):
                    abort(403)

                cur.execute(
                    """
                    INSERT INTO milestones (assignment_id, task, done, created_at)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (assign_id, task[:200], 0, datetime.utcnow()),
                )

        audit("MILESTONE_ADD", f"assignment_id={assign_id}")
        return redirect(url_for("dashboard"))

    # ---------------------------
    # Error handlers
    # ---------------------------
    @app.errorhandler(403)
    def forbidden(_e):
        return "403 Forbidden", 403

    @app.errorhandler(404)
    def notfound(_e):
        return "404 Not Found", 404

    return app


# ---------------------------
# DB bootstrap
# ---------------------------
def init_db():
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        autocommit=True,
        cursorclass=pymysql.cursors.Cursor,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(32) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    role TINYINT NOT NULL DEFAULT 3,
                    email VARCHAR(255),
                    phone VARCHAR(32),
                    created_at DATETIME NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS assignments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_id INT NOT NULL,
                    title VARCHAR(120) NOT NULL,
                    repo_link VARCHAR(400) NOT NULL,
                    description VARCHAR(800),
                    created_at DATETIME NOT NULL,
                    CONSTRAINT fk_assign_student FOREIGN KEY (student_id)
                        REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS milestones (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    assignment_id INT NOT NULL,
                    task VARCHAR(200) NOT NULL,
                    done TINYINT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    CONSTRAINT fk_ms_assign FOREIGN KEY (assignment_id)
                        REFERENCES assignments(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS feedback (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    username VARCHAR(32) NOT NULL,
                    type VARCHAR(32) NOT NULL,
                    message TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    INDEX (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    message VARCHAR(500) NOT NULL,
                    target_role TINYINT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    INDEX (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NULL,
                    username VARCHAR(32) NOT NULL,
                    role TINYINT NOT NULL,
                    action VARCHAR(64) NOT NULL,
                    details VARCHAR(500) NOT NULL,
                    ip VARCHAR(64) NOT NULL,
                    user_agent VARCHAR(255) NOT NULL,
                    created_at DATETIME NOT NULL,
                    INDEX (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    `key` VARCHAR(64) PRIMARY KEY,
                    value VARCHAR(64) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )

            cur.execute(
                """
                INSERT INTO settings (`key`, value) VALUES ('uploads_allowed','TRUE')
                ON DUPLICATE KEY UPDATE value=value
                """
            )

            # Seed a default admin if none exists (username: admin / password: Admin@1234)
            cur.execute("SELECT COUNT(*) FROM users WHERE role=1")
            if int(cur.fetchone()[0]) == 0:
                admin_user = "admin"
                admin_pass = "Admin@1234"
                admin_hash = generate_password_hash(admin_pass)
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role, email, phone, created_at)
                    VALUES (%s,%s,1,%s,%s,%s)
                    """,
                    (admin_user, admin_hash, "admin@local", "000", datetime.utcnow()),
                )
                cur.execute(
                    """
                    INSERT INTO notifications (message, target_role, created_at)
                    VALUES (%s, 0, %s)
                    """,
                    ("Welcome to the Student Project Portal. Default admin: admin / Admin@1234 (change it).", datetime.utcnow()),
                )
    finally:
        conn.close()


# ---------------------------
# Main
# ---------------------------
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
