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

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "true").lower() == "true"

csrf = CSRFProtect(app)

# =========================
# DB Connection MySQL
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
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16).hex()
    return hashlib.sha256((password + salt).encode()).hexdigest(), salt

def is_password_complex(password):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*]", password)
    )

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

# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    return redirect(url_for("dashboard")) if "user_id" in session else redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        conn = get_db()
        try:
            with conn.cursor() as cursor:
                cursor.execute("CALL Sec_sp_GetUserAuth(%s)", (request.form["username"],))
                user = cursor.fetchone()

                if user:
                    uid, pw_hash, salt, role = user
                    if hash_password(request.form["password"], salt)[0] == pw_hash:
                        session["user_id"] = uid
                        session["role"] = role
                        session["username"] = request.form["username"]
                        return redirect(url_for("dashboard"))

                flash("Invalid credentials")
        finally:
            conn.close()
    return render_template("login.html")

# =========================
# REGISTER ROUTE
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if not request.form.get("consent"):
            flash("You must agree to PDPA.")
            return render_template("register.html")

        if not is_password_complex(request.form["password"]):
            flash("Weak password.")
            return render_template("register.html")

        pwd_hash, salt = hash_password(request.form["password"])
        role = 3  # Student

        phone_enc_key = os.getenv("PHONE_ENC_KEY", "change-me-phone-key")

        conn = get_db()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "CALL Sec_sp_RegisterUser(%s,%s,%s,%s,%s,%s,%s)",
                    (
                        request.form["username"],
                        pwd_hash,
                        salt,
                        request.form["email"],
                        request.form["phone"],
                        role,
                        phone_enc_key,   # ✅ 7th parameter
                    ),
                )
            conn.commit()
            flash("Registered successfully. Please login.")
            return redirect(url_for("login"))
        except Exception as e:
            conn.rollback()
            print(e)
            flash("Registration failed.")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/dashboard")
@role_required()
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
