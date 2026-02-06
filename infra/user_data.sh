cat > user_data.sh << 'EOF'
#!/bin/bash
set -e

# --- 1. Basic Updates & Install ---
yum update -y
yum install -y python3 git mysql
python3 -m pip install --upgrade pip

# --- 2. Create Directory Structure ---
mkdir -p /opt/student-portal/templates
cd /opt/student-portal

# --- 3. Install Python Dependencies ---
python3 -m pip install flask flask-wtf pymysql gunicorn cryptography

# --- 4. Write app.py ---
cat > app.py << 'PYEOF'
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
import pymysql
import hashlib
import os
import re
from datetime import datetime, timedelta
from functools import wraps
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# Security Config
app.secret_key = os.getenv("FLASK_SECRET", "dev_fallback_key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"

csrf = CSRFProtect(app)

# DB Connection
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

# Utils
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

# Routes
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
        except Exception as e:
            print(f"Login Error: {e}")
            flash("Login failed. Check DB connection.")
        finally:
            if 'conn' in locals(): conn.close()
    return render_template("login.html")

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
        role = 3 
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
                        phone_enc_key,  
                    ),
                )
            conn.commit()
            flash("Registered successfully. Please login.")
            return redirect(url_for("login"))
        except Exception as e:
            conn.rollback()
            print(f"Register Error: {e}")
            flash(f"Registration failed: {str(e)}")
        finally:
             if 'conn' in locals(): conn.close()
    return render_template("register.html")

@app.route("/dashboard")
@role_required()
def dashboard():
    return render_template("dashboard.html", 
                           username=session.get("username"), 
                           role=session.get("role"),
                           projects=[], 
                           milestones={}, 
                           notif_count=0)

@app.route("/notifications")
@role_required()
def notifications():
    return render_template("notifications.html", notifications=[])

@app.route("/feedback", methods=["GET", "POST"])
@role_required()
def feedback():
    if request.method == "POST":
        flash("Feedback submitted.")
        return redirect(url_for("dashboard"))
    return render_template("feedback.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
PYEOF

# --- 5. Write HTML Templates ---

# dashboard.html
cat > templates/dashboard.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f4f6f8; display: flex; margin: 0; }
        .sidebar { width: 250px; background: #343a40; color: white; min-height: 100vh; padding: 20px; }
        .sidebar a { display: block; color: #adb5bd; padding: 10px; text-decoration: none; }
        .sidebar a:hover { color: white; }
        .content { flex: 1; padding: 30px; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
<div class="sidebar">
    <h2>Portal</h2>
    <p>User: {{ username }}</p>
    <a href="/dashboard"><i class="fa fa-home"></i> Dashboard</a>
    <a href="/notifications"><i class="fa fa-bell"></i> Alerts ({{ notif_count }})</a>
    <a href="/feedback"><i class="fa fa-comment"></i> Feedback</a>
    <a href="/logout"><i class="fa fa-sign-out-alt"></i> Logout</a>
</div>
<div class="content">
    <div class="card">
        <h3>Welcome, {{ username }}</h3>
        <p>This is your student project dashboard running on AWS EC2.</p>
    </div>
</div>
</body>
</html>
HTMLEOF

# login.html
cat > templates/login.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome | Student Project Portal</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; height: 100vh; background: linear-gradient(135deg, #4361ee 0%, #3a0ca3 100%); display: flex; align-items: center; justify-content: center; }
        .login-card { background: white; width: 900px; display: flex; border-radius: 20px; overflow: hidden; box-shadow: 0 25px 50px rgba(0,0,0,0.3); }
        .login-hero { flex: 1; background: #1e1e2f; padding: 40px; color: white; display: flex; flex-direction: column; justify-content: flex-end; }
        .login-form-side { flex: 1; padding: 60px; background: white; }
        .input-group { margin-bottom: 20px; position: relative; }
        .input-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; }
        .btn-login { width: 100%; padding: 14px; background: #4361ee; color: white; border: none; border-radius: 8px; cursor: pointer; }
    </style>
</head>
<body>
<div class="login-card">
    <div class="login-hero">
        <h2>Project Management Portal</h2>
    </div>
    <div class="login-form-side">
        <h3>Account Login</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="input-group"><input type="text" name="username" placeholder="Username" required></div>
            <div class="input-group"><input type="password" name="password" placeholder="Password" required></div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        <div style="margin-top: 25px;"><a href="/register">Create an Account</a></div>
        {% with messages = get_flashed_messages() %}
            {% if messages %} <p style="color: red;">{{ messages[0] }}</p> {% endif %}
        {% endwith %}
    </div>
</div>
</body>
</html>
HTMLEOF

# register.html
cat > templates/register.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <style>
        body { font-family: sans-serif; background: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .register-container { background: white; padding: 40px; border-radius: 12px; width: 400px; }
        input { width: 100%; padding: 10px; margin-bottom: 10px; }
        button { width: 100%; padding: 10px; background: #28a745; color: white; border: none; }
    </style>
</head>
<body>
<div class="register-container">
    <h2>Create Account</h2>
    {% with messages = get_flashed_messages() %}
        {% if messages %} <p style="color:red">{{ messages[0] }}</p> {% endif %}
    {% endwith %}
    <form action="/register" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="email" name="email" placeholder="Email" required>
        <input type="text" name="phone" placeholder="Phone" required>
        <label><input type="checkbox" name="consent" required> I consent to PDPA.</label>
        <button type="submit">Register</button>
    </form>
    <a href="/">Login here</a>
</div>
</body>
</html>
HTMLEOF

# notifications.html
cat > templates/notifications.html << 'HTMLEOF'
<!DOCTYPE html>
<html><head><title>Notifications</title></head><body><h2>Notifications</h2><a href="/dashboard">Back</a></body></html>
HTMLEOF

# feedback.html
cat > templates/feedback.html << 'HTMLEOF'
<!DOCTYPE html>
<html><head><title>Feedback</title></head><body><h2>Feedback</h2><a href="/dashboard">Back</a></body></html>
HTMLEOF

# --- 6. Environment Variables Setup ---
cat > /etc/profile.d/student_portal_env.sh <<ENVEOF
export FLASK_SECRET='${flask_secret}'
export DB_HOST='${db_host}'
export DB_NAME='${db_name}'
export DB_USER='${db_user}'
export DB_PASS='${db_pass}'
export DB_PORT='${db_port}'
export PHONE_ENC_KEY='${phone_enc_key}'
export PORT='${app_port}'
export COOKIE_SECURE='false'
ENVEOF
chmod 600 /etc/profile.d/student_portal_env.sh

# --- 7. Create Systemd Service ---
cat > /etc/systemd/system/student-portal.service <<serviceEOF
[Unit]
Description=Student Project Portal (Flask)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/student-portal
Environment=FLASK_SECRET=${flask_secret}
Environment=DB_HOST=${db_host}
Environment=DB_NAME=${db_name}
Environment=DB_USER=${db_user}
Environment=DB_PASS=${db_pass}
Environment=DB_PORT=${db_port}
Environment=PHONE_ENC_KEY=${phone_enc_key}
Environment=PORT=${app_port}
Environment=COOKIE_SECURE=false 
ExecStart=/usr/local/bin/gunicorn -w 2 -b 0.0.0.0:${app_port} app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
serviceEOF

systemctl daemon-reload
systemctl enable student-portal.service
systemctl start student-portal.service || true
EOF
