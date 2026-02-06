#!/bin/bash
set -e

# --- Basic hardening / updates ---
yum update -y

# --- Install Python & tools ---
yum install -y python3 git
python3 -m pip install --upgrade pip

# --- App folder ---
mkdir -p /opt/student-portal
cd /opt/student-portal

# Note: You would typically git clone here. 
# For this example, we assume code deployment happens via another mechanism 
# or manual copy, matching the provided CFN comments.

# --- Export env vars ---
cat > /etc/profile.d/student_portal_env.sh <<EOF
export FLASK_SECRET='${flask_secret}'
export DB_HOST='${db_host}'
export DB_NAME='${db_name}'
export DB_USER='${db_user}'
export DB_PASS='${db_pass}'
export DB_PORT='${db_port}'
export PHONE_ENC_KEY='${phone_enc_key}'
export PORT='${app_port}'
export COOKIE_SECURE='true'
EOF
chmod 600 /etc/profile.d/student_portal_env.sh

# --- Create systemd service ---
python3 -m pip install flask flask-wtf pymysql gunicorn

cat > /etc/systemd/system/student-portal.service <<EOF
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
Environment=COOKIE_SECURE=true
ExecStart=/usr/local/bin/gunicorn -w 2 -b 0.0.0.0:${app_port} app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable student-portal.service
systemctl start student-portal.service || true
