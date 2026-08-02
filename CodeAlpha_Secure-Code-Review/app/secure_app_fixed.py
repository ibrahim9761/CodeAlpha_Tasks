"""
VulnShop - Remediated Version
------------------------------
This file demonstrates the fixes for every vulnerability identified in
reports/SECURITY_REVIEW_REPORT.md. Compare against app/vulnerable_app.py.
"""

import os
import shutil
import sqlite3
import subprocess
import json

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from flask import Flask, request, redirect

app = Flask(__name__)

# FIX 1: Secret loaded from environment, never committed to source control
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set")

DB_PATH = "shop.db"
UPLOAD_DIR = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
ALLOWED_PING_HOSTS = {"127.0.0.1", "localhost"}


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0)"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # FIX 2: Parameterized query - no string concatenation, prevents SQLi
    conn = get_db()
    cursor = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    )
    row = cursor.fetchone()

    # FIX 3: Constant-time hash comparison via werkzeug, salted PBKDF2 hash
    if row and check_password_hash(row[0], password):
        return redirect("/dashboard")
    return "Invalid credentials", 401


@app.route("/dashboard")
def dashboard():
    # Minimal placeholder route so the post-login redirect resolves.
    # A real app would check session/auth state here before rendering.
    return "Welcome to your dashboard."


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if len(password) < 8:
        return "Password must be at least 8 characters", 400

    # FIX 3 (cont.): Strong, salted hash (PBKDF2-SHA256 by default)
    password_hash = generate_password_hash(password)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
            (username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return "Username already exists", 409
    return "Registered"


@app.route("/search")
def search():
    term = request.args.get("q", "")

    # FIX 4: Output properly escaped - prevents reflected XSS
    safe_term = escape(term)
    return f"<h1>Search results for: {safe_term}</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # FIX 5: Strict allow-list + no shell=True + argument list (no injection)
    if host not in ALLOWED_PING_HOSTS:
        return "Host not permitted", 400

    ping_bin = shutil.which("ping")
    if not ping_bin:
        return "ping utility not available on this host", 503

    result = subprocess.run(
        [ping_bin, "-c", "1", host], shell=False, capture_output=True, text=True
    )
    return result.stdout


@app.route("/load_cart", methods=["POST"])
def load_cart():
    # FIX 6: JSON instead of pickle - no arbitrary code execution on load
    try:
        cart = json.loads(request.data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Invalid payload", 400
    return {"items": cart}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")

    # FIX 7: Extension allow-list + secure_filename() to strip path traversal
    if not file or not allowed_file(file.filename):
        return "File type not allowed", 400

    filename = secure_filename(file.filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)
    return f"Saved to {save_path}"


if __name__ == "__main__":
    init_db()
    # FIX 8: Debug disabled, bind address should come from deployment config
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", debug=debug_mode)
