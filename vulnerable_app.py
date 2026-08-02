"""
VulnShop - Sample E-Commerce Backend (Flask)
---------------------------------------------
NOTE: This application was written INTENTIONALLY with common security
vulnerabilities for the purpose of a secure coding review exercise
(CodeAlpha Cyber Security Internship - Task 3).

Do NOT deploy this code as-is. See reports/SECURITY_REVIEW_REPORT.md
for the full audit and app/secure_app_fixed.py for the remediated version.
"""

import sqlite3
import hashlib
import subprocess
import pickle
import os

from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# --- VULN 1: Hardcoded secret key committed to source control ---
app.secret_key = "supersecret123"

DB_PATH = "shop.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT, password TEXT, is_admin INTEGER)"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- VULN 2: SQL Injection via unsanitized string concatenation ---
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    conn = get_db()
    cursor = conn.execute(query)
    user = cursor.fetchone()

    if user:
        return redirect("/dashboard")
    return "Invalid credentials", 401


@app.route("/dashboard")
def dashboard():
    return "Welcome to your dashboard."


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- VULN 3: Weak, unsalted password hashing (MD5) ---
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        (username, hashed),
    )
    conn.commit()
    return "Registered"


@app.route("/search")
def search():
    term = request.args.get("q", "")

    # --- VULN 4: Reflected XSS - user input rendered without escaping ---
    template = f"<h1>Search results for: {term}</h1>"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # --- VULN 5: OS Command Injection via shell=True with user input ---
    result = subprocess.run(
        "ping -c 1 " + host, shell=True, capture_output=True, text=True
    )
    return result.stdout


@app.route("/load_cart", methods=["POST"])
def load_cart():
    data = request.data

    # --- VULN 6: Insecure Deserialization using pickle on user input ---
    cart = pickle.loads(data)
    return {"items": cart}


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]

    # --- VULN 7: Unrestricted file upload - no type/extension validation ---
    save_path = os.path.join("uploads", file.filename)
    file.save(save_path)
    return f"Saved to {save_path}"


if __name__ == "__main__":
    init_db()
    # --- VULN 8: Debug mode enabled in what looks like a prod entrypoint ---
    app.run(host="0.0.0.0", debug=True)
