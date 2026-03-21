"""
sample_vulnerable/app.py
A deliberately vulnerable Flask application for testing CodeSentinel.
DO NOT deploy this. It contains intentional security flaws.
"""

import os
import pickle
import hashlib
import random
import subprocess
import sqlite3
import yaml

from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

# [FLAW] Hardcoded SECRET_KEY
SECRET_KEY = "xxxxxxxxxxxxxxxxxxxxxxxx"
app.secret_key = SECRET_KEY

# [FLAW] Hardcoded AWS credentials
AWS_ACCESS_KEY_ID     = "AK" + "IAXXXXXXXXXXXXXXXX"
AWS_SECRET_ACCESS_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# [FLAW] Hardcoded database password
DB_PASSWORD = "password=xxxxxxxx"

# [FLAW] DEBUG = True
DEBUG = True


@app.route("/login", methods=["POST"])
def login():
    """[FLAW] SQL Injection via string concatenation."""
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # [FLAW] Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "ok", "user": user})
    return jsonify({"status": "fail"})


@app.route("/search")
def search():
    """[FLAW] SQL injection via f-string."""
    term = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    results = cursor.fetchall()
    return jsonify(results)


@app.route("/ping")
def ping():
    """[FLAW] Command injection via os.system + subprocess shell=True."""
    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


@app.route("/exec")
def execute_code():
    """[FLAW] Arbitrary code execution via eval()."""
    code = request.args.get("code", "")
    result = eval(code)
    return str(result)


@app.route("/download")
def download():
    """[FLAW] Path traversal via os.path.join with user input."""
    filename = request.args.get("file", "")
    filepath = os.path.join("/uploads", filename)
    with open(filepath, "rb") as f:
        return f.read()


@app.route("/load-session")
def load_session():
    """[FLAW] Insecure deserialization via pickle."""
    session_data = request.cookies.get("session_data", "")
    if session_data:
        data = pickle.loads(bytes.fromhex(session_data))
        return jsonify(data)
    return jsonify({})


@app.route("/load-config")
def load_config():
    """[FLAW] YAML deserialization without SafeLoader."""
    config_data = request.data
    config = yaml.load(config_data)
    return jsonify(config)


@app.route("/reset-password")
def reset_password():
    """[FLAW] Weak PRNG for security token + MD5 password hashing."""
    token = random.randint(100000, 999999)
    password = request.args.get("password", "")

    # [FLAW] MD5 for password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"token": token, "hashed": hashed})


@app.route("/profile")
def profile():
    """[FLAW] XSS via mark_safe equivalent — raw template rendering."""
    name = request.args.get("name", "")
    # [FLAW] Direct user input in rendered HTML
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/error-test")
def error_test():
    """[FLAW] Stack trace exposed in API response."""
    try:
        result = 1 / 0
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "traceback": traceback.format_exc()})


if __name__ == "__main__":
    # [FLAW] Flask debug mode enabled
    app.run(debug=True, host="0.0.0.0")
