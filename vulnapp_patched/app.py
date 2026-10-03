"""
VulnApp - Purposefully Vulnerable Flask Web Application
========================================================
EDUCATIONAL USE ONLY. Run ONLY in an isolated sandbox/Docker container.

Built-in vulnerabilities:
  1. SQL Injection          → /login (POST)
  2. Path Traversal         → /file (GET)
  3. CSRF (no token)        → /transfer (POST)
  4. Hardcoded Credentials  → /admin (GET)
  5. Command Injection      → /ping (POST)
  6. Broken JWT (alg:none)  → /api/profile (GET, Authorization header)
"""

import os
import platform
import sqlite3
import subprocess
import tempfile
import jwt
import secrets
import hmac

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, g
)

app = Flask(__name__)
app.secret_key = "supersecretkey_do_not_use_in_prod"

# ─── Database Setup ────────────────────────────────────────────────────────────
DATABASE = os.path.join(tempfile.gettempdir(), "vulnapp.db")
# PATCHED: secret comes from the environment. A random per-process fallback
# keeps the app runnable while ensuring no known credential is shipped.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(32)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                balance REAL DEFAULT 1000.0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                amount REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Seed users
        existing = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            db.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)",
                       ("admin", ADMIN_PASSWORD, "admin", 99999.0))
            db.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)",
                       ("alice", "alice_pass", "user", 1000.0))
            db.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)",
                       ("bob", "bob_pass", "user", 500.0))
        db.commit()


# ─── Health Check ─────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "app": "vulnapp"}), 200


# ─── Index ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({
        "app": "VulnApp",
        "version": "1.0.0",
        "stack": "Flask + SQLite",
        "endpoints": ["/login", "/file", "/transfer", "/admin", "/ping", "/api/profile"]
    })


# ─── VULN 1: SQL Injection ─────────────────────────────────────────────────────
# Raw string interpolation in SQL query — never do this in production.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # PATCHED: parameterized query — prevents SQL injection
    try:
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
    except Exception as e:
        return jsonify({"error": "Database error"}), 500  # Do not leak error details

    if user:
        session["user"] = dict(user)
        token = jwt.encode(
            {"user": username, "role": user["role"]},
            app.secret_key,
            algorithm="HS256"
        )
        return jsonify({"status": "success", "message": f"Welcome {username}", "token": token})
    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


# ─── VULN 2: Path Traversal ───────────────────────────────────────────────────
# No sanitization on the 'name' parameter.
@app.route("/file")
def file_read():
    filename = request.args.get("name")
    if filename is None:
        return jsonify({"error": "Missing 'name' query parameter", "usage": "/file?name=<filename>"}), 400
    base_dir = os.path.join(os.path.dirname(__file__), "files")

    # VULNERABLE: no path canonicalization
    filepath = os.path.join(base_dir, filename)
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return jsonify({"file": filename, "content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found", "path": filepath}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── VULN 3: CSRF (No Token Validation) ───────────────────────────────────────
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if request.method == "GET":
        return render_template("transfer.html")

    # VULNERABLE: no CSRF token check
    sender = request.form.get("from", "alice")
    receiver = request.form.get("to", "")
    amount = float(request.form.get("amount", 0))

    db = get_db()
    sender_row = db.execute("SELECT balance FROM users WHERE username=?", (sender,)).fetchone()
    if not sender_row:
        return jsonify({"error": "Sender not found"}), 404

    if sender_row["balance"] < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    db.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, sender))
    db.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, receiver))
    db.execute("INSERT INTO transactions (sender, receiver, amount) VALUES (?,?,?)",
               (sender, receiver, amount))
    db.commit()
    return jsonify({"status": "transferred", "from": sender, "to": receiver, "amount": amount})


# ─── VULN 4: Hardcoded Credentials ────────────────────────────────────────────
@app.route("/admin")
def admin():
    auth = request.headers.get("X-Admin-Password", "")
    # VULNERABLE: hardcoded credential check
    if auth and hmac.compare_digest(auth, ADMIN_PASSWORD):  # PATCHED: constant-time comparison
        db = get_db()
        users = db.execute("SELECT id, username, role, balance FROM users").fetchall()
        return jsonify({"status": "admin_access", "users": [dict(u) for u in users]})
    return jsonify({"error": "Unauthorized"}), 401


# ─── VULN 5: Command Injection ────────────────────────────────────────────────
@app.route("/ping", methods=["GET", "POST"])
def ping():
    if request.method == "GET":
        return jsonify({"usage": "POST with JSON: {\"host\": \"<ip>\"}"}), 200

    host = request.json.get("host", "127.0.0.1") if request.is_json else request.form.get("host", "127.0.0.1")

    # PATCHED: safe subprocess call with argument list (no shell=True)
    # Validate host format before passing to subprocess
    import re as _re
    if not _re.match(r"^[a-zA-Z0-9._-]{1,253}$", host):
        return jsonify({"error": "Invalid host format"}), 400
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.check_output(
            ["ping", count_flag, "1", host],   # list form — no shell injection possible
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=5
        )
        return jsonify({"host": host, "output": result.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"host": host, "output": e.output.decode(), "returncode": e.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 408


# ─── VULN 6: Broken JWT (accepts alg:none) ─────────────────────────────────────
@app.route("/api/profile")
def api_profile():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.split(" ", 1)[1]
    try:
        # PATCHED: enforce full signature verification, disallow alg:none
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        username = payload.get("user", "anonymous")
        role = payload.get("role", "user")

        db = get_db()
        user = db.execute("SELECT id, username, role, balance FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({"user": dict(user), "token_role": role})
    except jwt.DecodeError as e:
        return jsonify({"error": f"Invalid token: {e}"}), 401


# ─── Bonus: Change Password (CSRF target) ────────────────────────────────────
@app.route("/change_password", methods=["POST"])
def change_password():
    username = request.form.get("username", "alice")
    new_password = request.form.get("new_password", "")
    # VULNERABLE: no CSRF token, no auth check
    db = get_db()
    db.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
    db.commit()
    return jsonify({"status": "password_changed", "user": username})


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Create sample files directory for path traversal demo
    # PATCHED: seed the same directory that /file serves from (module-relative)
    files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, "readme.txt"), "w", encoding="utf-8") as f:
        f.write("Welcome to VulnApp! This is a safe file.\n")

    init_db()
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5001")),
            debug=False)  # PATCHED: debug disabled, bind configurable