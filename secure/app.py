"""
SECURE VERSION -- fixes all 4 required vulnerabilities plus the three
bonus hardening items. Each fix is labeled FIX-n to map 1:1 onto the
VULN-n comments in vulnerable/app.py.

Run `python app.py` in this folder. It will self-seed store.db on first
run (admin password hashed, TOTP secret generated and printed once).

pip install flask flask-limiter pyotp werkzeug
"""
from flask import Flask, request, session, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import pyotp
import os
import re
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# FIX bonus: secure cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,     # requires HTTPS in real deployment
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "store.db")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def seed_if_needed():
    if os.path.exists(DB_PATH):
        return
    con = db()
    cur = con.cursor()
    cur.execute("""CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL)""")
    cur.execute("""CREATE TABLE customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mobile TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)""")
    cur.execute("""CREATE TABLE employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('employee','admin')),
        mfa_secret TEXT, failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT)""")

    cur.executemany("INSERT INTO products (name, price) VALUES (?,?)", [
        ("Wireless Mouse", 799.0), ("Mechanical Keyboard", 3499.0),
        ("27-inch Monitor", 15999.0), ("USB-C Hub", 1299.0),
        ("Noise Cancelling Headphones", 8999.0),
    ])
    cur.executemany(
        "INSERT INTO customers (name, mobile, username, password) VALUES (?,?,?,?)",
        [("Ravi Kumar", "9876543210", "ravik", generate_password_hash("custpass1")),
         ("Meena Shah", "9123456780", "meenas", generate_password_hash("custpass2")),
         ("Arjun Nair", "9988776655", "arjunn", generate_password_hash("custpass3"))],
    )

    # FIX-3: strong, randomly generated admin password (hashed) + TOTP secret
    strong_admin_password = secrets.token_urlsafe(12)
    admin_mfa_secret = pyotp.random_base32()
    staff_mfa_secret = pyotp.random_base32()
    cur.execute(
        "INSERT INTO employees (username,password,role,mfa_secret) VALUES (?,?,?,?)",
        ("floor_staff", generate_password_hash("Staff#" + secrets.token_hex(4)), "employee", staff_mfa_secret),
    )
    cur.execute(
        "INSERT INTO employees (username,password,role,mfa_secret) VALUES (?,?,?,?)",
        ("admin", generate_password_hash(strong_admin_password), "admin", admin_mfa_secret),
    )
    con.commit()
    con.close()
    print("=" * 70)
    print("First-run seed complete. SAVE THESE (shown only once):")
    print(f"  admin password : {strong_admin_password}")
    print(f"  admin TOTP seed: {admin_mfa_secret}  (add to an authenticator app)")
    print("=" * 70)


seed_if_needed()


# FIX bonus: security headers on every response
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


def require_role(*roles):
    """RBAC decorator -- FIX-2 / bonus RBAC item."""
    def wrapper(fn):
        def inner(*args, **kwargs):
            role = session.get("role")
            if role not in roles:
                return jsonify({"status": "forbidden"}), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrapper


def validate_username(u: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", u or ""))


# ---------------------------------------------------------------------------
# FIX-1 (SQL injection) + FIX-3 (weak auth / lockout) + bonus rate limiting
# ---------------------------------------------------------------------------
@app.route("/employee/login", methods=["POST"])
@limiter.limit("5 per minute")  # bonus: rate limiting on the login endpoint
def employee_login():
    try:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        totp_code = request.form.get("totp_code", "")

        if not validate_username(username):  # bonus: input validation
            return jsonify({"status": "fail"}), 400

        con = db()
        row = con.execute(
            "SELECT * FROM employees WHERE username = ?", (username,)  # FIX-1: parameterized
        ).fetchone()

        if not row:
            con.close()
            return jsonify({"status": "fail"}), 401

        # FIX-3: account lockout after repeated failures
        if row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
            if datetime.utcnow() < locked_until:
                con.close()
                return jsonify({"status": "locked", "retry_after": str(locked_until)}), 423

        valid_password = check_password_hash(row["password"], password)
        valid_totp = bool(row["mfa_secret"]) and pyotp.TOTP(row["mfa_secret"]).verify(totp_code)

        if valid_password and valid_totp:
            con.execute(
                "UPDATE employees SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (row["id"],),
            )
            con.commit()
            con.close()
            session.clear()
            session["employee_id"] = row["id"]
            session["role"] = row["role"]
            return jsonify({"status": "ok", "role": row["role"]})

        # wrong password or wrong/missing MFA code
        attempts = row["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        con.execute(
            "UPDATE employees SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, locked_until, row["id"]),
        )
        con.commit()
        con.close()
        return jsonify({"status": "fail"}), 401

    except Exception:
        # FIX-4b: never leak internals to the client
        app.logger.exception("employee_login error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# FIX-2: Broken access control -- RBAC + "own record only" rule for customers
# ---------------------------------------------------------------------------
@app.route("/customer/<int:cust_id>")
@require_role("admin")  # only admins may look up arbitrary customers by id
def get_customer(cust_id):
    con = db()
    row = con.execute("SELECT id, name, mobile FROM customers WHERE id = ?", (cust_id,)).fetchone()
    con.close()
    if not row:
        return jsonify({"status": "not found"}), 404
    return jsonify({"id": row["id"], "name": row["name"], "mobile": row["mobile"]})


@app.route("/me/customer")
def get_own_customer_record():
    """A customer can only ever see their own record (session-bound, not id-based)."""
    cust_id = session.get("customer_id")
    if not cust_id:
        return jsonify({"status": "unauthorized"}), 401
    con = db()
    row = con.execute("SELECT id, name, mobile FROM customers WHERE id = ?", (cust_id,)).fetchone()
    con.close()
    return jsonify({"id": row["id"], "name": row["name"], "mobile": row["mobile"]})


@app.route("/products")
@require_role("employee", "admin")  # products visible to all staff, not the public
def list_products():
    con = db()
    rows = con.execute("SELECT id, name, price FROM products").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# FIX-3: self-service "forgot password" removed. Admin-mediated reset only,
# still requiring the NEW password to meet a strength policy and still
# requiring a fresh TOTP enrollment -- no security questions anywhere.
# ---------------------------------------------------------------------------
@app.route("/employee/admin-reset-password", methods=["POST"])
@require_role("admin")
def admin_reset_password():
    try:
        target_username = request.form.get("username", "")
        new_password = request.form.get("new_password", "")

        if not validate_username(target_username):
            return jsonify({"status": "fail", "reason": "invalid username"}), 400
        if len(new_password) < 12:
            return jsonify({"status": "fail", "reason": "password too short (min 12 chars)"}), 400

        new_mfa_secret = pyotp.random_base32()
        con = db()
        con.execute(
            "UPDATE employees SET password = ?, mfa_secret = ?, failed_attempts = 0, locked_until = NULL "
            "WHERE username = ?",
            (generate_password_hash(new_password), new_mfa_secret, target_username),
        )
        con.commit()
        con.close()
        return jsonify({"status": "reset", "new_mfa_secret": new_mfa_secret})
    except Exception:
        app.logger.exception("admin_reset_password error")
        return jsonify({"status": "error", "message": "Something went wrong."}), 500


# ---------------------------------------------------------------------------
# FIX-4: bounded, validated input; errors caught and handled gracefully
# ---------------------------------------------------------------------------
MAX_QUANTITY = 1000


@app.route("/product/bulk-update", methods=["POST"])
@require_role("employee", "admin")
@limiter.limit("20 per minute")
def bulk_update():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "fail", "reason": "invalid or missing JSON body"}), 400

        product_id = data.get("product_id")
        quantity = data.get("quantity")

        if not isinstance(product_id, int) or product_id <= 0:
            return jsonify({"status": "fail", "reason": "product_id must be a positive integer"}), 400
        if not isinstance(quantity, int) or not (0 < quantity <= MAX_QUANTITY):
            return jsonify({"status": "fail", "reason": f"quantity must be 1..{MAX_QUANTITY}"}), 400

        con = db()
        exists = con.execute("SELECT 1 FROM products WHERE id = ?", (product_id,)).fetchone()
        if not exists:
            con.close()
            return jsonify({"status": "fail", "reason": "unknown product_id"}), 404

        con.execute("UPDATE products SET price = price WHERE id = ?", (product_id,))
        con.commit()
        con.close()
        return jsonify({"status": "updated", "quantity": quantity})
    except Exception:
        app.logger.exception("bulk_update error")
        return jsonify({"status": "error", "message": "Something went wrong."}), 500


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"status": "not found"}), 404


@app.errorhandler(500)
def server_error(_e):
    # FIX-4b: generic message only, full detail stays in server logs
    return jsonify({"status": "error", "message": "Internal error. Please try again later."}), 500


if __name__ == "__main__":
    app.config["DEBUG"] = False  # FIX-4: never run with debugger/stack traces in anything client-facing
    # host="0.0.0.0" so the container's published port actually reaches this
    # process -- see matching note in vulnerable/app.py.
    app.run(host="0.0.0.0", port=5001)
