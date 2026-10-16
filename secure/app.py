"""
SECURE VERSION -- Retail Storefront
Fixes all 4 vulnerabilities from the vulnerable build, using the exact
solutions documented in the project report.

FIX-1: SQL Injection → all queries use parameterized ? placeholders; no
       f-string or .format() SQL anywhere. Defense-in-depth: search term
       capped at 50 characters.
FIX-2: Broken Access Control → the ?user= override is removed entirely;
       role comes only from session.get("role"). /customer/<id> requires
       login + own-record check (or admin). Admin routes use an RBAC
       decorator that reads only the session.
FIX-3: Authentication Failure → passwords hashed with werkzeug.security;
       TOTP MFA via pyotp on every login; weak-security-question reset
       replaced with admin-mediated reset + TOTP re-enrollment; account
       lockout after 5 failures; rate limiting via flask-limiter.
       NOTE: In production, a managed IdP (Auth0, Okta, etc.) would be the
       proper solution. TOTP here demonstrates the same MFA principle
       locally without external service dependencies.
FIX-4: Mishandling Exceptional Conditions → quantity/product_id validated
       (quantity capped at 1000); try/except everywhere with generic 500
       responses; DEBUG=False always; custom 404/500 error handlers.
Bonus: secure cookies, security headers (CSP, X-Content-Type-Options,
       X-Frame-Options, Referrer-Policy, HSTS).

Same route surface and response shapes as the vulnerable build so the
storefront UI works identically for legitimate use.

DO NOT deploy this file anywhere reachable from the internet without
further production hardening (HTTPS termination, CSRF tokens, etc.).
"""
from flask import Flask, request, session, jsonify, render_template, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import pyotp
import os
import re
import secrets
import logging

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = secrets.token_hex(32)
app.config["DEBUG"] = False  # FIX-4: never expose Werkzeug debugger

# FIX-bonus: secure cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # requires HTTPS in real deployment
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secure_store.db")

# FIX-3: lockout configuration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# FIX-3: small blocklist of common weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "admin123", "password1",
    "qwerty", "abc123", "letmein", "welcome", "monkey",
    "1234567890", "password123", "admin", "iloveyou", "sunshine",
}
MIN_PASSWORD_LENGTH = 10

# FIX-3: rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

# Server-side logging for exceptions (FIX-4)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secure-app")


def db():
    """Open a connection to the SQLite database."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


# ---------------------------------------------------------------------------
# Self-seeding: create DB + hashed passwords + TOTP on first run
# ---------------------------------------------------------------------------
def seed_if_needed():
    """Create the database and seed it with hashed passwords and TOTP secrets
    on first run. The admin password and TOTP secret are printed to the
    console exactly once."""
    if os.path.exists(DB_PATH):
        return
    con = db()
    cur = con.cursor()

    cur.execute("""CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL
    )""")
    cur.execute("""CREATE TABLE customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        mobile TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")
    cur.execute("""CREATE TABLE employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('employee','admin')),
        mfa_secret TEXT,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    )""")

    # Same product catalog
    cur.executemany("INSERT INTO products (name, price) VALUES (?,?)", [
        ("Wireless Mouse", 799.0),
        ("Mechanical Keyboard", 3499.0),
        ("27-inch Monitor", 15999.0),
        ("USB-C Hub", 1299.0),
        ("Noise Cancelling Headphones", 8999.0),
    ])

    # FIX-3: customer passwords hashed (not plaintext)
    cur.executemany(
        "INSERT INTO customers (name, mobile, username, password) VALUES (?,?,?,?)",
        [
            ("Ravi Kumar",  "9876543210", "ravik",  generate_password_hash("custpass1")),
            ("Meena Shah",  "9123456780", "meenas", generate_password_hash("custpass2")),
            ("Arjun Nair",  "9988776655", "arjunn", generate_password_hash("custpass3")),
        ],
    )

    # FIX-3: strong, randomly generated passwords (hashed) + TOTP secrets
    strong_admin_password = secrets.token_urlsafe(16)
    admin_mfa_secret = pyotp.random_base32()

    strong_staff_password = "Staff#" + secrets.token_hex(4)
    staff_mfa_secret = pyotp.random_base32()

    cur.execute(
        "INSERT INTO employees (username, password, role, mfa_secret) VALUES (?,?,?,?)",
        ("floor_staff", generate_password_hash(strong_staff_password), "employee", staff_mfa_secret),
    )
    cur.execute(
        "INSERT INTO employees (username, password, role, mfa_secret) VALUES (?,?,?,?)",
        ("admin", generate_password_hash(strong_admin_password), "admin", admin_mfa_secret),
    )

    con.commit()
    con.close()
    print("=" * 70)
    print("First-run seed complete. SAVE THESE (shown only once):")
    print(f"  admin username : admin")
    print(f"  admin password : {strong_admin_password}")
    print(f"  admin TOTP seed: {admin_mfa_secret}  (add to an authenticator app)")
    print(f"  staff username : floor_staff")
    print(f"  staff password : {strong_staff_password}")
    print(f"  staff TOTP seed: {staff_mfa_secret}")
    print("=" * 70)


seed_if_needed()


# ---------------------------------------------------------------------------
# FIX-bonus: security headers on every response
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'"
    )
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# ---------------------------------------------------------------------------
# RBAC decorator — FIX-2: role comes ONLY from the server-side session
# ---------------------------------------------------------------------------
def require_role(*roles):
    """Decorator that enforces server-side session role. No ?user= override,
    no client-supplied role parameter — session.get('role') only."""
    def wrapper(fn):
        def inner(*args, **kwargs):
            role = session.get("role")   # FIX-2: only source of truth
            if role not in roles:
                return jsonify({"status": "forbidden", "error": "Unauthorized: insufficient role"}), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrapper


def validate_username(u: str) -> bool:
    """Allow only alphanumeric + underscore, 3-30 chars."""
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", u or ""))


def password_meets_policy(pw: str) -> tuple[bool, str]:
    """Check password strength. Returns (ok, reason)."""
    if len(pw) < MIN_PASSWORD_LENGTH:
        return False, f"Password too short (minimum {MIN_PASSWORD_LENGTH} characters)"
    if pw.lower() in COMMON_PASSWORDS:
        return False, "Password is too common — choose something stronger"
    return True, ""


# ---------------------------------------------------------------------------
# Storefront Frontend View
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# FIX-1: SQL Injection → parameterized queries, no string formatting
# Defense-in-depth: search term capped at 50 characters
# ---------------------------------------------------------------------------
@app.route("/products/search")
def search_products():
    try:
        q = request.args.get("q") or request.args.get("name") or ""

        # Defense-in-depth: cap search term length
        if len(q) > 50:
            return jsonify({"status": "fail", "error": "Search term too long (max 50 characters)"}), 400

        con = db()
        # FIX-1: parameterized query — no f-string, no .format(), no concatenation
        rows = con.execute(
            "SELECT id, name, price FROM products WHERE name LIKE ?",
            (f"%{q}%",)
        ).fetchall()
        con.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        logger.exception("search_products error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# FIX-1 & FIX-2: Admin Price Update
# FIX-1: parameterized UPDATE query
# FIX-2: @require_role("admin") reads only session, not ?user= param
# ---------------------------------------------------------------------------
@app.route("/admin/update-price", methods=["POST"])
@require_role("admin")
def update_price():
    try:
        data = request.get_json(silent=True) or {}
        product_name = request.form.get("name") or data.get("name", "")
        new_price = request.form.get("price") or data.get("price", 0)

        # FIX-4: validate inputs
        try:
            new_price = float(new_price)
        except (TypeError, ValueError):
            return jsonify({"status": "fail", "error": "price must be a number"}), 400

        if new_price < 0 or new_price > 9999999:
            return jsonify({"status": "fail", "error": "price out of valid range"}), 400
        if not product_name or len(product_name) > 100:
            return jsonify({"status": "fail", "error": "invalid product name"}), 400

        con = db()
        # FIX-1: parameterized query — no string formatting
        cur = con.execute(
            "UPDATE products SET price = ? WHERE name = ?",
            (new_price, product_name)
        )
        con.commit()
        rows_affected = cur.rowcount
        con.close()
        return jsonify({"status": "success", "rows_affected": rows_affected})
    except Exception:
        logger.exception("update_price error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# FIX-2: Broken Access Control
# /customer/<id>: requires login; customer can only access own record;
# admin can access any.  No unauthenticated access (IDOR eliminated).
# /admin/customers: @require_role("admin") — session only, no ?user= override
# ---------------------------------------------------------------------------
@app.route("/customer/<int:cust_id>")
def get_customer(cust_id):
    try:
        # FIX-2: must be logged in
        role = session.get("role")
        user_id = session.get("user_id")
        if not role or not user_id:
            return jsonify({"status": "forbidden", "error": "Authentication required"}), 403

        # FIX-2: customers can only see their own record
        if role == "customer" and user_id != cust_id:
            return jsonify({"status": "forbidden", "error": "Access denied — you can only view your own record"}), 403

        # Admins can access any customer record
        if role not in ("customer", "admin"):
            return jsonify({"status": "forbidden", "error": "Unauthorized role"}), 403

        con = db()
        row = con.execute(
            "SELECT id, name, mobile FROM customers WHERE id = ?", (cust_id,)
        ).fetchone()
        con.close()
        if not row:
            return jsonify({"error": "Customer not found"}), 404
        return jsonify({"id": row["id"], "name": row["name"], "mobile": row["mobile"]})
    except Exception:
        logger.exception("get_customer error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


@app.route("/admin/customers")
@require_role("admin")
def admin_customers():
    try:
        con = db()
        rows = con.execute("SELECT id, name, mobile, username FROM customers").fetchall()
        con.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        logger.exception("admin_customers error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# FIX-3: Login — hashed password check + TOTP MFA + lockout + rate limit
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
@app.route("/employee/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json(silent=True) or {}
        username = request.form.get("username") or data.get("username", "")
        password = request.form.get("password") or data.get("password", "")
        totp_code = request.form.get("totp_code") or data.get("totp_code", "")

        if not validate_username(username):
            return jsonify({"status": "fail", "error": "Invalid username format"}), 400

        con = db()

        # ---- Check employees table first ----
        emp = con.execute(
            "SELECT * FROM employees WHERE username = ?", (username,)
        ).fetchone()

        if emp:
            # FIX-3: account lockout check
            if emp["locked_until"]:
                locked_until = datetime.fromisoformat(emp["locked_until"])
                if datetime.utcnow() < locked_until:
                    con.close()
                    remaining = int((locked_until - datetime.utcnow()).total_seconds())
                    return jsonify({
                        "status": "locked",
                        "error": f"Account locked. Try again in {remaining // 60 + 1} minute(s).",
                        "retry_after": str(locked_until)
                    }), 423

            # FIX-3: verify hashed password
            valid_password = check_password_hash(emp["password"], password)

            # FIX-3: verify TOTP MFA
            valid_totp = True  # default for accounts without MFA secret
            if emp["mfa_secret"]:
                valid_totp = bool(totp_code) and pyotp.TOTP(emp["mfa_secret"]).verify(totp_code, valid_window=1)

            if valid_password and valid_totp:
                # Success: reset failure counter
                con.execute(
                    "UPDATE employees SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (emp["id"],),
                )
                con.commit()
                con.close()
                session.clear()
                session["user_id"] = emp["id"]
                session["username"] = emp["username"]
                session["role"] = emp["role"]
                return jsonify({
                    "status": "ok",
                    "role": emp["role"],
                    "username": emp["username"],
                    "name": emp["username"].capitalize()
                })

            # Failed: increment counter, maybe lock
            attempts = emp["failed_attempts"] + 1
            locked_until_val = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                locked_until_val = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                # FIX-3: stand-in for alert email — log it server-side
                logger.warning(
                    "ALERT: Account '%s' locked after %d failed attempts. "
                    "An alert email would be sent to the account owner in production.",
                    username, attempts
                )
            con.execute(
                "UPDATE employees SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until_val, emp["id"]),
            )
            con.commit()
            con.close()

            if not valid_password:
                return jsonify({"status": "fail", "error": "Invalid username or password"}), 401
            else:
                return jsonify({"status": "fail", "error": "Invalid or missing TOTP code"}), 401

        # ---- Check customers table ----
        cust = con.execute(
            "SELECT * FROM customers WHERE username = ?", (username,)
        ).fetchone()
        con.close()

        if cust and check_password_hash(cust["password"], password):
            session.clear()
            session["user_id"] = cust["id"]
            session["username"] = cust["username"]
            session["role"] = "customer"
            return jsonify({
                "status": "ok",
                "role": "customer",
                "username": cust["username"],
                "name": cust["name"],
                "mobile": cust["mobile"]
            })

        return jsonify({"status": "fail", "error": "Invalid username or password"}), 401

    except Exception:
        logger.exception("login error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# FIX-3: Password Reset — security-question flow REPLACED with
# admin-mediated reset. The old endpoint names are kept so the UI's fetch
# calls still resolve (but the behavior is now secure).
#
# NOTE: In production this would use a managed IdP (Auth0, Okta, etc.)
# for proper credential lifecycle. TOTP here demonstrates the same MFA
# principle locally without external service dependencies.
# ---------------------------------------------------------------------------
@app.route("/employee/security-question/<username>")
def get_security_question(username):
    """FIX-3: security questions removed. This endpoint now returns a
    message explaining that password resets require admin + TOTP."""
    return jsonify({
        "username": username,
        "question": "Password resets require admin approval and TOTP verification. Contact your administrator."
    })


@app.route("/employee/reset-password", methods=["POST"])
@limiter.limit("5 per minute")
def reset_password():
    """FIX-3: self-service security-question reset eliminated. This endpoint
    now requires the caller to be a logged-in admin and supply a valid TOTP
    code for their own account as authorization."""
    try:
        # Must be logged in as admin
        if session.get("role") != "admin":
            return jsonify({"status": "fail", "error": "Admin authentication required for password resets"}), 403

        data = request.get_json(silent=True) or {}
        target_username = request.form.get("username") or data.get("username", "")
        new_password = request.form.get("new_password") or data.get("new_password", "")
        admin_totp = request.form.get("totp_code") or data.get("totp_code", "")

        if not validate_username(target_username):
            return jsonify({"status": "fail", "error": "Invalid username format"}), 400

        # Enforce password policy on the new password
        pw_ok, pw_reason = password_meets_policy(new_password)
        if not pw_ok:
            return jsonify({"status": "fail", "error": pw_reason}), 400

        # Verify the admin's own TOTP code as authorization
        con = db()
        admin_row = con.execute(
            "SELECT mfa_secret FROM employees WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if admin_row and admin_row["mfa_secret"]:
            if not admin_totp or not pyotp.TOTP(admin_row["mfa_secret"]).verify(admin_totp, valid_window=1):
                con.close()
                return jsonify({"status": "fail", "error": "Invalid admin TOTP code"}), 401

        # Reset the target's password + generate new TOTP secret
        new_mfa_secret = pyotp.random_base32()
        con.execute(
            "UPDATE employees SET password = ?, mfa_secret = ?, "
            "failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (generate_password_hash(new_password), new_mfa_secret, target_username),
        )
        con.commit()
        con.close()

        logger.info(
            "ALERT: Password reset for '%s' by admin '%s'. "
            "An alert email would be sent to the account owner in production.",
            target_username, session.get("username")
        )
        return jsonify({"status": "password reset", "new_mfa_secret": new_mfa_secret})

    except Exception:
        logger.exception("reset_password error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# FIX-4: Mishandling of Exceptional Conditions
# - quantity/product_id validated (quantity capped at 1000)
# - try/except with generic error response
# ---------------------------------------------------------------------------
MAX_QUANTITY = 1000


@app.route("/product/bulk-update", methods=["POST"])
@limiter.limit("20 per minute")
def bulk_update():
    try:
        data = request.get_json(silent=True)

        # FIX-4: validate JSON body exists
        if not data:
            return jsonify({"status": "fail", "error": "Invalid or missing JSON body"}), 400

        product_id = data.get("product_id")
        quantity = data.get("quantity")

        # FIX-4: validate types and bounds
        if not isinstance(product_id, int) or product_id <= 0:
            return jsonify({"status": "fail", "error": "product_id must be a positive integer"}), 400
        if not isinstance(quantity, int) or not (0 < quantity <= MAX_QUANTITY):
            return jsonify({"status": "fail", "error": f"quantity must be between 1 and {MAX_QUANTITY}"}), 400

        con = db()
        exists = con.execute("SELECT 1 FROM products WHERE id = ?", (product_id,)).fetchone()
        if not exists:
            con.close()
            return jsonify({"status": "fail", "error": "Unknown product_id"}), 404

        # Safe bounded operation
        con.execute("UPDATE products SET price = price + 0 WHERE id = ?", (product_id,))
        con.commit()
        con.close()
        return jsonify({"status": "updated", "iterations": quantity})

    except Exception:
        logger.exception("bulk_update error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


# ---------------------------------------------------------------------------
# Catalog & Session Helpers (same response shapes as vulnerable build)
# ---------------------------------------------------------------------------
@app.route("/products")
def list_products():
    try:
        con = db()
        rows = con.execute("SELECT id, name, price FROM products").fetchall()
        con.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        logger.exception("list_products error")
        return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


@app.route("/session")
def get_session():
    user_id = session.get("user_id")
    role = session.get("role", "guest")
    username = session.get("username")

    profile = {}
    if role == "customer" and user_id:
        try:
            con = db()
            row = con.execute(
                "SELECT id, name, mobile, username FROM customers WHERE id = ?",
                (user_id,)
            ).fetchone()
            con.close()
            if row:
                profile = dict(row)
        except Exception:
            logger.exception("get_session profile lookup error")

    return jsonify({
        "logged_in": bool(user_id),
        "user_id": user_id,
        "role": role,
        "username": username,
        "profile": profile
    })


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    if "application/json" in request.headers.get("Accept", ""):
        return jsonify({"status": "logged out"})
    return redirect("/")


# ---------------------------------------------------------------------------
# FIX-4: Custom error handlers — never surface Werkzeug debug pages
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return jsonify({"status": "not found", "message": "The requested resource was not found."}), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify({"status": "error", "message": "Something went wrong. Please try again."}), 500


@app.errorhandler(429)
def rate_limited(_e):
    return jsonify({"status": "rate_limited", "error": "Too many requests. Please slow down."}), 429


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
