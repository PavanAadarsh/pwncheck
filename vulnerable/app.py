"""
VULNERABLE VERSION -- Retail Storefront
Baseline vulnerable application for demonstration.

Deliberately contains 4 vulnerabilities in server-side logic:
  1. SQL Injection:
     - Storefront product search builds raw string query against products
       (UNION extraction into sqlite_master and customers).
     - Admin price update builds raw string query in WHERE clause
       (boolean injection allows updating prices of expensive products).
     - Login uses parameterized queries (safe from injection).
  2. Broken Access Control:
     - /customer/<id> has no auth check (plain IDOR, unlinked in UI).
     - Admin-only routes (/admin/update-price, /admin/customers) check role
       using client-supplied URL query parameter (?user=admin) over session.
  3. Authentication Failure:
     - 2-3 admin accounts with distinct weak passwords (admin123, password, 123456).
     - Password reset via single weak security question (no MFA, no lockout).
     - No rate limiting on login or password reset.
  4. Mishandling Exceptional Conditions:
     - /product/bulk-update loops client-supplied quantity with no upper bound.
     - DEBUG=True leaks Werkzeug stack traces and SQLite error text on malformed input.

DO NOT deploy this file anywhere reachable from the internet.
"""
from flask import Flask, request, session, jsonify, render_template, redirect
import sqlite3
import os

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "retail-store-session-secret"
app.config["DEBUG"] = True  # VULN-4: debug mode leaks stack traces to client

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "store.db")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# ---------------------------------------------------------------------------
# Storefront Frontend View
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# VULN-1: SQL Injection in Storefront Product Search Bar
# Builds raw string-formatted SQL query against products.
# Allows:
#  - Table enumeration: ' UNION SELECT 1, tbl_name, sql FROM sqlite_master WHERE type='table' --
#  - Customer PII extraction: ' UNION SELECT id, name, mobile FROM customers --
# VULN-4:
#  - Malformed SQL (e.g. test') raises uncaught sqlite3.OperationalError;
#    with DEBUG=True, Flask leaks the SQLite error & real table/column names.
# ---------------------------------------------------------------------------
@app.route("/products/search")
def search_products():
    q = request.args.get("q") or request.args.get("name") or ""
    con = db()
    cur = con.cursor()
    # VULN-1: Raw string concatenation in search query
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
    cur.execute(query)  # VULN-4: Uncaught exception if syntax error
    rows = cur.fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
def current_role():
    # VULN: client-supplied URL parameter is trusted over the real session
    override = request.args.get("user")
    if override in ("cust", "empl", "admin"):
        return override
    return session.get("role")


# ---------------------------------------------------------------------------
# VULN-1 & VULN-2: Admin Price Update
# - VULN-1: Raw string concatenation in WHERE clause allows boolean injection
#   to manipulate prices of expensive products (e.g. name = "' OR price > 1000 --").
# - VULN-2: Role check trusts client-supplied URL query parameter (?user=admin)
#   over the server session.
# ---------------------------------------------------------------------------
@app.route("/admin/update-price", methods=["POST"])
def update_price():
    # VULN-2: Trusts client-supplied URL query parameter ?user=admin
    if current_role() != "admin":
        return jsonify({"status": "forbidden", "error": "Unauthorized: admin role required"}), 403

    data = request.get_json(silent=True) or {}
    product_name = request.form.get("name") or data.get("name", "")
    new_price = request.form.get("price") or data.get("price", 0)

    con = db()
    cur = con.cursor()
    # VULN-1: Raw string concatenation in WHERE clause
    query = f"UPDATE products SET price = {new_price} WHERE name = '{product_name}'"
    cur.execute(query)
    con.commit()
    rows_affected = cur.rowcount
    con.close()
    return jsonify({"status": "success", "rows_affected": rows_affected, "query": query})


# ---------------------------------------------------------------------------
# VULN-2: Broken Access Control
# - /customer/<id>: Plain IDOR with no authorization check at all.
# - /admin/customers: Trusts client-supplied URL query parameter ?user=admin.
# ---------------------------------------------------------------------------
@app.route("/customer/<int:cust_id>")
def get_customer(cust_id):
    # VULN-2 Instance 1: Plain IDOR -- no auth check, reachable only via direct URL
    con = db()
    row = con.execute("SELECT id, name, mobile FROM customers WHERE id = ?", (cust_id,)).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Customer not found"}), 404
    return jsonify({"id": row["id"], "name": row["name"], "mobile": row["mobile"]})


@app.route("/admin/customers")
def admin_customers():
    # VULN-2 Instance 2: Trusts client-supplied URL query parameter ?user=admin
    if current_role() != "admin":
        return jsonify({"status": "forbidden", "error": "Unauthorized: admin role required"}), 403

    con = db()
    rows = con.execute("SELECT id, name, mobile, username FROM customers").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Login (SAFE FROM SQLi -- Parameterized Query)
# Purely weak on credentials (VULN-3), not vulnerable to SQL injection.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
@app.route("/employee/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = request.form.get("username") or data.get("username", "")
    password = request.form.get("password") or data.get("password", "")

    con = db()
    cur = con.cursor()

    # Check employees table (staff/admin) with parameterized query
    cur.execute("SELECT * FROM employees WHERE username = ? AND password = ?", (username, password))
    emp = cur.fetchone()

    if emp:
        con.close()
        session["user_id"] = emp["id"]
        session["username"] = emp["username"]
        session["role"] = emp["role"]
        return jsonify({
            "status": "ok",
            "role": emp["role"],
            "username": emp["username"],
            "name": emp["username"].capitalize()
        })

    # Check customers table with parameterized query
    cur.execute("SELECT * FROM customers WHERE username = ? AND password = ?", (username, password))
    cust = cur.fetchone()
    con.close()

    if cust:
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


# ---------------------------------------------------------------------------
# VULN-3: Authentication Failure (Weak Security Questions, No Lockout/MFA)
# ---------------------------------------------------------------------------
SECURITY_QUESTIONS = {
    "admin": {
        "question": "What is your mother's maiden name?",
        "answer": "Fernandez"
    },
    "store_admin": {
        "question": "What is your date of birth? (DD/MM/YYYY)",
        "answer": "12/04/1985"
    },
    "manager_admin": {
        "question": "What was your place of birth?",
        "answer": "Mumbai"
    },
}


@app.route("/employee/security-question/<username>")
def get_security_question(username):
    qa = SECURITY_QUESTIONS.get(username)
    if qa:
        return jsonify({"username": username, "question": qa["question"]})
    return jsonify({"username": username, "question": "What is your mother's maiden name?"})


@app.route("/employee/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    username = request.form.get("username") or data.get("username", "")
    answer = request.form.get("answer") or data.get("answer", "")
    new_password = request.form.get("new_password") or data.get("new_password", "")

    qa = SECURITY_QUESTIONS.get(username)
    if qa and answer.strip().lower() == qa["answer"].lower():  # Single factor, no lockout, no MFA
        con = db()
        con.execute("UPDATE employees SET password = ? WHERE username = ?", (new_password, username))
        con.commit()
        con.close()
        return jsonify({"status": "password reset"})
    return jsonify({"status": "fail", "error": "Incorrect security answer"}), 401


# ---------------------------------------------------------------------------
# VULN-4: Mishandling of Exceptional Conditions (App-layer DoS)
# - Unbounded loop on client-supplied quantity.
# - Malformed JSON triggers uncaught KeyError with full traceback when DEBUG=True.
# ---------------------------------------------------------------------------
@app.route("/product/bulk-update", methods=["POST"])
def bulk_update():
    data = request.get_json()  # VULN-4: uncaught KeyError if payload malformed
    product_id = data["product_id"]
    quantity = data["quantity"]

    con = db()
    total = 0
    for _ in range(quantity):  # VULN-4: unbounded loop, CPU/resource exhaustion
        total += 1
    con.execute("UPDATE products SET price = price + 0 WHERE id = ?", (product_id,))
    con.commit()
    con.close()
    return jsonify({"status": "updated", "iterations": total})


# ---------------------------------------------------------------------------
# Catalog & Session Helpers
# ---------------------------------------------------------------------------
@app.route("/products")
def list_products():
    con = db()
    rows = con.execute("SELECT id, name, price FROM products").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/session")
def get_session():
    user_id = session.get("user_id")
    role = session.get("role", "guest")
    username = session.get("username")

    profile = {}
    if role == "customer" and user_id:
        con = db()
        row = con.execute("SELECT id, name, mobile, username FROM customers WHERE id = ?", (user_id,)).fetchone()
        con.close()
        if row:
            profile = dict(row)

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
