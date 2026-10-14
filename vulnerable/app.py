"""
VULNERABLE VERSION -- for controlled, local demonstration only.
Run seed_db.py (from the project root, mode="vulnerable") before starting this.

Deliberately contains 4 vulnerabilities, each labeled with a VULN comment:

  VULN-1  SQL Injection in employee login
  VULN-2  Broken Access Control on /customer/<id>
  VULN-3  Authentication failure: weak admin password + weak "security
          question" reset flow + no lockout/rate limiting
  VULN-4  Mishandling of exceptional conditions: unvalidated input crashes
          the app / leaks stack traces, unbounded loop allows resource
          exhaustion

DO NOT deploy this file anywhere reachable from the internet.
"""
from flask import Flask, request, session, jsonify, redirect
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "dev-secret-not-for-prod"
app.config["DEBUG"] = True  # VULN-4: debug mode -> leaks stack traces to the client

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "store.db")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# ---------------------------------------------------------------------------
# VULN-1: SQL Injection in employee login
# The query is built with raw string formatting instead of parameters, so a
# username like   admin' --            bypasses the password check entirely,
# and a username like   ' UNION SELECT id,name,mobile,username,1,1,1 FROM customers --
# can be used to pull data out of an unrelated table.
# ---------------------------------------------------------------------------
@app.route("/employee/login", methods=["POST"])
def employee_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    con = db()
    query = f"SELECT * FROM employees WHERE username = '{username}' AND password = '{password}'"
    cur = con.cursor()
    cur.execute(query)  # <-- VULN-1: string-built SQL, no parameterization
    row = cur.fetchone()
    con.close()

    if row:
        session["employee_id"] = row["id"]
        session["role"] = row["role"]
        return jsonify({"status": "ok", "role": row["role"]})
    return jsonify({"status": "fail"}), 401


# ---------------------------------------------------------------------------
# VULN-2: Broken Access Control
# Any logged-in employee (not just admins) -- or in this buggy version, even
# an unauthenticated request -- can fetch ANY customer's PII just by
# incrementing the id in the URL. There is no check that the caller is an
# admin, nor that a customer is only viewing their own record.
# ---------------------------------------------------------------------------
@app.route("/customer/<int:cust_id>")
def get_customer(cust_id):
    # no session / role check at all here -- VULN-2
    con = db()
    row = con.execute("SELECT id, name, mobile FROM customers WHERE id = ?", (cust_id,)).fetchone()
    con.close()
    if not row:
        return jsonify({"status": "not found"}), 404
    return jsonify({"id": row["id"], "name": row["name"], "mobile": row["mobile"]})


# ---------------------------------------------------------------------------
# VULN-3: Authentication failure
#  (a) the admin account was seeded with a weak, guessable password (admin123)
#  (b) the "forgot password" flow resets a password using a security
#      question whose answer is realistically findable on a social media
#      profile (mother's maiden name / first pet) -- no second factor
#  (c) there is no rate limiting or lockout, so both (a) and (b) can be
#      brute-forced without any friction
# ---------------------------------------------------------------------------
SECURITY_QUESTIONS = {
    # In a real deployment these answers are frequently public on Facebook/
    # Instagram bios, old blog posts, etc. -- that is exactly the weakness.
    "admin": {"question": "What is your mother's maiden name?", "answer": "Fernandez"},
}


@app.route("/employee/reset-password", methods=["POST"])
def reset_password():
    username = request.form.get("username", "")
    answer = request.form.get("answer", "")
    new_password = request.form.get("new_password", "")

    qa = SECURITY_QUESTIONS.get(username)
    if qa and answer.strip().lower() == qa["answer"].lower():  # VULN-3: single
        # easily-researched factor, no rate limit on attempts, no MFA
        con = db()
        con.execute("UPDATE employees SET password = ? WHERE username = ?", (new_password, username))
        con.commit()
        con.close()
        return jsonify({"status": "password reset"})
    return jsonify({"status": "fail"}), 401


# ---------------------------------------------------------------------------
# VULN-4: Mishandling of exceptional conditions
#  (a) /product/bulk-update trusts a client-supplied "quantity" and loops
#      that many times with no upper bound -> a single request with a huge
#      number ties up the worker and can exhaust CPU/memory (an
#      application-layer DoS triggered by a malformed/oversized payload --
#      the kind of thing a SYN flood would do at the network layer, except
#      this is the app's own fault for not validating input)
#  (b) malformed JSON / wrong types raise an uncaught exception, and because
#      DEBUG=True above, Flask returns a full stack trace to the client --
#      an information disclosure bug on top of the crash itself
# ---------------------------------------------------------------------------
@app.route("/product/bulk-update", methods=["POST"])
def bulk_update():
    data = request.get_json()  # VULN-4b: no try/except, no schema check
    product_id = data["product_id"]
    quantity = data["quantity"]

    con = db()
    total = 0
    for _ in range(quantity):  # VULN-4a: unbounded, attacker-controlled loop
        total += 1
    con.execute(
        "UPDATE products SET price = price + 0 WHERE id = ?", (product_id,)
    )
    con.commit()
    con.close()
    return jsonify({"status": "updated", "iterations": total})


@app.route("/products")
def list_products():
    con = db()
    rows = con.execute("SELECT id, name, price FROM products").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    # host="0.0.0.0" so the container's published port actually reaches this
    # process -- 127.0.0.1 (the old default) is only reachable from inside
    # the container itself. This is a networking setting, not a security fix.
    app.run(host="0.0.0.0", port=5000)
