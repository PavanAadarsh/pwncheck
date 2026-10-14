"""
seed_db.py
Builds a fresh SQLite database (store.db) with the three-tier data model:
  - products   : accessible to all logged-in employees/admins
  - customers  : PII (name + mobile) -- admin-only
  - employees  : employee/admin accounts (role = 'employee' | 'admin')

Run this once in each app folder (vulnerable/ and secure/) before starting
the respective app.py. It intentionally seeds a WEAK admin password in the
vulnerable DB and a STRONG hashed one in the secure DB -- see the two
app.py files for how each one is created and checked.
"""
import sqlite3
import sys
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "store.db")


def build(weak_admin: bool):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mobile TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('employee','admin')),
            mfa_secret TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
    """)

    products = [
        ("Wireless Mouse", 799.0),
        ("Mechanical Keyboard", 3499.0),
        ("27-inch Monitor", 15999.0),
        ("USB-C Hub", 1299.0),
        ("Noise Cancelling Headphones", 8999.0),
    ]
    cur.executemany("INSERT INTO products (name, price) VALUES (?,?)", products)

    customers = [
        ("Ravi Kumar", "9876543210", "ravik", "custpass1"),
        ("Meena Shah", "9123456780", "meenas", "custpass2"),
        ("Arjun Nair", "9988776655", "arjunn", "custpass3"),
    ]
    cur.executemany(
        "INSERT INTO customers (name, mobile, username, password) VALUES (?,?,?,?)",
        customers,
    )

    if weak_admin:
        # VULNERABLE seed: trivially guessable admin credentials, plaintext storage
        employees = [
            ("floor_staff", "staff123", "employee", None, 0, None),
            ("admin", "admin123", "admin", None, 0, None),
        ]
        cur.executemany(
            "INSERT INTO employees (username, password, role, mfa_secret, failed_attempts, locked_until) "
            "VALUES (?,?,?,?,?,?)",
            employees,
        )
    else:
        # SECURE seed: handled separately in secure/app.py so we can hash + attach TOTP
        pass

    con.commit()
    con.close()
    print(f"Database created at {DB_PATH} (weak_admin={weak_admin})")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"
    build(weak_admin=(mode == "vulnerable"))
