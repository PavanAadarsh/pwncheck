"""
verify_fixes.py -- Full adversarial + legitimate-use verification (23 checks).

Part 1 (checks 1-17): Replay the exact 4 attack categories from
    vulnerable/exploits_v2.py and confirm each is now blocked.
Part 2 (checks A-D): Close 3 remaining gaps and verify legitimate use.

Prerequisites:
    cd secure && python app.py   (running on :5001)
    python verify_fixes.py       (this script, from any terminal)

The script reads the admin TOTP seed directly from the SQLite DB so it
can generate live TOTP codes for authenticated-admin tests.
"""
import requests
import time
import sys
import json
import io
import os
import sqlite3

# Force UTF-8 on Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

try:
    import pyotp
except ImportError:
    print("ERROR: pyotp is required.  pip install pyotp")
    sys.exit(1)

BASE = "http://127.0.0.1:5001"
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secure_store.db")

passed = 0
failed = 0
total = 0


def check(test_id: str, test_name: str, condition: bool, detail: str = ""):
    global passed, failed, total
    total += 1
    if condition:
        passed += 1
        print(f"  [PASS]  [{test_id}] {test_name}")
    else:
        failed += 1
        print(f"  [FAIL]  [{test_id}] {test_name}")
    if detail:
        print(f"           {detail}")
    print()


def get_admin_creds():
    """Read admin password hash and TOTP seed from DB.
    The plaintext password is only available at first-run; for tests that
    need to log in as admin, we read the mfa_secret from the DB and the
    script requires ADMIN_PASSWORD env var or the password file."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM employees WHERE username = 'admin'").fetchone()
    con.close()
    return dict(row) if row else None


def get_staff_creds():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM employees WHERE username = 'floor_staff'").fetchone()
    con.close()
    return dict(row) if row else None


# ===================================================================
# PART 1: ORIGINAL 17 ATTACK CHECKS
# ===================================================================

def test_sql_injection():
    print("\n" + "=" * 72)
    print("TEST 1 -- SQL INJECTION (FIX-1: parameterized queries)")
    print("=" * 72)

    payload = "' UNION SELECT id, name, mobile FROM customers --"
    r = requests.get(f"{BASE}/products/search", params={"q": payload})
    try:
        body = r.json()
        has_pii = any(
            "Ravi" in str(item) or "Meena" in str(item) or "Arjun" in str(item)
            or "9876543210" in str(item)
            for item in (body if isinstance(body, list) else [body])
        )
    except Exception:
        has_pii = False
        body = r.text[:200]
    check("1a", "UNION injection returns NO customer PII",
          not has_pii,
          f"Status: {r.status_code} | Body: {json.dumps(body)[:200] if isinstance(body, (list, dict)) else str(body)[:200]}")

    payload2 = "' UNION SELECT 1, tbl_name, sql FROM sqlite_master WHERE type='table' --"
    r2 = requests.get(f"{BASE}/products/search", params={"q": payload2})
    try:
        body2 = r2.json()
        has_tables = any(
            "employees" in str(item) or "customers" in str(item)
            for item in (body2 if isinstance(body2, list) else [body2])
        )
    except Exception:
        has_tables = False
        body2 = r2.text[:200]
    check("1b", "UNION injection (long) returns NO table names",
          not has_tables,
          f"Status: {r2.status_code} | Body: {json.dumps(body2)[:200] if isinstance(body2, (list, dict)) else str(body2)[:200]}")

    products_before = requests.get(f"{BASE}/products").json()
    prices_before = {p["name"]: p["price"] for p in products_before}
    r3 = requests.post(f"{BASE}/admin/update-price",
                        json={"name": "' OR price > 1000 --", "price": 1})
    products_after = requests.get(f"{BASE}/products").json()
    prices_after = {p["name"]: p["price"] for p in products_after}
    prices_changed = any(prices_before.get(n) != prices_after.get(n) for n in prices_before)
    check("1c", "SQLi in price update (unauthenticated) blocked",
          r3.status_code in (401, 403) or not prices_changed,
          f"Status: {r3.status_code} | Prices changed: {prices_changed}")


def test_broken_access_control():
    print("\n" + "=" * 72)
    print("TEST 2 -- BROKEN ACCESS CONTROL (FIX-2: session-only role checks)")
    print("=" * 72)

    r = requests.get(f"{BASE}/customer/2")
    check("2a", "GET /customer/2 (unauthenticated) -> 403",
          r.status_code in (401, 403),
          f"Status: {r.status_code} | Body: {r.text[:200]}")

    s = requests.Session()
    s.post(f"{BASE}/login", json={"username": "ravik", "password": "custpass1"})
    r_idor = s.get(f"{BASE}/customer/2")
    check("2a+", "GET /customer/2 (as customer 1) -> 403",
          r_idor.status_code in (401, 403),
          f"Status: {r_idor.status_code} | Body: {r_idor.text[:200]}")

    r1 = requests.get(f"{BASE}/admin/customers", params={"user": "admin"})
    check("2b-i", "GET /admin/customers?user=admin (unauth) -> 403",
          r1.status_code in (401, 403),
          f"Status: {r1.status_code}")

    r2 = requests.get(f"{BASE}/admin/customers", params={"user": "admin"},
                       cookies=s.cookies)
    check("2b-ii", "GET /admin/customers?user=admin (as customer) -> 403",
          r2.status_code in (401, 403),
          f"Status: {r2.status_code}")

    r3 = requests.get(f"{BASE}/admin/customers", params={"user": "cust"})
    check("2b-iii", "GET /admin/customers?user=cust -> 403",
          r3.status_code in (401, 403),
          f"Status: {r3.status_code}")

    r4 = requests.post(f"{BASE}/admin/update-price?user=admin",
                        json={"name": "Wireless Mouse", "price": 1})
    check("2c", "POST /admin/update-price?user=admin (non-admin) -> 403",
          r4.status_code in (401, 403),
          f"Status: {r4.status_code}")


def test_weak_auth():
    """Uses a fresh session (no prior /login hits in this function)."""
    print("\n" + "=" * 72)
    print("TEST 3 -- AUTHENTICATION FAILURE (FIX-3: hashed pw, MFA, lockout)")
    print("=" * 72)

    s = requests.Session()
    candidates = [
        ("admin", "admin123"),
        ("store_admin", "password"),
        ("manager_admin", "123456"),
    ]
    for user, pw in candidates:
        r = s.post(f"{BASE}/login", json={"username": user, "password": pw})
        login_ok = r.status_code == 200 and r.json().get("status") == "ok"
        check(f"3a-{user}", f"Login {user}/{pw} REJECTED",
              not login_ok,
              f"Status: {r.status_code} | Body: {r.text[:150]}")

    # Lockout test moved to Test C (Part 2) for isolated counting

    r_reset = requests.post(f"{BASE}/employee/reset-password", data={
        "username": "admin", "answer": "Fernandez", "new_password": "hacked123"
    })
    reset_worked = r_reset.status_code == 200 and r_reset.json().get("status") == "password reset"
    check("3c", "Security-question-only reset BLOCKED",
          not reset_worked,
          f"Status: {r_reset.status_code} | Body: {r_reset.text[:200]}")


def test_exceptional_conditions():
    print("\n" + "=" * 72)
    print("TEST 4 -- EXCEPTIONAL CONDITIONS (FIX-4: validation, no debug)")
    print("=" * 72)

    start = time.time()
    r = requests.post(f"{BASE}/product/bulk-update",
                       json={"product_id": 1, "quantity": 50_000_000}, timeout=15)
    elapsed = time.time() - start
    check("4a", "Oversized quantity (50M) rejected as 400, near-instant",
          r.status_code == 400 and elapsed < 2,
          f"Status: {r.status_code} | Elapsed: {elapsed:.3f}s | Body: {r.text[:200]}")

    r2 = requests.post(f"{BASE}/product/bulk-update", json={"product_id": 1})
    has_trace = any(kw in r2.text.lower() for kw in ["traceback", "debugger", "werkzeug", 'file "'])
    check("4b", "Missing key -> generic JSON error, NO stack trace",
          r2.status_code in (400, 500) and not has_trace,
          f"Status: {r2.status_code} | Has trace: {has_trace} | Body: {r2.text[:300]}")

    r3 = requests.get(f"{BASE}/products/search", params={"name": "test'"})
    has_leak = any(kw in r3.text.lower() for kw in [
        "operationalerror", "sqlite3.operationalerror", "traceback", "debugger",
    ])
    check("4c", "Malformed SQL -> no stack trace or schema leak",
          not has_leak,
          f"Status: {r3.status_code} | Body: {r3.text[:300]}")


# ===================================================================
# PART 2: GAP-CLOSING + LEGITIMATE-USE CHECKS
# ===================================================================

def test_A_short_sqli_payload():
    """Test A: Schema enumeration with a payload UNDER 50 chars so the
    length cap is not the thing blocking it."""
    print("\n" + "=" * 72)
    print("TEST A -- Short SQLi payload (under 50 chars, bypasses length cap)")
    print("=" * 72)

    # This payload is 49 characters (under the 50-char cap)
    payload = "' UNION SELECT 1,tbl_name,2 FROM sqlite_master --"
    print(f"  Payload length: {len(payload)} chars")

    r = requests.get(f"{BASE}/products/search", params={"q": payload})
    try:
        body = r.json()
        has_table_names = any(
            tbl in str(item).lower()
            for item in (body if isinstance(body, list) else [body])
            for tbl in ["employees", "customers", "products", "sqlite_master"]
        )
    except Exception:
        has_table_names = False
        body = r.text[:200]
    check("A", "Short UNION injection returns NO real table names",
          not has_table_names,
          f"Status: {r.status_code} | Body: {json.dumps(body)[:300] if isinstance(body, (list, dict)) else str(body)[:300]}")


def test_B_authenticated_admin_sqli(admin_password, admin_totp_seed):
    """Test B: Price-manipulation SQLi as a real authenticated admin."""
    print("\n" + "=" * 72)
    print("TEST B -- Authenticated admin price SQLi")
    print("=" * 72)

    s = requests.Session()

    # Log in as admin with real credentials
    totp_code = pyotp.TOTP(admin_totp_seed).now()
    login_r = s.post(f"{BASE}/login", json={
        "username": "admin",
        "password": admin_password,
        "totp_code": totp_code,
    })
    print(f"  Admin login: status={login_r.status_code}, body={login_r.text[:200]}")
    if login_r.status_code != 200 or login_r.json().get("status") != "ok":
        check("B-login", "Admin login succeeded", False,
              f"Cannot proceed -- admin login failed: {login_r.text[:200]}")
        return

    # Record all prices BEFORE
    products_before = s.get(f"{BASE}/products").json()
    prices_before = {p["name"]: p["price"] for p in products_before}
    print(f"  Prices before: {prices_before}")

    # Submit the SQLi price update as authenticated admin
    sqli_r = s.post(f"{BASE}/admin/update-price", json={
        "name": "' OR price > 1000 --",
        "price": 1,
    })
    print(f"  SQLi update: status={sqli_r.status_code}, body={sqli_r.text[:200]}")

    # Record all prices AFTER
    products_after = s.get(f"{BASE}/products").json()
    prices_after = {p["name"]: p["price"] for p in products_after}
    print(f"  Prices after:  {prices_after}")

    changed_products = [n for n in prices_before if prices_before[n] != prices_after.get(n)]
    print(f"  Changed products: {changed_products if changed_products else 'none'}")

    # PASS if either: request was rejected (400), or 0-1 products changed (the literal name match)
    if sqli_r.status_code == 400:
        check("B", "Authenticated SQLi price update rejected (400)",
              True, f"Server rejected the payload outright")
    else:
        check("B", "Authenticated SQLi does NOT mass-update prices",
              len(changed_products) <= 1,
              f"Changed: {len(changed_products)} product(s) -- {changed_products}")


def test_C_isolated_lockout(target_account):
    """Test C: Isolated rate-limit/lockout count with zero prior requests.
    Uses a fresh session and a specific account that hasn't been touched."""
    print("\n" + "=" * 72)
    print(f"TEST C -- Isolated lockout/rate-limit count (account: {target_account})")
    print("=" * 72)

    s = requests.Session()
    lockout_attempt = None

    for i in range(1, 12):  # up to 11 attempts to find the boundary
        r = s.post(f"{BASE}/login", json={
            "username": target_account,
            "password": f"wrong_password_{i}",
            "totp_code": "000000",
        })
        status = r.status_code
        print(f"    Attempt {i}: status={status} | body={r.text[:100]}")

        if status in (423, 429):
            lockout_attempt = i
            print(f"    >>> Lockout/rate-limit triggered on attempt {i}")
            break

    if lockout_attempt is not None:
        # The design specifies: rate-limit = 5 per minute, lockout = 5 failures
        # So we expect lockout/rate-limit at attempt 5 or 6
        is_at_threshold = lockout_attempt <= 6
        check("C", f"Lockout triggered at attempt {lockout_attempt} (design threshold: 5)",
              is_at_threshold,
              f"Triggered at attempt {lockout_attempt}. "
              f"{'Matches spec (<=6)' if is_at_threshold else 'OUTSIDE expected range'}")
    else:
        check("C", "Lockout/rate-limit triggered within 11 attempts",
              False, "No lockout observed in 11 attempts")


def test_D_legitimate_use(admin_password, admin_totp_seed):
    """Test D: Legitimate-use 'should succeed' checks."""
    print("\n" + "=" * 72)
    print("TEST D -- LEGITIMATE USE (should-succeed checks)")
    print("=" * 72)

    # D1: Customer login with correct credentials
    s_cust = requests.Session()
    r_cust_login = s_cust.post(f"{BASE}/login", json={
        "username": "ravik", "password": "custpass1"
    })
    cust_ok = r_cust_login.status_code == 200 and r_cust_login.json().get("status") == "ok"
    check("D1", "Customer login (ravik/custpass1) succeeds",
          cust_ok,
          f"Status: {r_cust_login.status_code} | Body: {r_cust_login.text[:200]}")

    # D2: Customer can GET /customer/<own id>
    if cust_ok:
        # ravik is customer id=1
        r_own = s_cust.get(f"{BASE}/customer/1")
        own_ok = r_own.status_code == 200
        try:
            own_data = r_own.json()
            has_own_data = own_data.get("name") == "Ravi Kumar"
        except Exception:
            has_own_data = False
        check("D2", "Customer GET /customer/1 (own record) returns own data",
              own_ok and has_own_data,
              f"Status: {r_own.status_code} | Body: {r_own.text[:200]}")
    else:
        check("D2", "Customer GET /customer/1 (own record) returns own data",
              False, "Skipped -- customer login failed")

    # D3: Admin login with correct credentials + TOTP
    s_admin = requests.Session()
    totp_code = pyotp.TOTP(admin_totp_seed).now()
    r_admin_login = s_admin.post(f"{BASE}/login", json={
        "username": "admin",
        "password": admin_password,
        "totp_code": totp_code,
    })
    admin_ok = r_admin_login.status_code == 200 and r_admin_login.json().get("status") == "ok"
    check("D3", "Admin login (admin + correct password + TOTP) succeeds",
          admin_ok,
          f"Status: {r_admin_login.status_code} | Body: {r_admin_login.text[:200]}")

    # D4: Admin legitimate price update
    if admin_ok:
        # Read current price of "Wireless Mouse"
        products = s_admin.get(f"{BASE}/products").json()
        old_price = next((p["price"] for p in products if p["name"] == "Wireless Mouse"), None)
        new_price = 899.0 if old_price != 899.0 else 999.0

        r_price = s_admin.post(f"{BASE}/admin/update-price", json={
            "name": "Wireless Mouse",
            "price": new_price,
        })
        price_ok = r_price.status_code == 200 and r_price.json().get("status") == "success"

        # Verify the price actually changed
        products_after = s_admin.get(f"{BASE}/products").json()
        actual_price = next((p["price"] for p in products_after if p["name"] == "Wireless Mouse"), None)

        check("D4", f"Admin price update (Wireless Mouse -> {new_price}) succeeds",
              price_ok and actual_price == new_price,
              f"Status: {r_price.status_code} | Old: {old_price} | New: {actual_price} | Body: {r_price.text[:150]}")
    else:
        check("D4", "Admin price update succeeds", False, "Skipped -- admin login failed")

    # D5: Product search with real substring
    r_search = requests.get(f"{BASE}/products/search", params={"q": "Mouse"})
    try:
        search_data = r_search.json()
        found_mouse = any("Mouse" in str(item.get("name", "")) for item in search_data)
    except Exception:
        found_mouse = False
        search_data = r_search.text[:200]
    check("D5", "GET /products/search?q=Mouse returns matching product",
          r_search.status_code == 200 and found_mouse,
          f"Status: {r_search.status_code} | Results: {json.dumps(search_data)[:200] if isinstance(search_data, list) else str(search_data)[:200]}")

    # D6: Legitimate bulk-update with small quantity
    r_bulk = requests.post(f"{BASE}/product/bulk-update", json={
        "product_id": 1, "quantity": 5
    })
    try:
        bulk_data = r_bulk.json()
        bulk_ok = r_bulk.status_code == 200 and bulk_data.get("status") == "updated"
    except Exception:
        bulk_ok = False
        bulk_data = r_bulk.text[:200]
    check("D6", "POST /product/bulk-update (quantity=5) succeeds",
          bulk_ok,
          f"Status: {r_bulk.status_code} | Body: {json.dumps(bulk_data)[:200] if isinstance(bulk_data, dict) else str(bulk_data)[:200]}")


# ===================================================================
# MAIN
# ===================================================================
def main():
    global passed, failed, total

    print("=" * 72)
    print("SECURE BUILD VERIFICATION -- verify_fixes.py (23 checks)")
    print(f"Target: {BASE}")
    print("=" * 72)

    # Health check
    try:
        r = requests.get(f"{BASE}/", timeout=5)
        if r.status_code != 200:
            print(f"ERROR: Secure app returned {r.status_code}")
            sys.exit(1)
        print(f"Health check: OK (status {r.status_code})")
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Cannot connect to {BASE}")
        print("Start the secure app first: cd secure && python app.py")
        sys.exit(1)

    # Read admin credentials from DB for authenticated tests
    admin_row = get_admin_creds()
    if not admin_row:
        print("ERROR: No admin account found in DB")
        sys.exit(1)
    admin_totp_seed = admin_row["mfa_secret"]

    # The admin password is only known at seed time; read from env or prompt
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        # Try to read from the server log (convenience for automated testing)
        log_candidates = [
            os.path.join(os.path.dirname(__file__), "..", ".admin_password"),
        ]
        for lf in log_candidates:
            if os.path.exists(lf):
                admin_password = open(lf).read().strip()
                break

    if not admin_password:
        print("\nAdmin password not found in ADMIN_PASSWORD env var.")
        print("Enter the admin password from the secure app's first-run output:")
        admin_password = input("  admin password: ").strip()

    print(f"\nAdmin TOTP seed: {admin_totp_seed}")
    print(f"Admin password:  {'*' * len(admin_password)} ({len(admin_password)} chars)")

    # ---- Part 1: Original 17 attack checks ----
    print("\n" + "#" * 72)
    print("# PART 1: ATTACK CHECKS (should all be BLOCKED)")
    print("#" * 72)

    test_sql_injection()
    test_broken_access_control()
    test_weak_auth()
    test_exceptional_conditions()

    # ---- Part 2: Gap-closing + legitimate use ----
    print("\n" + "#" * 72)
    print("# PART 2: GAP-CLOSING + LEGITIMATE-USE CHECKS")
    print("#" * 72)

    test_A_short_sqli_payload()
    test_B_authenticated_admin_sqli(admin_password, admin_totp_seed)
    test_C_isolated_lockout("floor_staff")  # fresh account, no prior hits
    test_D_legitimate_use(admin_password, admin_totp_seed)

    # ---- Final summary ----
    print("\n" + "=" * 72)
    print(f"FINAL RESULTS: {passed}/{total} checks PASSED, {failed}/{total} FAILED")
    if failed == 0:
        print("ALL ATTACKS BLOCKED + ALL LEGITIMATE USE WORKS -- secure build verified.")
    else:
        print("SOME CHECKS FAILED -- review the output above.")
    print("=" * 72)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
