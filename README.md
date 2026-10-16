# Trust Issues — QuickMart Retail Store

## Problem Statement

A college club has developed an internal web portal for managing members and
administrative activities. The developers claim the application is secure
because users must log in before accessing it. However, authentication alone
does not guarantee security. Users might access resources belonging to
someone else, sensitive information might be exposed, or the application
might incorrectly trust information supplied by clients. This project
builds a small, intentionally vulnerable web application in a controlled
local environment, identifies its security weaknesses, demonstrates their
impact, and implements appropriate fixes.

The application models an ordinary retail store, QuickMart, that operates
both online and in a physical shop, sharing one backend database between
the website and in-store staff tools.

## Project Structure

- `vulnerable/` — the intentionally insecure build. Contains all 4 required
  vulnerabilities, implemented as real, working server-side bugs. Nothing
  in the interface hints at, labels, or exposes any vulnerability — a
  shopper or staff member using the site sees a completely ordinary
  storefront. The vulnerabilities are only discoverable by actually testing
  the application, not by reading the UI.
- `secure/` — a separately built, fixed version of the same storefront,
  created from scratch to implement the proposed fixes rather than patching
  the vulnerable build in place. Same functionality, same roles, same
  routes — the difference is that the 4 vulnerabilities (plus several bonus
  hardening measures) are addressed.
- `seed_db.py` — populates the vulnerable build's database with weak
  credentials and sample data.
- `docker-compose.yml`, `vulnerable/Dockerfile`, `secure/Dockerfile` —
  optional containerized setup so each build runs in an isolated
  environment without needing Python installed locally.

## Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Security testing:** Burp Suite Community Edition
- **Containerization:** Docker (optional, via Docker Compose)

## Roles and Data Model

Three access levels exist, modeling how a real retail store's systems would
be structured:

- **Customer** — can only ever see their own account (name, username,
  mobile number). No access to employee or admin functionality.
- **Employee** — can browse and search the product catalog, and use the
  in-store inventory restock tool. No access to customer PII or price
  management.
- **Admin** — full access: product pricing, customer accounts, and
  inventory.

Data model:

- `products(id, name, price)` — the shared catalog used by both the website
  and the physical store.
- `customers(id, name, mobile, username, password)` — customer PII: real
  name and phone number.
- `employees(id, username, password, role)` — staff accounts, where `role`
  is either `employee` or `admin`.

## Vulnerabilities (vulnerable build)

### 1. SQL Injection

Two separate injection points, both built with raw string formatting
instead of parameterized queries:

- **Product search bar** (`GET /products/search`) — the single search bar
  every visitor uses to look up products by name. A `UNION`-based payload
  pivots out of the `products` table into `customers`, extracting PII such
  as mobile numbers. A separate payload against `sqlite_master` enumerates
  every table name in the database, which matters because an attacker
  testing this blind does not know the customer table's name in advance.
- **Admin price-update field** (`POST /admin/update-price`) — the product
  name field feeds directly into the `WHERE` clause of an `UPDATE`
  statement. A boolean injection payload causes the price change intended
  for one product to apply to every product matching the injected
  condition instead, allowing mass price manipulation.

The employee login form itself uses a parameterized query and is not
injectable — its weakness lies entirely in vulnerability #3 below
(weak credentials), not in the query construction.

### 2. Broken Access Control

Two separate instances:

- **IDOR** — `GET /customer/<id>` performs no authorization check of any
  kind. Any ID is fetchable by anyone, authenticated or not, simply by
  incrementing the number in the URL.
- **Client-supplied parameter override** — the admin-only routes
  (`/admin/update-price`, `/admin/customers`) determine the caller's role
  by reading a `user` query parameter from the URL and trusting it over the
  real server-side session. Appending `?user=admin` to a request grants
  admin-level access regardless of who is actually logged in, or whether
  anyone is logged in at all. The parameter only recognizes the exact
  values `cust`, `empl`, and `admin` — any other value correctly falls back
  to the real session role.

### 3. Authentication Failure

- Three separate admin accounts are seeded with distinct, common weak
  passwords (drawn from a well-known top-200 most-used-passwords list):
  `admin` / `admin123`, `store_admin` / `password`, `manager_admin` /
  `123456`.
- The "forgot password" flow resets a password based on a single weak
  security question (mother's maiden name, date of birth, or place of
  birth) — information that is realistically findable on a public social
  media profile — with no second factor required.
- No rate limiting or lockout exists on either the login form or the
  password reset flow, so both the weak credentials and the weak reset
  question can be brute-forced without friction.

### 4. Mishandling of Exceptional Conditions

- `POST /product/bulk-update` trusts a client-supplied `quantity` value and
  loops that many times with no upper bound. An oversized value ties up the
  server's request-handling resources — an application-layer resource
  exhaustion issue.
- Debug mode is left enabled, so any uncaught exception — a malformed JSON
  payload missing an expected key, or a malformed SQL injection payload
  that breaks query syntax — returns a full interactive stack trace to the
  client, including real table and column names pulled directly from the
  underlying SQLite error text.

Network-layer attacks such as SYN flooding were deliberately not
implemented or tested, since they target the TCP/IP stack and
infrastructure rather than the application's own code, and are out of
scope for this project.

### 5. Additional finding (not one of the original 4, discovered during review)

The `/admin/update-price` response includes the raw injected SQL query
string in its JSON body. This is a separate information-disclosure issue:
it hands an attacker the exact query that was executed, making exploitation
far easier to verify and iterate on directly from the response, rather than
through blind testing.

## Fixes (secure build)

### 1. SQL Injection

All queries touching user input use parameterized (`?`) placeholders —
string formatting is never used to build SQL. As defense-in-depth, the
search term is also capped at 50 characters, though this does not itself
prevent injection; it only limits how much CPU a malicious payload could
otherwise waste.

### 2. Broken Access Control

- The `?user=` override has been removed entirely. Role is determined only
  from the server-side session.
- `/customer/<id>` now requires a logged-in session, and a customer may
  only retrieve their own record — any mismatch between the requested ID
  and the authenticated user's own ID returns a 403 unless the caller is an
  admin.
- Admin-only routes check role via the session exclusively, never via
  request parameters, form data, or JSON body.

### 3. Authentication Failure

- Passwords are hashed with a salted scrypt hash (via `werkzeug.security`)
  rather than stored in plaintext.
- A strong password policy is enforced, rejecting short or common
  passwords.
- The weak security-question reset flow is replaced with TOTP-based
  multi-factor authentication for admin accounts, generated and verified
  with `pyotp`.
- Rate limiting is applied to login and reset attempts (roughly 5 per
  minute), and accounts lock for a cooldown period after 5 consecutive
  failed login attempts.

### 4. Mishandling of Exceptional Conditions

- `quantity` and `product_id` are validated for type and bounds before use;
  quantity is capped at 1000, and invalid or oversized values are rejected
  outright.
- All request handling is wrapped so that unexpected errors return a
  generic error message instead of raw exception detail — the real error
  is still recorded server-side, just never sent back to the client.
- Debug mode is switched off.
- Custom error handlers ensure no path can surface a debugger page.

### Additional hardening included

- **Secure cookies**: session cookies are marked `HttpOnly`, `Secure`, and
  `SameSite`.
- **Security headers**: Content-Security-Policy, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, and Strict-Transport-Security are set
  on every response.
- **Rate limiting and account lockout**, as described above.

## Security Assumptions and Remaining Limitations

These apply to the secure build, and describe what it does not cover or
what it relies on being true in its current, local, unconfigured form:

- The application assumes network-level protections — a firewall, IDS, or
  IPS — are present in front of it. Nothing in the application code defends
  against network-layer denial-of-service attacks; if one occurred, the
  application itself has no countermeasure.
- There is no audit logging system recording who did what and when —
  admin actions such as price changes or customer lookups leave no trace
  beyond the database's current state.
- Account lockout after repeated failed logins applies per account, not
  per IP address. A locked account is locked regardless of where the
  requests originated from.
- The application does not perform a TLS handshake in this local setup.
  Session cookies are signed by Flask (tamper-proof — they cannot be
  forged or edited without the server's secret key) but not encrypted, so
  without HTTPS the cookie's contents still travel in plaintext over the
  network and could be read by anyone intercepting that traffic.

Other categories of vulnerability — such as cross-site scripting, CSRF,
session fixation, or encryption of secrets at rest — were not part of the
4 vulnerabilities this project targets and have not been assessed or
addressed.

## How to Run

### Local (without Docker)

Install dependencies for whichever build you want to run:

```
pip install -r vulnerable/requirements.txt
pip install -r secure/requirements.txt
```

Vulnerable build:

```
python seed_db.py vulnerable
python vulnerable/app.py
```

Runs at `http://127.0.0.1:5000`.

Secure build:

```
python secure/app.py
```

Runs at `http://127.0.0.1:5001`. The secure build seeds its own database on
first run and prints a randomly generated admin password and TOTP secret to
the console — save these, they are shown only once.

### With Docker

Requires Docker Desktop installed and running.

```
docker compose up --build
```

Builds and runs both apps together — vulnerable on port 5000, secure on
port 5001 — with their logs interleaved in one terminal. Run just one with
`docker compose up --build vulnerable` or `docker compose up --build
secure`. Stop everything with `Ctrl+C` followed by `docker compose down`.

## Verification

- `vulnerable/exploits_v2.py` — scripts all 4 attacks against the
  vulnerable build (the two SQL injection payloads, the IDOR and parameter
  override, the weak-credential and reset-flow checks, and the
  resource-exhaustion and stack-trace-leak checks) and prints the result of
  each.
- `secure/verify_fixes.py` — re-runs the same attacks against the secure
  build and asserts that each one is now blocked, alongside a set of
  legitimate-use checks (real login, viewing one's own account, a normal
  price update, a normal search) confirming the fixes did not break actual
  functionality.

## Deliverables

- Source code for both the vulnerable and secured implementations,
  separated into `vulnerable/` and `secure/`.
- Documentation describing each vulnerability, its root cause, and its
  remediation.
- Proof-of-concept demonstrations against the local application, both via
  the exploit scripts above and via manual testing in Burp Suite.
- A security assessment report covering root cause and impact, the fixes
  implemented, and the application's remaining security assumptions and
  limitations.
- This README.

## Testing Policy

All security testing in this project was performed only against a local
instance of this application, owned and controlled by its developer. No
third-party services, campus infrastructure, or other users' systems were
scanned or tested.
