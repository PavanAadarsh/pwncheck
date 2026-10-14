# Trust Issues — Vulnerable vs Secure Retail Store

Two runnable Flask apps sharing one data model (products / customers / employees,
three access levels: customer, employee, admin). Deliberately scoped to the
4 vulnerabilities you listed — reporting items (root cause write-up, limitations
doc) are intentionally left for later, as agreed.

## Run it

```bash
pip install -r vulnerable/requirements.txt
pip install -r secure/requirements.txt

# Vulnerable build
python seed_db.py vulnerable
cd vulnerable && python app.py          # http://127.0.0.1:5000
python exploits.py                      # in a second terminal — runs all 4 attacks

# Secure build (separate store.db — self-seeds on first run, auto-generates
# a strong admin password + TOTP secret, printed once to the console)
cd ../secure && python app.py           # http://127.0.0.1:5001
```

## Running with Docker (optional — everything above still works without it)

Docker just packages each app plus its exact Python version/dependencies into
a self-contained "container" so it runs the same on any machine, without you
installing Python packages manually. You don't need to understand it deeply
to use it here.

**One-time setup**: install Docker Desktop from docker.com and open it (it
needs to be running in the background). Confirm it's installed:
```bash
docker --version
```

**Run both apps**, from the project root (the folder with `docker-compose.yml`):
```bash
docker compose up --build
```
First run takes a minute or two (downloading the Python base image). After
that you'll see both apps' startup logs interleaved in one terminal —
vulnerable on `http://127.0.0.1:5000`, secure on `http://127.0.0.1:5001`,
exactly like running them manually. The secure app will print its
auto-generated admin password and TOTP secret in this log, same as before.

**Stop everything**: `Ctrl+C`, then `docker compose down`.

**Run just one**: `docker compose up --build vulnerable` or `... secure`.

**Re-test the exploits** while the vulnerable container is running — `exploits.py`
talks to `http://127.0.0.1:5000` either way, so run it exactly as before,
from your normal terminal (not inside the container):
```bash
cd vulnerable && python exploits.py
```

Note: I don't have a Docker daemon available on my end, so I've written and
syntax-checked these files carefully but couldn't actually build/run the
images myself — please do a real `docker compose up --build` on your machine
as the first real test, and tell me if anything errors.

## Vulnerability → Fix map

| # | Vulnerability | Root cause (vulnerable/app.py) | Fix (secure/app.py) |
|---|---|---|---|
| 1 | SQL injection, employee login | Query built with an f-string, user input concatenated directly into SQL | Parameterized query (`?` placeholders); `admin' --` now just fails to match a real username |
| 2 | Broken access control | `/customer/<id>` has no auth/role check at all | `@require_role("admin")` RBAC decorator on the lookup-by-id route; customers get a separate `/me/customer` bound to their own session, never to an arbitrary id |
| 3 | Authentication failure | Default admin password `admin123`; password reset via a guessable "security question"; no lockout | Random strong password generated at seed time (hashed with `werkzeug.security`); TOTP-based MFA (`pyotp`) required on every login; security-question reset removed entirely, replaced with admin-mediated reset; failed-attempt counter + 15-min lockout after 5 failures |
| 4 | Mishandling exceptional conditions | Unbounded attacker-controlled loop (`quantity`); missing try/except; `DEBUG=True` leaks stack traces | Input type/range validation (`quantity` capped at 1000), try/except around all handlers, generic 500 response, `DEBUG=False`, custom error handlers |

## Bonus items included (flagged as priority in your brief)

- **Rate limiting + lockout**: `flask-limiter` on `/employee/login` (5/min) and
  `/product/bulk-update` (20/min); DB-tracked failed-attempt lockout independent
  of the rate limiter.
- **RBAC**: `require_role(*roles)` decorator applied per-route
  (`employee`/`admin`/own-record-only for customers).
- **Secure cookies / headers / input validation**: `SESSION_COOKIE_HTTPONLY`,
  `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE`; `X-Content-Type-Options`,
  `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`,
  `Strict-Transport-Security` headers on every response; username regex +
  password-length + JSON-type validation on every endpoint that takes input.

## A note on "SYN attack" under vuln #4

A SYN flood is a transport-layer attack against the TCP handshake itself — it
has nothing to do with the Flask application code, so there's no app-level
"fix" to write for it (that's what reverse proxies / load balancers / OS-level
SYN cookies are for). What *is* in scope and fixed here is the
application-layer version of the same idea: a client sending a payload
designed to make your own code do unbounded or unsafe work. That's the
`quantity` loop and the unvalidated JSON — both fixed above.

## Not yet done (by your instruction)

- Written root-cause/impact explanation (item 05)
- Formal demonstration write-up (item 06 — the `exploits.py` script above is
  the technical proof; a narrated report is still pending)
- Security assumptions / limitations document (item 07)
