# Builds the VULNERABLE app as its own container.
# Build context is the project root (see docker-compose.yml), so this image
# contains the whole repo under /app -- that's needed because the vulnerable
# app re-uses the shared seed_db.py at the project root.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r vulnerable/requirements.txt

EXPOSE 5000

# Seed a fresh weak-credentials DB, then start the app.
CMD ["sh", "-c", "python seed_db.py vulnerable && python vulnerable/app.py"]
