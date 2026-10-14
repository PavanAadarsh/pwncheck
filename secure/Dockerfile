# Builds the SECURE app as its own container. Build context is the project
# root (see docker-compose.yml). secure/app.py self-seeds its own database
# (hashed passwords + TOTP secrets) the first time it starts, so no extra
# seeding step is needed here.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r secure/requirements.txt

EXPOSE 5001

CMD ["python", "secure/app.py"]
