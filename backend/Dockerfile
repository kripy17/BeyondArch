FROM python:3.12-slim

WORKDIR /app

# System deps: nmap + other CLI tools used by the app
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    dnsutils \
    netcat-openbsd \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
# In-container bind must stay 0.0.0.0 (the namespace boundary is the
# published port); override via BEYONDLABS_BACKEND_HOST/PORT if needed.
CMD ["sh", "-c", "uvicorn app.main:app --host ${BEYONDLABS_BACKEND_HOST:-0.0.0.0} --port ${BEYONDLABS_BACKEND_PORT:-8000}"]
