# AIAuth Enterprise — self-hosted Docker image (Phase C.1)
# Single-stage build on python:3.11-slim. Image runs as non-root,
# takes config.yaml via a bind mount, persists keys + databases in
# a named volume.

FROM python:3.11-slim

# Runtime deps: sqlite3 CLI (for ops), curl (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 curl tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY server.py ./
COPY verify.html ./
COPY index.html ./
COPY logo.png ./
COPY docs/ ./docs/
COPY templates/ ./templates/
COPY self-hosted/ ./self-hosted/

# Non-root user for runtime
RUN useradd --uid 1000 --home /app --shell /bin/sh aiauth && \
    mkdir -p /var/lib/aiauth && \
    chown -R aiauth:aiauth /app /var/lib/aiauth
USER aiauth

# Persistent state + config
VOLUME ["/var/lib/aiauth"]

# Default: run bootstrap.py (idempotent) then uvicorn.
# Customers override via docker-compose.yml if they need a different flow.
ENV AIAUTH_CONFIG=/etc/aiauth/config.yaml
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8100/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", \
    "python self-hosted/scripts/bootstrap.py --config ${AIAUTH_CONFIG} && \
     exec python -m uvicorn server:app --host 0.0.0.0 --port 8100 --workers 2"]
