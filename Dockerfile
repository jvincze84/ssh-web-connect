# syntax=docker/dockerfile:1

# ---- Stage 1: fetch pinned front-end assets (xterm.js) -----------------------
FROM node:22-alpine AS assets
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && mkdir -p /vendor \
 && cp node_modules/@xterm/xterm/lib/xterm.js \
       node_modules/@xterm/xterm/css/xterm.css \
       node_modules/@xterm/addon-fit/lib/addon-fit.js \
       node_modules/@xterm/addon-web-links/lib/addon-web-links.js \
       /vendor/

# ---- Stage 2: Python dependencies --------------------------------------------
FROM python:3.13-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r /tmp/requirements.txt

# ---- Stage 3: runtime --------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    SSH_MANAGER_CONFIG=/app/config/config.yaml

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && mkdir -p /app/config /var/log/ssh-manager \
 && chown app:app /var/log/ssh-manager

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY app/ /app/app/
COPY static/ /app/static/
COPY --from=assets /vendor/ /app/static/assets/vendor/

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"]

# Single worker on purpose: session limits are tracked in process memory.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", \
     "--no-server-header", \
     "--no-proxy-headers", \
     "--ws-max-size", "1048576", \
     "--ws-ping-interval", "20", \
     "--ws-ping-timeout", "20", \
     "--timeout-graceful-shutdown", "10"]
