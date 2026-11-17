# ==============================================================================
# PhishGuard-AI v4.1 — container image for Render (free web service, 512 MB RAM)
# Also runs on Railway, Fly.io or any Docker host. The platform terminates HTTPS in front of it.
# ==============================================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000 \
    PHISHGUARD_DB_PATH=/tmp/phishguard.db \
    YOLO_CONFIG_DIR=/tmp/ultralytics \
    MALLOC_ARENA_MAX=2

# libgl1 / libglib2.0-0: OpenCV runtime; libzbar0: barcode support; curl: health check
RUN apt-get update && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 libzbar0 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# CPU-only PyTorch (requirements.txt also points pip at the CPU wheel index).
RUN pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY api ./api
COPY core ./core
COPY database ./database
COPY schemas ./schemas
COPY services ./services
COPY dashboard ./dashboard
COPY scripts ./scripts
COPY phishguard_custom_model ./phishguard_custom_model
COPY visual_identity/models ./visual_identity/models
COPY visual_identity/classes.txt ./visual_identity/classes.txt

# Render clones without Git LFS: swap any pointer file (< 10 KB) for the real weights from GitHub,
# then build the small int8 BERT that the server loads (see scripts/quantize_bert.py).
RUN python scripts/fetch_lfs_weights.py && python scripts/quantize_bert.py phishguard_custom_model

RUN useradd --create-home --uid 1000 app && chown -R app:app /app
USER app
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD curl -fs "http://127.0.0.1:${PORT}/health" || exit 1

# --proxy-headers: trust X-Forwarded-Proto from the platform's HTTPS proxy (Secure cookies, HSTS).
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
