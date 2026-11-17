# ==============================================================================
# PhishGuard-AI v4.0 — container image
# Runs on Hugging Face Spaces (Docker SDK, port 7860), Render, Railway or any
# Docker host. The platform terminates HTTPS in front of the container.
# ==============================================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=7860 \
    PHISHGUARD_DB_PATH=/tmp/phishguard.db \
    YOLO_CONFIG_DIR=/tmp/ultralytics \
    HF_HOME=/tmp/hf

# libgl1 / libglib2.0-0: OpenCV runtime libraries (QR decoding, YOLO)
RUN apt-get update && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 curl \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user (uid 1000, as Hugging Face Spaces expects).
RUN useradd --create-home --uid 1000 app
WORKDIR /app

# CPU-only PyTorch keeps the image small; then the remaining runtime packages.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code, dashboard and model weights (pulled from Git LFS).
COPY --chown=app:app main.py ./
COPY --chown=app:app api ./api
COPY --chown=app:app core ./core
COPY --chown=app:app database ./database
COPY --chown=app:app schemas ./schemas
COPY --chown=app:app services ./services
COPY --chown=app:app dashboard ./dashboard
COPY --chown=app:app phishguard_custom_model ./phishguard_custom_model
COPY --chown=app:app visual_identity/models ./visual_identity/models
COPY --chown=app:app visual_identity/classes.txt ./visual_identity/classes.txt

USER app
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fs "http://127.0.0.1:${PORT}/health" || exit 1

# --proxy-headers: trust X-Forwarded-Proto from the platform's HTTPS proxy so
# cookies are marked Secure and HSTS is sent.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
