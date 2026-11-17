"""
PhishGuard-AI — Application Entry Point.
=========================================

Creates the FastAPI application:

* **Lifespan** — opens the SQLite database, loads the BERT URL model and
  the YOLOv8n logo detector once, and shares them through ``app.state``.
* **Security middleware** — CORS (explicit origins only), hardening headers,
  per-IP rate limiting and request logging.
* **Routes** — the analysis API (``/api/v1``), the dashboard API
  (``/api/v1/dashboard``), the dashboard itself (``/dashboard/``), the
  interactive API documentation (``/docs``) and a health probe (``/health``).

Run locally:   uvicorn main:app --host 127.0.0.1 --port 8000
In Docker:     see Dockerfile (Render sets PORT; default 10000)

Architecture Layer : Composition Root
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Final

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler  # type: ignore[import-untyped]
from slowapi.errors import RateLimitExceeded  # type: ignore[import-untyped]
from starlette.middleware.base import BaseHTTPMiddleware

from api.dashboard_endpoints import router as dashboard_router
from api.endpoints import router as analysis_router
from core.config import (
    APP_DESCRIPTION,
    APP_TITLE,
    APP_VERSION,
    CORS_ALLOWED_ORIGINS,
    CORS_ORIGIN_REGEX,
    ENABLE_SEMANTIC_ENGINE,
    ENABLE_VISUAL_ENGINE,
    USING_DEFAULT_API_KEY,
)
from core.rate_limit import limiter
from database.demo_seed import seed_demo_data
from database.init_db import initialize_database
from services.cache_service import SemanticResultCache
from services.mule_scanner import MuleScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
    force=True,
)
logger: Final[logging.Logger] = logging.getLogger("phishguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Load shared resources once at start-up and release them at shutdown."""
    logger.info("PhishGuard-AI %s — starting up", APP_VERSION)
    if USING_DEFAULT_API_KEY:
        logger.warning("SECURITY: the documented development key is in use. Set PHISHGUARD_API_KEY and "
                       "PHISHGUARD_ADMIN_KEY for any deployment beyond a demonstration.")

    app.state.db = await initialize_database()
    await seed_demo_data(app.state.db)
    app.state.mule_scanner = MuleScanner()
    app.state.cache = SemanticResultCache(ttl_seconds=600)

    app.state.semantic_engine = None
    if ENABLE_SEMANTIC_ENGINE:
        from services.nlp_engine import SemanticEngine

        engine = SemanticEngine()
        engine.warm_up()
        app.state.semantic_engine = engine
    else:
        logger.warning("BERT URL model disabled (PHISHGUARD_ENABLE_SEMANTIC=false).")

    app.state.visual_detector = None
    if ENABLE_VISUAL_ENGINE:
        from services.visual_detector import VisualLogoDetector

        detector = VisualLogoDetector()
        # Load YOLO in the background so start-up is not delayed.
        asyncio.get_running_loop().run_in_executor(None, detector._load_model)
        app.state.visual_detector = detector

    logger.info("PhishGuard-AI — Ready to Serve")
    yield

    if app.state.semantic_engine is not None:
        app.state.semantic_engine.shutdown()
    await app.state.db.close()
    logger.info("PhishGuard-AI — stopped")


OPENAPI_TAGS: Final[list[dict[str, str]]] = [
    {"name": "Analysis API", "description": "Used by the browser extension. Requires the API key as a Bearer token."},
    {"name": "SOC Dashboard", "description": "Backs the four dashboard tabs. Requires the admin key or a dashboard session."},
    {"name": "System", "description": "Health probe."},
]

app: Final[FastAPI] = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_tags=OPENAPI_TAGS,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers on every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'self'")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Method, path, status and latency of every request."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        logger.info("%s %s -> %d (%.1f ms)", request.method, request.url.path, response.status_code,
                    (time.perf_counter() - start) * 1000)
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)

app.include_router(analysis_router)
app.include_router(dashboard_router)
app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")


_DOCS_HTML: Final[str] = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard-AI — API Documentation</title>
<link rel="icon" href="/dashboard/favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css">
<link rel="stylesheet" href="/dashboard/styles.css">
<link rel="stylesheet" href="/dashboard/docs.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="/dashboard/"><img src="/dashboard/favicon.png" alt=""><span>PhishGuard-AI<small>API Documentation</small></span></a>
  <nav class="tabs"><a class="tab" href="/dashboard/">Dashboard</a><a class="tab" href="/docs" aria-selected="true">API Docs</a></nav>
</header>
<main id="swagger-ui" class="docs"></main>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
<script>
window.ui = SwaggerUIBundle({url: "/openapi.json", dom_id: "#swagger-ui", docExpansion: "list",
  defaultModelsExpandDepth: 0, persistAuthorization: true});
</script>
</body>
</html>"""


@app.get("/docs", include_in_schema=False)
async def api_docs() -> HTMLResponse:
    """Interactive OpenAPI documentation."""
    return HTMLResponse(_DOCS_HTML)


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse("/dashboard/")


@app.get("/health", tags=["System"], summary="Liveness probe")
async def health(request: Request) -> dict[str, object]:
    state = request.app.state
    detector = getattr(state, "visual_detector", None)
    return {
        "status": "healthy",
        "service": APP_TITLE,
        "version": APP_VERSION,
        "models": {
            "bert_url_classifier": getattr(state, "semantic_engine", None) is not None,
            "yolov8n_logo_detector": bool(detector is not None and getattr(detector, "_model", None) is not None),
        },
    }
