"""
PhishGuard-AI — Application Entry Point.
==========================================

Bootstraps the FastAPI application with:

    1. **Lifespan Context Manager** — cold-starts the BERT model
       (Singleton), the Mule Scanner (pre-compiled regex), and the
       aiosqlite database connection.  All three are stored in
       ``app.state`` and shared across requests via dependency injection.
       On shutdown, resources are explicitly released.

    2. **Rate Limiting** — enforced globally via ``SlowAPI`` using the
       client's IP address as the rate-limit key.

    3. **Router Inclusion** — mounts the ``/api/v1`` analysis router.

    4. **Structured Logging** — configures a uniform log format across
       all PhishGuard modules.

Run with:
    ``uvicorn main:app --host 0.0.0.0 --port 8000 --reload``

Architecture Layer : Composition Root / Application Shell
Thesis Reference   : §6.2 — Application Bootstrap & Lifespan Management
"""

from __future__ import annotations

import asyncio
import logging
import random
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Final

import torch
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore[import-untyped]
from slowapi.errors import RateLimitExceeded  # type: ignore[import-untyped]
from slowapi.util import get_remote_address  # type: ignore[import-untyped]
from starlette.middleware.base import BaseHTTPMiddleware

from api.endpoints import router as analysis_router
from api.dashboard_endpoints import router as dashboard_router
from api.visual import router as visual_router
from core.config import (
    APP_DESCRIPTION,
    APP_TITLE,
    APP_VERSION,
    ENABLE_SEMANTIC_ENGINE,
    RATE_LIMIT,
)
from database.init_db import initialize_database
from services.cache_service import SemanticResultCache
from services.mule_scanner import MuleScanner
from services.nlp_engine import SemanticEngine

# ==============================================================================
# Logging Configuration
# ==============================================================================
_LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
)

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
    force=True,
)

logger: Final[logging.Logger] = logging.getLogger("phishguard.main")

# ==============================================================================
# Rate Limiter (SlowAPI)
# ==============================================================================
limiter: Final[Limiter] = Limiter(
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://",
)


# ==============================================================================
# Live Threat Simulator
# ==============================================================================

async def simulate_live_threats(state) -> None:
    """Continuously generates live threat intel for demonstration purposes."""
    banks = ["Maybank", "CIMB Bank", "Public Bank", "RHB Bank", "Hong Leong Bank", "AmBank", "Bank Islam"]
    platforms = ["Shopee", "Facebook Marketplace", "WhatsApp", "Telegram", "Mudah.my", "Carousell", "Lazada"]
    domains = ["secure-login-cimb.com", "maybznk2u.com.my", "shopee-free-gifts.net", "lhdn-refunds.org", "pnm-gov.my-login.com", "cimb-clicks-secure.com", "pbb-update-info.net"]

    logger.info("Live Threat Simulator started.")
    while True:
        await asyncio.sleep(random.randint(5, 12))
        
        if not getattr(state, "simulator_running", False):
            continue
            
        try:
            # 1. Always inject a telemetry log (malicious URL detection)
            malicious_url = f"http://{random.choice(domains)}/auth/login?token={random.randint(1000, 9999)}"
            score = round(random.uniform(0.75, 0.99), 3)
            await state.db.execute(
                "INSERT INTO threat_telemetry (malicious_url, bert_score) VALUES (?, ?)",
                (malicious_url, score)
            )

            # 2. 40% chance to report a new mule account or increment an existing one
            if random.random() < 0.4:
                account_num = str(random.randint(1000000000, 99999999999999))
                bank = random.choice(banks)
                plat = random.choice(platforms)
                reports = random.randint(1, 3)
                
                # Check if it exists to just increment report_count, though randomly generated it's unlikely
                # but let's just insert
                await state.db.execute(
                    """
                    INSERT INTO mule_registry (account_number, bank_name, platform_flagged, report_count) 
                    VALUES (?, ?, ?, ?)
                    """,
                    (account_num, bank, plat, reports)
                )

            await state.db.commit()
            logger.debug("Live Threat Simulator: Injected new threat intel.")
        except Exception as e:
            logger.error("Live Threat Simulator Error: %s", e)
            await asyncio.sleep(5)


# ==============================================================================
# Lifespan Context Manager (PEP 3143-style)
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application-wide singletons across the server lifecycle.

    **Startup Phase** (before ``yield``):
        1. Initialise the aiosqlite database (DDL + seed data).
        2. Instantiate the ``SemanticEngine`` (loads BERT into memory).
        3. Run a warm-up inference pass to prime caches.
        4. Instantiate the ``MuleScanner`` (compiles the regex).
        5. Store all singletons in ``app.state``.

    **Shutdown Phase** (after ``yield``):
        1. Shut down the ``SemanticEngine`` (frees GPU VRAM).
        2. Close the aiosqlite connection.
        3. Log a clean-shutdown confirmation.

    Yields
    ------
    None
        Control is returned to the ASGI server for the duration of the
        application's runtime.
    """
    # ────────────────────── STARTUP ──────────────────────
    logger.info("=" * 60)
    logger.info("  PhishGuard-AI Backend — Starting Up")
    logger.info("=" * 60)

    # 1. Database
    logger.info("[1/5] Initialising database …")
    app.state.db = await initialize_database()

    # 2. BERT Semantic Engine (Singleton)
    if ENABLE_SEMANTIC_ENGINE:
        logger.info("[2/5] Loading BERT Semantic Engine …")
        engine = SemanticEngine()
        app.state.semantic_engine = engine

        # 3. Warm-up pass
        logger.info("[3/5] Running BERT warm-up inference …")
        engine.warm_up()
    else:
        logger.warning(
            "[2/5] BERT Semantic Engine disabled by PHISHGUARD_ENABLE_SEMANTIC=false."
        )
        app.state.semantic_engine = None

    # 4. Mule Scanner
    logger.info("[4/5] Initialising Mule Scanner & Semantic Cache …")
    app.state.mule_scanner = MuleScanner()
    app.state.cache = SemanticResultCache(ttl_seconds=600)

    # 5. Start Live Threat Simulator background task
    logger.info("[5/5] Starting Live Threat Simulator …")
    app.state.simulator_running = False
    simulator_task = asyncio.create_task(simulate_live_threats(app.state))

    logger.info("=" * 60)
    logger.info("  PhishGuard-AI Backend — Ready to Serve")
    logger.info("=" * 60)

    yield  # ← Application is running and accepting requests.

    # ────────────────────── SHUTDOWN ──────────────────────
    logger.info("=" * 60)
    logger.info("  PhishGuard-AI Backend — Shutting Down")
    logger.info("=" * 60)

    # Release ML resources
    if app.state.semantic_engine is not None:
        app.state.semantic_engine.shutdown()

    # Cancel background tasks
    if not simulator_task.done():
        simulator_task.cancel()
        try:
            await simulator_task
        except asyncio.CancelledError:
            pass

    # Close database connection
    await app.state.db.close()

    logger.info("All resources released.  Goodbye.")


# ==============================================================================
# FastAPI Application Instance
# ==============================================================================

app: Final[FastAPI] = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    contact={
        "name": "PhishGuard-AI Security Team",
        "email": "security@phishguard.ai",
    },
    license_info={
        "name": "Proprietary",
        "identifier": "LicenseRef-PhishGuard-Proprietary",
    },
)


# ── Attach the rate limiter to the app ──
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Global Exception Handler: PyTorch / CUDA Inference Errors (§4.5) ──
@app.exception_handler(RuntimeError)
async def pytorch_runtime_error_handler(
    request: Request, exc: RuntimeError
) -> JSONResponse:
    """Catch PyTorch/CUDA RuntimeErrors (e.g., OOM) and return a
    structured 503 response instead of a raw 500."""
    error_msg = str(exc).lower()
    if "cuda" in error_msg or "out of memory" in error_msg:
        logger.critical("CUDA Out-of-Memory during inference: %s", exc)
        # Attempt to free cached GPU memory
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        return JSONResponse(
            status_code=503,
            content={
                "error": "MODEL_INFERENCE_FAILURE",
                "message": (
                    "The AI inference engine encountered a memory allocation "
                    "failure.  Please retry the request or contact your "
                    "PhishGuard administrator."
                ),
            },
        )
    # Re-raise non-CUDA RuntimeErrors to the default handler
    raise exc


# ── CORS Middleware (restrict in production) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict to extension origin in prod.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Request Logging Middleware ──
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs the method, path, status code, and latency of every request."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter_ns()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter_ns() - start) / 1_000_000, 2)
        logger.info(
            "%s %s -> %d (%.2f ms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response


app.add_middleware(RequestLoggingMiddleware)


# ── Mount the API router ──
app.include_router(analysis_router)
app.include_router(visual_router)
app.include_router(dashboard_router)

app.mount(
    "/dashboard",
    StaticFiles(directory="dashboard", html=True),
    name="dashboard",
)


# ==============================================================================
# Custom Cyber Dark Swagger UI & Documentation (§6.4)
# ==============================================================================

_SWAGGER_CYBER_DARK_HTML: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard-AI — API Documentation & OpenAPI Specs</title>
    <link rel="icon" type="image/png" href="/dashboard/favicon.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="stylesheet" href="/dashboard/styles.css">
    <link rel="stylesheet" href="/dashboard/swagger_dark.css">
</head>
<body>
    <!-- ═══════════════════ HEADER ═══════════════════ -->
    <header class="header">
        <div class="header__brand">
            <div class="header__logo">
                <img src="/dashboard/favicon.png" alt="PhishGuard Cyber Shield" class="header__logo-img" />
            </div>
            <div>
                <h1 class="header__title">PhishGuard-AI</h1>
                <p class="header__subtitle">API & Threat Intel Specs</p>
            </div>
        </div>

        <nav class="header__nav" aria-label="Main Navigation">
            <a href="/dashboard/index.html" class="nav-tab">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>
                Live Dashboard
            </a>
            <a href="/dashboard/sandbox.html" class="nav-tab">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                Threat Sandbox
            </a>
            <a href="/dashboard/test_scam.html" class="nav-tab">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Test Scam Target
            </a>
            <a href="/docs" class="nav-tab active">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                API Docs
            </a>
        </nav>

        <div class="header__status">
            <span class="status-dot live"></span>
            <span class="status-text">FastAPI 2.0 Docs</span>
        </div>
    </header>

    <div id="swagger-ui"></div>

    <footer class="footer" style="margin-top: 3rem;">
        <p>&copy; 2026 PhishGuard-AI &mdash; Threat Intelligence Platform<br/>
        <small>Faculty of Computing & Information Technology, TAR UMT</small></p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout"
            });
        };
    </script>
</body>
</html>
"""


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html() -> HTMLResponse:
    """Return the cyber-dark themed Swagger UI documentation."""
    return HTMLResponse(content=_SWAGGER_CYBER_DARK_HTML)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html() -> HTMLResponse:
    """Return the Redoc documentation."""
    from fastapi.openapi.docs import get_redoc_html
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="PhishGuard-AI — ReDoc API Documentation",
        redoc_favicon_url="/dashboard/favicon.png",
    )



# ==============================================================================
# Health Check (unprotected)
# ==============================================================================

@app.get(
    "/health",
    tags=["Operations"],
    summary="Liveness probe",
    response_description="Service health status.",
)
async def health_check() -> dict[str, str]:
    """Lightweight liveness probe for orchestrators (K8s, ECS, etc.)."""
    return {"status": "healthy", "service": APP_TITLE, "version": APP_VERSION}


# ==============================================================================
# Uvicorn Direct Execution
# ==============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
