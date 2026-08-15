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
    """Continuously generates live threat intel for demonstration purposes across all 10 tracked banks."""
    all_banks = [
        ("Maybank", ["maybznk2u.com.my", "maybank2u-secure-login.top", "mae-verify-otp.net", "maybank-ccid-update.com"]),
        ("CIMB Bank", ["secure-login-cimb.com", "cimb-clicks-secure.com", "cimb-security-gateway.net", "cimbclicks-auth.top"]),
        ("Public Bank", ["pbebank-update-info.net", "pbb-online-auth.top", "publicbank-ebank.com", "pbe-secure-portal.org"]),
        ("RHB Bank", ["rhb-online-verify.net", "rhbgroup-secure-auth.top", "rhbnow-login-gateway.com"]),
        ("Hong Leong Bank", ["hlb-connect-secure.com", "hongleong-auth-verify.top", "hlbb-portal-update.net"]),
        ("AmBank", ["ambank-amonline-secure.top", "amonline-verify-auth.com", "ambankgroup-portal.net"]),
        ("Bank Islam", ["bankislam-internet-auth.com", "bimb-portal-verify.top", "bankislam-secure-login.net"]),
        ("Touch 'n Go eWallet", ["tng-digital-claim-bonus.net", "touchngo-ewallet-auth.top", "tng-wallet-verify.com"]),
        ("GrabPay Malaysia", ["grabpay-reward-verification.top", "grab-malaysia-bonus.net", "grabpay-auth-login.com"]),
        ("ShopeePay", ["shopeepay-voucher-claim.net", "shopee-free-gifts.net", "shopeepay-verify-portal.top"]),
    ]
    platforms = ["Shopee", "Facebook Marketplace", "WhatsApp", "Telegram", "Mudah.my", "Carousell", "Lazada", "TikTok Shop"]

    logger.info("Live Threat Simulator started with full 10-Bank coverage.")
    while True:
        # Dynamic interval based on speed multiplier
        speed = max(0.2, min(getattr(state, "simulator_speed", 1.0), 10.0))
        base_interval = random.uniform(3.0, 7.0)
        await asyncio.sleep(base_interval / speed)
        
        if not getattr(state, "simulator_running", False):
            continue
            
        try:
            # 1. Always inject a telemetry log (malicious URL detection)
            bank_name, bank_domains = random.choice(all_banks)
            chosen_domain = random.choice(bank_domains)
            malicious_url = f"http://{chosen_domain}/auth/login?session={random.randint(10000, 99999)}"
            score = round(random.uniform(0.78, 0.99), 4)
            await state.db.execute(
                "INSERT INTO threat_telemetry (malicious_url, bert_score) VALUES (?, ?)",
                (malicious_url, score)
            )

            # 2. 50% chance to report a new mule account or increment an existing one
            inserted_mule = None
            if random.random() < 0.5:
                account_num = str(random.randint(1000000000, 99999999999999))
                plat = random.choice(platforms)
                reports = random.randint(1, 4)
                inserted_mule = {"account_number": account_num, "bank_name": bank_name}
                
                await state.db.execute(
                    """
                    INSERT INTO mule_registry (account_number, bank_name, platform_flagged, report_count) 
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(account_number) DO UPDATE SET report_count = report_count + 1
                    """,
                    (account_num, bank_name, plat, reports)
                )

            await state.db.commit()
            logger.debug("Live Threat Simulator: Injected new threat intel for %s.", bank_name)

            # 3. Autonomous Playbook Trigger on Critical Threats
            if score >= 0.90 and inserted_mule:
                from services.playbook_engine import execute_playbook_action
                threat_payload = {
                    "malicious_url": malicious_url,
                    "url": malicious_url,
                    "bank": bank_name,
                    "score": score,
                    "mules": [inserted_mule]
                }
                asyncio.create_task(execute_playbook_action("PLAYBOOK-CRITICAL-INTERCEPT", threat_payload, state.db))

        except Exception as e:
            logger.error("Live Threat Simulator Error: %s", e)
            await asyncio.sleep(2)


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

OPENAPI_TAGS: Final[list[dict[str, Any]]] = [
    {
        "name": "Live Analysis & Ingestion",
        "description": "Real-time DOM payload ingestion, BERT semantic NLP classification, heuristic parsing, and parallel mule verification.",
    },
    {
        "name": "SOC Defense & Tactical Modules",
        "description": "SOC War Room, Visual Sandbox, NSRC 997 & National Fraud Portal gateway, and Quishing QR code inspection.",
    },
    {
        "name": "Threat Intelligence & Syndication",
        "description": "OASIS STIX 2.1 / TAXII 2.1 server, Global Threat Feeds (URLhaus, PhishTank, OpenPhish), and Batch Forensic Inspector.",
    },
    {
        "name": "Autonomous Defense & Radar",
        "description": "Autonomous Incident Response Playbooks, Pre-emptive Typosquatting Radar, and DNS Sinkhole / SIEM rule exports.",
    },
    {
        "name": "Dashboard & Telemetry",
        "description": "Live SSE event streaming, 10-Bank telemetry distributions, Geo-node attack vectors, and executive CISO briefing reports.",
    },
    {
        "name": "Visual Identity Analysis",
        "description": "YOLO-based bank logo detection and visual screenshot domain mismatch validation.",
    },
    {
        "name": "System & Operations",
        "description": "Database maintenance, SQLite live hot backups, hardware inference benchmarks, webhook alerts, and liveness probes.",
    },
]

app: Final[FastAPI] = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_tags=OPENAPI_TAGS,
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
<html lang="en" class="dark-mode">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard-AI — API Documentation & OpenAPI Specs</title>
    <link rel="icon" type="image/png" href="/dashboard/favicon.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="stylesheet" href="/dashboard/styles.css?v=9">
    <link rel="stylesheet" href="/dashboard/swagger_dark.css?v=9">

    <style>
        html, body {
            background-color: #060911 !important;
            background-image:
                radial-gradient(circle 900px at 50% -120px, rgba(99, 102, 241, 0.32), transparent 70%),
                radial-gradient(circle 700px at 90% 70%, rgba(6, 182, 212, 0.22), transparent 60%),
                radial-gradient(circle 800px at 10% 90%, rgba(139, 92, 246, 0.22), transparent 65%),
                linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px) !important;
            background-size: 100% 100%, 100% 100%, 100% 100%, 36px 36px, 36px 36px !important;
            background-attachment: fixed !important;
            min-height: 100vh !important;
        }
        #swagger-ui, .swagger-ui, .swagger-ui .wrapper { background: transparent !important; background-color: transparent !important; }
        .swagger-ui .wrapper { padding: 0 1.5rem !important; max-width: 1440px !important; margin: 0 auto !important; }
        .swagger-ui .opblock-tag-section { margin-bottom: 0.75rem !important; }
        .swagger-ui .opblock-tag-section:empty { display: none !important; }
        .swagger-ui .scheme-container { background: transparent !important; box-shadow: none !important; border: none !important; }
        .swagger-ui section.models { background: #0f172a !important; border: 1px solid rgba(99, 102, 241, 0.4) !important; margin: 1.5rem 0 2rem 0 !important; }
        .swagger-ui section.models .model-container { background: #111827 !important; border: 1px solid rgba(255, 255, 255, 0.12) !important; }
        .swagger-ui .json-schema-2020-12, .swagger-ui .json-schema-2020-12 button, .swagger-ui .json-schema-2020-12-accordion, .swagger-ui .model-box, .swagger-ui .model-box button, .swagger-ui .model-box-control, .swagger-ui .models-control { background: transparent !important; background-color: transparent !important; border: none !important; box-shadow: none !important; }
        .swagger-ui .json-schema-2020-12__title, .swagger-ui .model-title, .swagger-ui span.model-title__text { color: #38bdf8 !important; font-family: 'JetBrains Mono', monospace !important; font-weight: 800 !important; }
        .swagger-ui .json-schema-2020-12__attribute { color: #a78bfa !important; font-family: 'JetBrains Mono', monospace !important; }
        .swagger-ui .model { color: #f8fafc !important; }
        .swagger-ui .opblock-description-wrapper, .swagger-ui .opblock-description-wrapper p, .swagger-ui .opblock-title_normal p, .swagger-ui .opblock-summary-description, .swagger-ui .markdown p, .swagger-ui .renderedMarkdown p, .swagger-ui .parameters-col_description p, .swagger-ui .response-col_description { color: #f1f5f9 !important; font-size: 0.95rem !important; line-height: 1.6 !important; }
    </style>
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
            <span class="status-text">OAS 3.1 &bull; v3.0.0</span>
        </div>
    </header>

    <div id="swagger-ui"></div>

    <footer class="footer" style="margin-top: 3rem;">
        <p>&copy; 2026 PhishGuard-AI &mdash; Semantic Threat Intelligence Engine v3.0<br/>
        <small>Faculty of Computing & Information Technology, TAR UMT</small></p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                docExpansion: 'list',
                filter: true,
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                showExtensions: true,
                showCommonExtensions: true,
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
    tags=["System & Operations"],
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
