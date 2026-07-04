"""
PhishGuard-AI — API Endpoint Router.
======================================

Defines the ``/api/v1/analyse/semantics`` endpoint — the primary
ingestion point for the browser extension.  The handler orchestrates
the full analysis pipeline:

    DOM Payload → ETL Sanitization → [BERT Inference ∥ Mule Scan]
                                      (asyncio.gather)
               → Orchestration Verdict → JSON Response

Security: Protected by the ``verify_api_key`` dependency (Bearer token).
Concurrency: BERT inference and mule-account scanning execute **in
parallel** via ``asyncio.gather()`` to minimise wall-clock latency.

Architecture Layer : Presentation / API Gateway
Thesis Reference   : §6.1 — Request Orchestration & Parallel Execution
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Final
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from slowapi import Limiter  # type: ignore[import-untyped]
from slowapi.util import get_remote_address  # type: ignore[import-untyped]

from core.config import (
    GLOBAL_SAFE_DOMAINS,
    MALICIOUS_THRESHOLD,
    RATE_LIMIT,
    TRUSTED_DOMAIN_CONFIDENCE,
    TRUSTED_DOMAINS,
    VERDICT_BLOCK,
    VERDICT_SAFE,
)
from core.security import verify_api_key
from schemas.payload import WebPayload
from schemas.response import (
    AnalysisResponse,
    DataBlock,
    MetaBlock,
    MuleScanResult,
    SemanticResult,
)
from services.sanitizer import sanitize_dom
from database.repository import log_threat_telemetry

logger: Final[logging.Logger] = logging.getLogger("phishguard.endpoints")

# ==============================================================================
# Router Configuration
# ==============================================================================
router: Final[APIRouter] = APIRouter(
    prefix="/api/v1",
    tags=["Threat Analysis"],
    dependencies=[Depends(verify_api_key)],  # All routes require auth.
)

# ── Rate limiter instance (mirrors the one in main.py) ──
limiter: Final[Limiter] = Limiter(
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://",
)

# Maximum characters of sanitized text included in the response preview.
_PREVIEW_LENGTH: Final[int] = 200


def _is_trusted_domain(url: str) -> bool:
    """Check whether the given URL belongs to a trusted (whitelisted) domain.

    Checks both the Malaysian bank ``TRUSTED_DOMAINS`` and the
    ``GLOBAL_SAFE_DOMAINS`` set (Google, YouTube, WhatsApp, etc.).
    Supports exact matches and subdomain matches.

    Parameters
    ----------
    url : str
        Fully-qualified URL to check.

    Returns
    -------
    bool
        ``True`` if the domain (or a parent domain) is whitelisted.
    """
    try:
        hostname: str = urlparse(str(url)).hostname or ""
        hostname = hostname.lower().strip(".")
    except Exception:
        return False

    # Combined whitelist: bank domains + global safe platforms
    all_trusted = TRUSTED_DOMAINS | GLOBAL_SAFE_DOMAINS

    # Exact match
    if hostname in all_trusted:
        return True

    # Subdomain match: e.g., "www.google.com" → "google.com"
    for trusted in all_trusted:
        if hostname.endswith("." + trusted):
            return True

    return False


# ==============================================================================
# POST /api/v1/analyse/semantics
# ==============================================================================

@router.post(
    "/analyse/semantics",
    response_model=AnalysisResponse,
    summary="Analyse a web page for phishing threats",
    description=(
        "Accepts a raw DOM payload, sanitises the HTML, runs BERT semantic "
        "analysis and mule-account scanning **in parallel**, and returns a "
        "unified threat-assessment response with an orchestration directive."
    ),
    response_description="Unified analysis envelope with orchestration verdict.",
    status_code=200,
)
@limiter.limit(RATE_LIMIT)
async def analyse_semantics(
    payload: WebPayload,
    request: Request,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(verify_api_key),
) -> AnalysisResponse:
    """Primary analysis endpoint invoked by the browser extension.

    Pipeline Steps
    --------------
    1. Generate a UUID v4 transaction identifier for traceability.
    2. ETL-sanitise the raw DOM content (strip tags, scripts, CSS).
    3. Start a high-resolution timer.
    4. Execute BERT inference and mule-account scanning **concurrently**
       via ``asyncio.gather()``.
    5. Determine the orchestration verdict based on combined results.
    6. If malicious, enqueue an async background task to persist
       telemetry (non-blocking — does not inflate response latency).
    7. Assemble and return the ``AnalysisResponse`` envelope.

    Parameters
    ----------
    payload : WebPayload
        Validated inbound request body.
    request : Request
        FastAPI request object — used to access ``app.state`` singletons.
    background_tasks : BackgroundTasks
        FastAPI background-task scheduler for deferred telemetry writes.
    _api_key : str
        The validated bearer token (unused in logic; satisfies the
        dependency chain for documentation purposes).

    Returns
    -------
    AnalysisResponse
        Nested JSON envelope with ``meta``, ``data``, and
        ``orchestration`` sections.
    """
    # asyncio imported at module level

    # ── 1. Transaction ID ──
    transaction_id: str = str(uuid.uuid4())
    logger.info(
        "[%s] Received analysis request for URL: %s",
        transaction_id,
        payload.url,
    )

    # ── 2. ETL Sanitisation ──
    sanitized_text: str = sanitize_dom(payload.dom_content)
    if not sanitized_text:
        logger.warning(
            "[%s] Sanitised text is empty — DOM may be purely structural.",
            transaction_id,
        )
        # Provide a fallback to prevent model errors on empty input.
        sanitized_text = "empty page content"

    logger.debug(
        "[%s] Sanitised text (%d chars): %s…",
        transaction_id,
        len(sanitized_text),
        sanitized_text[:100],
    )

    # ── 3. Retrieve singletons from app.state ──
    semantic_engine = request.app.state.semantic_engine
    mule_scanner = request.app.state.mule_scanner
    db = request.app.state.db

    # ── 4. Trusted Domain Whitelist Check ──
    #
    #   If the URL belongs to a known-legitimate financial institution,
    #   bypass BERT inference entirely to prevent false positives.  The
    #   DOM text of real bank sites contains keywords ("login", "transfer",
    #   "account") that the phishing-trained model misclassifies.
    #
    url_str: str = str(payload.url)
    is_trusted: bool = _is_trusted_domain(url_str)

    start_ns: int = time.perf_counter_ns()

    bert_result: dict[str, Any]
    mule_result: dict[str, Any]

    if is_trusted:
        # ── Whitelisted domain: skip BERT, force LEGITIMATE ──
        logger.info(
            "[%s] URL '%s' matches trusted domain whitelist — "
            "bypassing BERT inference.",
            transaction_id,
            url_str,
        )
        bert_result = {
            "label": "LEGITIMATE",
            "confidence": TRUSTED_DOMAIN_CONFIDENCE,
            "is_malicious": False,
        }
        # Still run mule scan (defence-in-depth)
        mule_result = await mule_scanner.scan_and_verify(sanitized_text, db)
    else:
        # ── Non-whitelisted: inject URL context into model input ──
        #   Prepending the URL gives the BERT model domain-level signal
        #   alongside the page content, improving classification accuracy.
        model_input: str = f"URL: {url_str} | {sanitized_text}"

        bert_result, mule_result = await asyncio.gather(
            semantic_engine.predict(model_input),
            mule_scanner.scan_and_verify(sanitized_text, db),
        )

    elapsed_ms: float = round(
        (time.perf_counter_ns() - start_ns) / 1_000_000, 2
    )

    logger.info(
        "[%s] Pipeline completed in %.2f ms — BERT=%s, Mule=%s, trusted=%s",
        transaction_id,
        elapsed_ms,
        bert_result["label"],
        mule_result["mule_detected"],
        is_trusted,
    )

    # ── 5. Orchestration Verdict ──
    is_threat: bool = bert_result["is_malicious"] or mule_result["mule_detected"]
    verdict: str = VERDICT_BLOCK if is_threat else VERDICT_SAFE

    # ── 6. Background Telemetry (fire-and-forget) ──
    # Based on user request, we now log ALL scans to the telemetry feed
    # so they can see their live activity in the dashboard, even if it's safe.
    background_tasks.add_task(
        log_threat_telemetry,
        url=str(payload.url),
        score=bert_result["confidence"],
        db=db,
    )
    logger.info(
        "[%s] Telemetry write scheduled (background).",
        transaction_id,
    )

    # ── 7. Assemble Response ──
    response = AnalysisResponse(
        meta=MetaBlock(
            transaction_id=transaction_id,
            processing_time_ms=elapsed_ms,
        ),
        data=DataBlock(
            semantic_analysis=SemanticResult(
                label=bert_result["label"],
                confidence=bert_result["confidence"],
                is_malicious=bert_result["is_malicious"],
                sanitized_text_preview=sanitized_text[:_PREVIEW_LENGTH],
            ),
            mule_scan=MuleScanResult(
                accounts_extracted=mule_result["accounts_extracted"],
                flagged_accounts=mule_result["flagged_accounts"],
                mule_detected=mule_result["mule_detected"],
            ),
        ),
        orchestration=verdict,
    )

    logger.info(
        "[%s] Response assembled — verdict=%s",
        transaction_id,
        verdict,
    )

    return response
