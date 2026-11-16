"""
PhishGuard-AI — API Endpoint Router.
======================================

Defines the ``/api/v1/analyze/semantics`` endpoint — the primary
ingestion point for the browser extension.  The handler orchestrates
the full analysis pipeline:

    DOM Payload → ETL Sanitization → [BERT URL Inference ∥ Mule Scan]
                                      (asyncio.gather)
               → Brand / Heuristic Profiling
               → Corroborated Verdict (services.verdict_engine)
               → JSON Response

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

from core.config import (
    GLOBAL_SAFE_DOMAINS,
    MALICIOUS_THRESHOLD,
    RATE_LIMIT,
    TRUSTED_DOMAIN_CONFIDENCE,
    TRUSTED_DOMAINS,
    VERDICT_BLOCK,
    VERDICT_SAFE,
)
from core.rate_limit import limiter
from core.security import verify_api_key
from schemas.payload import MuleReportRequest, WebPayload
from schemas.response import (
    AnalysisResponse,
    DataBlock,
    MetaBlock,
    MuleScanResult,
    QuishingAnalysisRequest,
    QuishingAnalysisResponse,
    SemanticResult,
)
from services.sanitizer import sanitize_dom
from services.brand_profiler import profile_brand_impersonation
from services.heuristic_engine import analyze_url_heuristics
from services.nlp_engine import build_model_input
from services.verdict_engine import decide
from database.repository import create_mule_report, log_threat_telemetry

logger: Final[logging.Logger] = logging.getLogger("phishguard.endpoints")

# ==============================================================================
# Router Configuration
# ==============================================================================
router: Final[APIRouter] = APIRouter(
    prefix="/api/v1",
    tags=["Live Analysis & Ingestion"],
    dependencies=[Depends(verify_api_key)],  # All routes require auth.
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
# POST /api/v1/analyze/semantics
# ==============================================================================

@router.post(
    "/analyze/semantics",
    response_model=AnalysisResponse,
    summary="Analyse a web page for phishing threats",
    description=(
        "Accepts a raw DOM payload, sanitises the HTML, runs BERT URL "
        "classification and mule-account scanning **in parallel**, corroborates "
        "them with brand, heuristic and credential-form signals, and returns a "
        "unified threat-assessment response with an orchestration directive."
    ),
    response_description="Unified analysis envelope with orchestration verdict.",
    status_code=200,
)
@router.post(
    "/analyse/semantics",
    response_model=AnalysisResponse,
    include_in_schema=False,
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
    # ── 1. Transaction ID ──
    transaction_id: str = str(uuid.uuid4())
    logger.info(
        "[%s] Received analysis request for URL: %s",
        transaction_id,
        payload.url,
    )

    # ── 2. ETL Sanitisation ──
    raw_content = payload.dom_content or payload.text_content or ""
    sanitized_text: str = sanitize_dom(raw_content)
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
    cache = getattr(request.app.state, "cache", None)

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
        # ── Non-whitelisted: classify the URL with BERT ──
        if semantic_engine is None:
            logger.warning(
                "[%s] Semantic engine is disabled — returning neutral "
                "classification for non-whitelisted URL '%s'.",
                transaction_id,
                url_str,
            )
            bert_result = {
                "label": "LEGITIMATE",
                "confidence": 0.0,
                "is_malicious": False,
            }
            mule_result = await mule_scanner.scan_and_verify(sanitized_text, db)
        else:
            # The model is a URL classifier: feed it the URL in the same
            # form as its training corpus (see ``build_model_input``).
            model_input: str = build_model_input(url_str)
            cache_key = cache.hash_key(model_input) if cache else None
            cached_bert = cache.get(cache_key) if cache and cache_key else None

            if cached_bert is not None:
                logger.info("[%s] Returning cached BERT inference result (hash=%s)", transaction_id, cache_key[:12])
                bert_result = cached_bert
                mule_result = await mule_scanner.scan_and_verify(sanitized_text, db)
            else:
                bert_result, mule_result = await asyncio.gather(
                    semantic_engine.predict(model_input),
                    mule_scanner.scan_and_verify(sanitized_text, db),
                )
                if cache and cache_key:
                    cache.set(cache_key, bert_result)

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

    # ── 5. Corroborated Multi-Signal Orchestration Verdict ──
    #
    #   No probabilistic signal blocks a page on its own.  The verdict engine
    #   combines the BERT URL verdict, mule-registry lookup, brand profiling,
    #   URL heuristics, credential-form detection and the scam lexicon, and
    #   blocks only when independent signals corroborate one another.
    brand_result = profile_brand_impersonation(url_str, sanitized_text)
    heur_result = analyze_url_heuristics(url_str)
    decision = decide(
        is_trusted=is_trusted,
        bert_result=bert_result,
        mule_result=mule_result,
        brand_result=brand_result,
        heuristic_result=heur_result,
        sanitized_text=sanitized_text,
        raw_content=raw_content,
    )
    is_threat: bool = decision.is_threat
    verdict: str = decision.verdict

    # ── 6. Live Telemetry & Mule Registry Ingestion ──
    if is_threat:
        try:
            # ``log_threat_telemetry`` also broadcasts the SSE event (once).
            await log_threat_telemetry(
                url=str(payload.url),
                score=decision.risk_score,
                db=db,
            )
            # Increment the report counter of accounts that are ALREADY in the
            # registry.  Accounts that are merely extracted from a blocked page
            # are deliberately NOT inserted: doing so would let a single
            # false positive poison the registry with an innocent account.
            for acc in mule_result.get("flagged_accounts", []):
                acc_num = str(acc.get("account_number", "")).strip()
                if acc_num:
                    await db.execute(
                        "UPDATE mule_registry SET report_count = report_count + 1 "
                        "WHERE account_number = ?;",
                        (acc_num,),
                    )
            await db.commit()
        except Exception:
            logger.exception("[%s] Real-time telemetry ingestion failed.", transaction_id)

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
        status="success",
        verdict=verdict,
        risk_score=round(decision.risk_score, 4),
        bert_score=round(float(bert_result["confidence"]), 6),
        is_whitelisted=is_trusted,
        brand_impersonation=brand_result,
        threat_indicators=decision.indicators,
        decision_rule=decision.rule,
        signals=decision.signals,
        mule_accounts_flagged=mule_result.get("flagged_accounts", []),
        execution_time_ms=elapsed_ms,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
    )

    logger.info(
        "[%s] Response assembled — verdict=%s rule=%s",
        transaction_id,
        verdict,
        decision.rule,
    )

    return response


# ==============================================================================
# POST /api/v1/analyze/quishing
# ==============================================================================

@router.post(
    "/analyze/quishing",
    response_model=QuishingAnalysisResponse,
    summary="Decode QR Code and Forensically Audit Embedded Payload (§4.3.3)",
    description=(
        "Accepts a base64-encoded image containing a QR code matrix, decodes "
        "the embedded payload via OpenCV cv2.QRCodeDetector, and audits the payload "
        "against PayNet EMVCo DuitNow payment specifications and phishing threat indicators."
    ),
    status_code=200,
)
@router.post(
    "/analyse/quishing",
    response_model=QuishingAnalysisResponse,
    include_in_schema=False,
    status_code=200,
)
async def analyze_quishing_endpoint(
    payload: QuishingAnalysisRequest,
    _api_key: str = Depends(verify_api_key),
) -> QuishingAnalysisResponse:
    """Optical Quishing forensic scan endpoint."""
    from services.quishing_scanner import decode_and_scan_qr_image

    scan_res = decode_and_scan_qr_image(payload.image_base64)
    quish_score = float(scan_res.get("quishing_score", 0.0))
    is_threat = quish_score >= 0.70 or bool(scan_res.get("extracted_mule_accounts"))
    verdict = "BLOCK_RENDER" if is_threat else "SAFE"

    return QuishingAnalysisResponse(
        quishing_threat=is_threat,
        quishing_score=quish_score,
        decoded_payload=scan_res.get("raw_payload", ""),
        verdict=verdict,
        risk_factors=scan_res.get("risk_factors", []),
        raw_payload=scan_res.get("raw_payload", ""),
        is_duitnow_scheme=scan_res.get("is_duitnow_scheme", False),
        extracted_destination_urls=scan_res.get("extracted_destination_urls", []),
        extracted_mule_accounts=scan_res.get("extracted_mule_accounts", []),
    )


# ==============================================================================
# POST /api/v1/mule-reports
# ==============================================================================

@router.post(
    "/mule-reports",
    summary="Submit a suspected mule account for analyst review",
    description=(
        "Queues a user report with status PENDING. The account is NOT added to "
        "the blocking registry until an analyst approves the report from the "
        "SOC dashboard; this prevents registry poisoning by a single client."
    ),
    status_code=201,
)
@limiter.limit(RATE_LIMIT)
async def submit_mule_report(
    payload: MuleReportRequest,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Record a mule-account report from the browser extension."""
    account = "".join(ch for ch in payload.account_number if ch.isdigit() or ch == "+")
    result = await create_mule_report(
        account_number=account,
        bank_name=payload.bank_name.strip() or "Unknown",
        source="extension",
        page_url=str(payload.page_url) if payload.page_url else None,
        db=request.app.state.db,
    )
    logger.info("Mule report %s queued (already_registered=%s).", result["report_id"], result["already_registered"])
    return result


# ==============================================================================
# GET /api/v1/mule-registry (Browser Extension & Direct Query Alias)
# ==============================================================================

@router.get(
    "/mule-registry",
    summary="Direct Mule Registry Query Alias",
    include_in_schema=False,
)
@router.get(
    "/mules",
    summary="Direct Mule Registry Query Alias",
    include_in_schema=False,
)
async def direct_mule_registry_alias(request: Request) -> dict[str, Any]:
    """Expose mule registry directly under /api/v1/mule-registry for extension clients."""
    from api.dashboard_endpoints import get_mule_registry
    return await get_mule_registry(request)


