"""
PhishGuard-AI — Public Analysis API (browser extension and API clients).
=========================================================================

All routes need the API key as ``Authorization: Bearer <key>`` and are rate
limited per client IP.

``POST /api/v1/analyze``       explained verdict for a page (URL + DOM + optional screenshot)
``POST /api/v1/analyze/qr``    decode a QR image and analyse its destination
``POST /api/v1/mule-reports``  queue a suspected mule account for analyst review

Architecture Layer : Presentation / API Gateway
"""

from __future__ import annotations

import logging
from typing import Any, Final

from fastapi import APIRouter, Depends, Request

from core.config import RATE_LIMIT
from core.rate_limit import limiter
from core.security import verify_api_key
from database.repository import create_mule_report
from schemas.payload import AnalyzeRequest, MuleReportRequest, QRScanRequest
from schemas.response import AnalysisResponse, QRScanResponse
from services.analysis_pipeline import PageInput, analyze_page, scan_qr_code
from services.mule_scanner import normalise_account

logger: Final[logging.Logger] = logging.getLogger("phishguard.endpoints")

router: Final[APIRouter] = APIRouter(
    prefix="/api/v1", tags=["Analysis API"], dependencies=[Depends(verify_api_key)],
)


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyse a web page and explain the verdict",
    description=(
        "Runs the full pipeline on the page the extension is showing: URL canonicalisation, HTTPS check, "
        "page-structure analysis, the BERT URL model, the mule-account registry and (when a screenshot is "
        "sent) the YOLOv8n logo detector in parallel, then the corroborated verdict engine. Returns "
        "SAFE, WARNING or BLOCK_RENDER with plain-language reasons and a step-by-step breakdown."
    ),
)
@limiter.limit(RATE_LIMIT)
async def analyze(payload: AnalyzeRequest, request: Request) -> dict[str, Any]:
    return await analyze_page(
        PageInput(url=payload.url, html=payload.dom_content or "", text=payload.text_content or "",
                  screenshot=payload.screenshot, source="extension", tls_error=payload.tls_error),
        request.app.state,
    )


@router.post(
    "/analyze/qr",
    response_model=QRScanResponse,
    summary="Decode a QR code and analyse where it leads",
    description="Decodes the QR image, checks any DuitNow account against the registry and, if it holds a "
                "link, fetches and analyses the destination page with the full pipeline.",
)
@limiter.limit(RATE_LIMIT)
async def analyze_qr(payload: QRScanRequest, request: Request) -> dict[str, Any]:
    return await scan_qr_code(payload.image_base64, request.app.state, source="api")


@router.post(
    "/mule-reports",
    status_code=201,
    summary="Report a suspected mule account for review",
    description="Queues the report as PENDING. Nothing is blocked until an analyst approves it in the "
                "dashboard, so a single client cannot poison the registry.",
)
@limiter.limit(RATE_LIMIT)
async def submit_mule_report(payload: MuleReportRequest, request: Request) -> dict[str, Any]:
    result = await create_mule_report(
        account_number=normalise_account(payload.account_number),
        bank_name=payload.bank_name.strip() or "Unknown",
        source="extension",
        page_url=payload.page_url,
        db=request.app.state.db,
    )
    logger.info("Mule report %s queued (already registered: %s).", result["report_id"], result["already_registered"])
    return result
