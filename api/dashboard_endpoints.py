"""
PhishGuard-AI — SOC Dashboard API.
===================================

Backs the four dashboard tabs.  Every route needs the admin key (bearer
token) or a browser session created by ``POST /auth/login``; only the
``/auth/*`` routes are reachable without one.

Tab 1  Overview          GET  /overview, GET /scans, GET /scans/export
Tab 2  Mule registry     GET/POST /mules, DELETE /mules/{id},
                         GET /mule-reports, POST /mule-reports/{id}/review
Tab 3  QR scanner        POST /qr-scan
Tab 4  URL analyzer      POST /analyze

Architecture Layer : Presentation / Administration
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Final, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from core.config import DASHBOARD_SESSION_TTL_SECONDS, RATE_LIMIT
from core.rate_limit import LOGIN_RATE_LIMIT, limiter
from core.security import (
    SESSION_COOKIE_NAME,
    create_dashboard_session,
    destroy_dashboard_session,
    is_valid_admin_key,
    is_valid_dashboard_session,
    verify_dashboard_access,
)
from database.repository import (
    SCAN_COLUMNS,
    add_mule_account,
    delete_mule_account,
    list_mule_accounts,
    list_mule_reports,
    list_scans,
    review_mule_report,
    scan_statistics,
)
from schemas.payload import (
    DashboardAnalyzeRequest,
    DashboardLoginRequest,
    MuleAccountCreate,
    MuleReportReview,
    QRScanRequest,
)
from schemas.response import AnalysisResponse, QRScanResponse
from services.analysis_pipeline import PageInput, analyze_page, scan_qr_code
from services.mule_scanner import normalise_account

logger: Final[logging.Logger] = logging.getLogger("phishguard.dashboard")

router: Final[APIRouter] = APIRouter(
    prefix="/api/v1/dashboard", tags=["SOC Dashboard"], dependencies=[Depends(verify_dashboard_access)],
)

Verdict = Literal["SAFE", "WARNING", "BLOCK_RENDER"]


# ==============================================================================
# Sign-in
# ==============================================================================

@router.post("/auth/login", summary="Exchange the admin key for a session cookie")
@limiter.limit(LOGIN_RATE_LIMIT)
async def login(request: Request, payload: DashboardLoginRequest, response: Response) -> dict[str, Any]:
    if not is_valid_admin_key(payload.api_key):
        logger.warning("Rejected dashboard sign-in from %s", request.client.host if request.client else "unknown")
        raise HTTPException(401, {"error": "INVALID_ADMIN_KEY", "message": "The admin key is incorrect."})
    response.set_cookie(
        SESSION_COOKIE_NAME, create_dashboard_session(), max_age=DASHBOARD_SESSION_TTL_SECONDS,
        httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/",
    )
    return {"authenticated": True, "expires_in": DASHBOARD_SESSION_TTL_SECONDS}


@router.get("/auth/session", summary="Is the caller signed in?")
async def session_status(request: Request) -> dict[str, bool]:
    return {"authenticated": is_valid_dashboard_session(request.cookies.get(SESSION_COOKIE_NAME))}


@router.post("/auth/logout", summary="End the dashboard session")
async def logout(request: Request, response: Response) -> dict[str, bool]:
    destroy_dashboard_session(request.cookies.get(SESSION_COOKIE_NAME))
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"authenticated": False}


# ==============================================================================
# Tab 1 — Overview and scan log
# ==============================================================================

@router.get("/overview", summary="Scan counters and the most recent scans")
async def overview(request: Request, recent: int = Query(15, ge=1, le=100)) -> dict[str, Any]:
    db = request.app.state.db
    return {"stats": await scan_statistics(db), "recent_scans": await list_scans(db, limit=recent)}


@router.get("/scans", summary="Page through the scan log")
async def scans(
    request: Request,
    verdict: Optional[Verdict] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    return {"items": await list_scans(request.app.state.db, verdict, limit, offset)}


@router.get("/scans/export", summary="Download the scan log as CSV or JSON")
async def export_scans(
    request: Request,
    format: Literal["csv", "json"] = "csv",
    verdict: Optional[Verdict] = None,
) -> StreamingResponse:
    rows = await list_scans(request.app.state.db, verdict, limit=100_000)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if format == "json":
        body = json.dumps({"exported_at": stamp, "count": len(rows), "scans": rows}, indent=2)
        media, ext = "application/json", "json"
    else:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(SCAN_COLUMNS))
        writer.writeheader()
        for row in rows:
            # Neutralise spreadsheet formula injection in URL-derived cells.
            writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in row.items()})
        body, media, ext = buffer.getvalue(), "text/csv", "csv"
    return StreamingResponse(
        iter([body]), media_type=media,
        headers={"Content-Disposition": f'attachment; filename="phishguard-scans-{stamp}.{ext}"'},
    )


# ==============================================================================
# Tab 2 — Mule registry and review queue
# ==============================================================================

@router.get("/mules", summary="Search the mule-account registry")
async def mules(
    request: Request,
    search: str = Query("", max_length=60),
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    term = normalise_account(search) if search and search.replace(" ", "").replace("-", "").isdigit() else search.strip()
    return await list_mule_accounts(request.app.state.db, term, limit, offset)


@router.post("/mules", status_code=201, summary="Add a verified account to the registry")
async def add_mule(payload: MuleAccountCreate, request: Request) -> dict[str, Any]:
    record = await add_mule_account(
        normalise_account(payload.account_number), payload.bank_name, payload.platform_flagged, 1, request.app.state.db,
    )
    logger.info("Registry account %s added from the dashboard.", record["account_number"])
    return record


@router.delete("/mules/{mule_id}", summary="Remove an account from the registry")
async def remove_mule(mule_id: int, request: Request) -> dict[str, Any]:
    if not await delete_mule_account(mule_id, request.app.state.db):
        raise HTTPException(404, {"error": "NOT_FOUND", "message": f"No registry account with id {mule_id}."})
    return {"deleted": mule_id}


@router.get("/mule-reports", summary="List user-submitted reports")
async def mule_reports(
    request: Request,
    status: Literal["PENDING", "APPROVED", "REJECTED", "ALL"] = "PENDING",
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    items = await list_mule_reports(None if status == "ALL" else status, limit, request.app.state.db)
    return {"count": len(items), "reports": items}


@router.post("/mule-reports/{report_id}/review", summary="Approve or reject a report")
async def review_report(report_id: int, payload: MuleReportReview, request: Request) -> dict[str, Any]:
    result = await review_mule_report(report_id, payload.decision == "APPROVE", request.app.state.db)
    if result is None:
        raise HTTPException(404, {"error": "NOT_FOUND", "message": f"No report with id {report_id}."})
    return result


# ==============================================================================
# Tab 3 — QR scanner, Tab 4 — Live URL analyzer
# ==============================================================================

@router.post("/qr-scan", response_model=QRScanResponse, summary="Decode a QR image and analyse its destination")
@limiter.limit(RATE_LIMIT)
async def qr_scan(payload: QRScanRequest, request: Request) -> dict[str, Any]:
    return await scan_qr_code(payload.image_base64, request.app.state, source="qr")


@router.post("/analyze", response_model=AnalysisResponse, summary="Analyse any URL with the live pipeline")
@limiter.limit(RATE_LIMIT)
async def analyze(payload: DashboardAnalyzeRequest, request: Request) -> dict[str, Any]:
    return await analyze_page(
        PageInput(
            url=payload.url,
            text=payload.page_text or "",
            source="dashboard",
            fetch=payload.fetch_page and not payload.page_text,
            extra_accounts=[payload.account_number] if payload.account_number else [],
        ),
        request.app.state,
    )
