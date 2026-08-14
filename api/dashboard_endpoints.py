"""
PhishGuard-AI — Dashboard API Endpoints.
==========================================

Exposes read-only endpoints consumed by the monitoring dashboard to
visualise threat telemetry, mule-registry contents, and aggregate
statistics.

These routes are **unauthenticated** by design — the dashboard is an
internal monitoring tool intended for system administrators operating
within a trusted network boundary.

Architecture Layer : Presentation / Internal Monitoring
Thesis Reference   : §5.3 — Operational Monitoring & Telemetry Visualisation
"""

from __future__ import annotations

import logging
from typing import Any, Final

from fastapi import APIRouter, Request

logger: Final[logging.Logger] = logging.getLogger("phishguard.dashboard")

# ==============================================================================
# Router Configuration (no auth dependency — internal use only)
# ==============================================================================
router: Final[APIRouter] = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard (Internal)"],
)


# ==============================================================================
# GET /api/v1/dashboard/stats
# ==============================================================================

@router.get(
    "/stats",
    summary="Aggregate threat statistics",
    response_description="High-level stats for dashboard cards.",
)
async def get_stats(request: Request) -> dict[str, Any]:
    """Return aggregate statistics for the dashboard stat cards.

    Metrics
    -------
    - ``total_threats`` : Total rows in ``threat_telemetry``.
    - ``avg_confidence`` : Average BERT confidence score across all threats.
    - ``total_mule_accounts`` : Number of entries in ``mule_registry``.
    - ``total_reports`` : Sum of all ``report_count`` values in the registry.
    """
    db = request.app.state.db

    # ── Threat telemetry aggregates ──
    cursor = await db.execute(
        "SELECT COUNT(*), COALESCE(AVG(bert_score), 0.0) "
        "FROM threat_telemetry;"
    )
    row = await cursor.fetchone()
    total_threats: int = row[0] if row else 0
    avg_confidence: float = round(row[1], 4) if row else 0.0

    # ── Mule registry aggregates ──
    cursor = await db.execute(
        "SELECT COUNT(*), COALESCE(SUM(report_count), 0) "
        "FROM mule_registry;"
    )
    row = await cursor.fetchone()
    total_mule_accounts: int = row[0] if row else 0
    total_reports: int = row[1] if row else 0

    return {
        "total_threats": total_threats,
        "avg_confidence": avg_confidence,
        "total_mule_accounts": total_mule_accounts,
        "total_reports": total_reports,
    }


# ==============================================================================
# GET /api/v1/dashboard/system-health
# ==============================================================================

@router.get(
    "/system-health",
    summary="AI engine, database, and cache health diagnostics",
)
async def get_system_health(request: Request) -> dict[str, Any]:
    """Return runtime system status, model availability, and cache efficiency."""
    cache = getattr(request.app.state, "cache", None)
    cache_entries = len(cache._cache) if cache and hasattr(cache, "_cache") else 0
    
    nlp_engine = getattr(request.app.state, "nlp_engine", None)
    bert_loaded = nlp_engine is not None and hasattr(nlp_engine, "is_ready") and nlp_engine.is_ready

    visual_detector = getattr(request.app.state, "visual_detector", None)
    yolo_loaded = visual_detector is not None

    return {
        "status": "healthy",
        "database": "SQLite 3NF (WAL mode)",
        "cache": {
            "status": "active" if cache else "disabled",
            "active_entries": cache_entries,
            "ttl_seconds": 600,
        },
        "models": {
            "bert_semantic": "loaded" if bert_loaded else "mock_or_offline",
            "yolov8_visual": "loaded" if yolo_loaded else "mock_or_offline",
        },
        "sse_subscribers": len(_SSE_CLIENTS),
    }


# ==============================================================================
# POST /api/v1/dashboard/quick-scan
# ==============================================================================

from pydantic import BaseModel

class QuickScanRequest(BaseModel):
    url: str
    text_content: str = ""

@router.post(
    "/quick-scan",
    summary="Immediate URL / text heuristic analysis directly from dashboard",
)
async def quick_scan_url(request: Request, payload: QuickScanRequest) -> dict[str, Any]:
    """Run an instant heuristic & mule scanner scan on any URL or text payload."""
    import pathlib
    import httpx
    from urllib.parse import urlparse

    db = request.app.state.db
    mule_scanner = request.app.state.mule_scanner
    semantic_engine = getattr(request.app.state, "semantic_engine", None)

    target_url = payload.url.strip()
    fetched_content = payload.text_content or ""

    # Check if target_url is a web URL or local static file
    if target_url.startswith("http://") or target_url.startswith("https://") or "test_scam.html" in target_url:
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        # If local test scam page on disk
        if "test_scam.html" in parsed.path:
            local_scam_path = pathlib.Path("dashboard/test_scam.html")
            if local_scam_path.is_file():
                fetched_content += " " + local_scam_path.read_text(encoding="utf-8", errors="ignore")

        # Attempt HTTP fetch for external or live local URLs
        if not fetched_content or len(fetched_content) < 100:
            try:
                async with httpx.AsyncClient(timeout=2.5, follow_redirects=True) as client:
                    resp = await client.get(target_url)
                    if resp.status_code == 200:
                        fetched_content += " " + resp.text
            except Exception:
                pass

    combined_text = f"{target_url} {fetched_content}"

    # 1. Run Mule & DuitNow Scanner
    mule_result = await mule_scanner.scan_and_verify(combined_text, db)

    # 2. Run BERT Semantic Engine if available
    bert_score = 0.05
    is_phishing_semantic = False
    if semantic_engine and len(combined_text.strip()) > 20:
        try:
            sem_result = semantic_engine.predict_proba(combined_text)
            bert_score = float(sem_result.get("phishing_probability", 0.05))
            is_phishing_semantic = bert_score >= 0.70
        except Exception:
            pass

    # 3. Typo-squatting & keywords
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    host = (parsed.hostname or target_url).lower()
    has_scam_keywords = any(
        kw in combined_text.lower()
        for kw in ["verify", "suspended", "urgent", "security update", "pdrm", "bank login", "transfer", "deposit"]
    )

    is_threat = mule_result["mule_detected"] or is_phishing_semantic or (has_scam_keywords and "scam" in target_url)
    if mule_result["mule_detected"]:
        score = max(0.99, bert_score)
        verdict = "BLOCK_RENDER"
    elif is_threat:
        score = max(0.85, bert_score)
        verdict = "BLOCK_RENDER"
    else:
        score = bert_score if bert_score < 0.5 else 0.05
        verdict = "SAFE"

    # Broadcast event if threat detected so dashboard counters immediately update
    if verdict == "BLOCK_RENDER":
        try:
            from database.repository import log_threat_telemetry
            log_id = await log_threat_telemetry(db, target_url, score)
            await broadcast_threat_event("new_threat", {
                "log_id": log_id,
                "malicious_url": target_url,
                "bert_score": round(score, 4),
                "timestamp": "Just now",
            })
        except Exception:
            pass

    return {
        "url": target_url,
        "verdict": verdict,
        "score": score,
        "mule_detected": mule_result["mule_detected"],
        "flagged_accounts": mule_result["flagged_accounts"],
        "scanned_at": "Just now",
    }



# ==============================================================================
# GET /api/v1/dashboard/telemetry
# ==============================================================================

@router.get(
    "/telemetry",
    summary="Recent threat telemetry entries",
    response_description="List of recent malicious URL detections.",
)
async def get_telemetry(request: Request) -> dict[str, Any]:
    """Return the 50 most recent threat telemetry entries (newest first)."""
    db = request.app.state.db

    cursor = await db.execute(
        "SELECT log_id, malicious_url, bert_score, timestamp "
        "FROM threat_telemetry "
        "ORDER BY log_id DESC "
        "LIMIT 50;"
    )
    rows = await cursor.fetchall()

    entries: list[dict[str, Any]] = [
        {
            "log_id": r[0],
            "malicious_url": r[1],
            "bert_score": round(r[2], 4),
            "timestamp": r[3],
        }
        for r in rows
    ]

    return {"count": len(entries), "entries": entries}


# ==============================================================================
# GET /api/v1/dashboard/mule-registry
# ==============================================================================

@router.get(
    "/mule-registry",
    summary="Full mule account registry",
    response_description="All known mule accounts in the registry.",
)
async def get_mule_registry(request: Request) -> dict[str, Any]:
    """Return every entry in the ``mule_registry`` table."""
    db = request.app.state.db

    cursor = await db.execute(
        "SELECT id, account_number, bank_name, platform_flagged, "
        "       report_count, date_added "
        "FROM mule_registry "
        "ORDER BY id DESC;"
    )
    rows = await cursor.fetchall()

    accounts: list[dict[str, Any]] = [
        {
            "id": r[0],
            "account_number": r[1],
            "bank_name": r[2],
            "platform_flagged": r[3],
            "report_count": r[4],
            "date_added": r[5],
        }
        for r in rows
    ]

    return {"count": len(accounts), "accounts": accounts}


# ==============================================================================
# POST /api/v1/dashboard/mule-registry
# ==============================================================================

from pydantic import BaseModel, Field
from fastapi import HTTPException
from fastapi.responses import Response
import csv
import io
from database.repository import add_mule_account, delete_mule_account

class CreateMuleRequest(BaseModel):
    account_number: str = Field(..., min_length=8, max_length=20)
    bank_name: str = Field(..., min_length=2, max_length=50)
    platform_flagged: str = Field(default="dashboard_entry", max_length=50)
    report_count: int = Field(default=1, ge=1)


@router.post(
    "/mule-registry",
    summary="Add or update a mule account",
    response_description="Created or updated mule record.",
)
async def create_mule(payload: CreateMuleRequest, request: Request) -> dict[str, Any]:
    """Add a new mule account or increment existing report count."""
    db = request.app.state.db
    record = await add_mule_account(
        account_number=payload.account_number,
        bank_name=payload.bank_name,
        platform_flagged=payload.platform_flagged,
        report_count=payload.report_count,
        db=db,
    )
    return {"success": True, "record": record}


@router.delete(
    "/mule-registry/{mule_id}",
    summary="Delete a mule account",
)
async def remove_mule(mule_id: int, request: Request) -> dict[str, Any]:
    """Delete a mule account by ID."""
    db = request.app.state.db
    deleted = await delete_mule_account(mule_id=mule_id, db=db)
    if not deleted:
        raise HTTPException(status_code=404, detail="Mule account not found")
    return {"success": True, "deleted_id": mule_id}


# ==============================================================================
# GET /api/v1/dashboard/telemetry/export (CSV)
# ==============================================================================

@router.get(
    "/telemetry/export",
    summary="Export threat telemetry as CSV",
)
async def export_telemetry_csv(request: Request) -> Response:
    """Stream threat telemetry entries as a downloadable CSV file."""
    db = request.app.state.db
    cursor = await db.execute(
        "SELECT log_id, malicious_url, bert_score, timestamp "
        "FROM threat_telemetry ORDER BY log_id DESC;"
    )
    rows = await cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Log ID", "Malicious URL", "BERT Score", "Timestamp"])
    for r in rows:
        writer.writerow([r[0], r[1], f"{r[2]:.4f}", r[3]])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_threat_telemetry.csv"},
    )


# ==============================================================================
# GET /api/v1/dashboard/distributions (Analytics Charts)
# ==============================================================================

@router.get(
    "/distributions",
    summary="Data distributions for analytics charts",
)
async def get_distributions(request: Request) -> dict[str, Any]:
    """Return bank and platform breakdowns for visual analytics charts."""
    db = request.app.state.db

    # Bank distribution
    cursor = await db.execute(
        "SELECT bank_name, COUNT(*), SUM(report_count) FROM mule_registry "
        "GROUP BY bank_name ORDER BY COUNT(*) DESC LIMIT 8;"
    )
    bank_rows = await cursor.fetchall()
    banks = [
        {"bank": r[0], "count": r[1], "reports": r[2] or 0}
        for r in bank_rows
    ]

    # Platform distribution
    cursor = await db.execute(
        "SELECT platform_flagged, COUNT(*) FROM mule_registry "
        "GROUP BY platform_flagged ORDER BY COUNT(*) DESC LIMIT 6;"
    )
    platform_rows = await cursor.fetchall()
    platforms = [
        {"platform": r[0], "count": r[1]}
        for r in platform_rows
    ]

    # Timeline distribution (recent threat velocity buckets)
    cursor = await db.execute(
        "SELECT SUBSTR(timestamp, 1, 13) as hour_bucket, COUNT(*), AVG(bert_score) "
        "FROM threat_telemetry GROUP BY hour_bucket ORDER BY hour_bucket DESC LIMIT 12;"
    )
    timeline_rows = await cursor.fetchall()
    timeline = [
        {"time": r[0] + ":00", "count": r[1], "avg_score": round(r[2], 3)}
        for r in reversed(timeline_rows)
    ]

    return {
        "banks": banks,
        "platforms": platforms,
        "timeline": timeline,
    }


# ==============================================================================
# GET /api/v1/dashboard/stream (Server-Sent Events)
# ==============================================================================

import json
import asyncio
from fastapi.responses import StreamingResponse

# Set of active subscriber queues for broadcasting live threat events
_SSE_CLIENTS: set[asyncio.Queue] = set()

def broadcast_threat_event(event_type: str, data: dict[str, Any]) -> None:
    """Broadcast an event to all connected dashboard SSE clients."""
    payload = json.dumps({"event": event_type, "data": data})
    for queue in list(_SSE_CLIENTS):
        try:
            queue.put_nowait(payload)
        except Exception:
            _SSE_CLIENTS.discard(queue)


@router.get(
    "/stream",
    summary="Real-time Server-Sent Events stream",
)
async def sse_threat_stream(request: Request) -> StreamingResponse:
    """Stream real-time threat intelligence and telemetry via Server-Sent Events (SSE)."""
    client_queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _SSE_CLIENTS.add(client_queue)

    async def event_generator():
        try:
            # Send initial connected ping
            yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(client_queue.get(), timeout=15.0)
                    yield f"event: update\ndata: {message}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield ": heartbeat\n\n"
        finally:
            _SSE_CLIENTS.discard(client_queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ==============================================================================
# SIMULATOR TOGGLE
# ==============================================================================

@router.post(
    "/simulator/toggle",
    summary="Toggle live threat simulator",
)
async def toggle_simulator(request: Request) -> dict[str, Any]:
    """Toggle the background simulator on/off."""
    current = getattr(request.app.state, "simulator_running", False)
    request.app.state.simulator_running = not current
    return {"simulator_running": not current}


@router.get(
    "/simulator/status",
    summary="Get simulator status",
)
async def simulator_status(request: Request) -> dict[str, Any]:
    """Check if the simulator is currently running."""
    return {"simulator_running": getattr(request.app.state, "simulator_running", False)}


