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
        "ORDER BY log_id DESC;"
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
