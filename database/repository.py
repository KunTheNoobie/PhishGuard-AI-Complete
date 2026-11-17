"""
PhishGuard-AI — Data Access Functions.
=======================================

Every SQL statement the application runs.  Each function takes the
``aiosqlite`` connection as a parameter (dependency injection) and uses
positional placeholders only — values are never interpolated into SQL.

Architecture Layer : Data Access / Repository
"""

from __future__ import annotations

import logging
from typing import Any, Final

import aiosqlite

logger: Final[logging.Logger] = logging.getLogger("phishguard.repository")

_REGISTRY_COLUMNS: Final[tuple[str, ...]] = (
    "id", "account_number", "bank_name", "platform_flagged", "report_count", "date_added",
)
_REPORT_COLUMNS: Final[tuple[str, ...]] = (
    "report_id", "account_number", "bank_name", "source", "page_url", "status",
    "registry_id", "created_at", "reviewed_at",
)
SCAN_COLUMNS: Final[tuple[str, ...]] = (
    "scan_id", "created_at", "source", "url", "hostname", "scheme", "verdict", "rule",
    "risk_score", "bert_score", "headline", "latency_ms",
)


# ==============================================================================
# Mule registry
# ==============================================================================

async def check_mule_accounts(accounts: list[str], db: aiosqlite.Connection) -> list[dict[str, Any]]:
    """Return the registry rows whose compact account number is in ``accounts``."""
    if not accounts:
        return []
    placeholders = ", ".join("?" for _ in accounts)
    cursor = await db.execute(
        f"SELECT account_number, bank_name, report_count FROM mule_registry "
        f"WHERE account_number IN ({placeholders});",
        accounts,
    )
    return [{"account_number": r[0], "bank_name": r[1], "report_count": r[2]} for r in await cursor.fetchall()]


async def list_mule_accounts(
    db: aiosqlite.Connection, search: str = "", limit: int = 25, offset: int = 0,
) -> dict[str, Any]:
    """Page through the registry, newest first, optionally filtered."""
    where, params = "", []
    if search:
        where = "WHERE account_number LIKE ? OR bank_name LIKE ? OR platform_flagged LIKE ?"
        like = f"%{search}%"
        params = [like, like, like]
    cursor = await db.execute(f"SELECT COUNT(*) FROM mule_registry {where};", params)
    (total,) = await cursor.fetchone()
    cursor = await db.execute(
        f"SELECT {', '.join(_REGISTRY_COLUMNS)} FROM mule_registry {where} "
        f"ORDER BY date_added DESC, id DESC LIMIT ? OFFSET ?;",
        [*params, limit, offset],
    )
    return {"total": total, "items": [dict(zip(_REGISTRY_COLUMNS, r)) for r in await cursor.fetchall()]}


async def add_mule_account(
    account_number: str, bank_name: str, platform_flagged: str, report_count: int, db: aiosqlite.Connection,
) -> dict[str, Any]:
    """Insert an account, or add to its report count if it already exists."""
    await db.execute(
        "INSERT INTO mule_registry (account_number, bank_name, platform_flagged, report_count) "
        "VALUES (?, ?, ?, ?) ON CONFLICT(account_number) DO UPDATE SET "
        "report_count = report_count + excluded.report_count, bank_name = excluded.bank_name, "
        "platform_flagged = excluded.platform_flagged;",
        (account_number, bank_name.strip() or "Unknown", platform_flagged.strip() or "manual entry",
         max(1, report_count)),
    )
    await db.commit()
    cursor = await db.execute(
        f"SELECT {', '.join(_REGISTRY_COLUMNS)} FROM mule_registry WHERE account_number = ?;", (account_number,)
    )
    return dict(zip(_REGISTRY_COLUMNS, await cursor.fetchone()))


async def delete_mule_account(mule_id: int, db: aiosqlite.Connection) -> bool:
    """Delete a registry row by id; True if a row was removed."""
    cursor = await db.execute("DELETE FROM mule_registry WHERE id = ?;", (mule_id,))
    await db.commit()
    return cursor.rowcount > 0


async def increment_report_counts(accounts: list[str], db: aiosqlite.Connection) -> None:
    """Add one sighting to registry accounts seen on a blocked page."""
    for account in accounts:
        await db.execute("UPDATE mule_registry SET report_count = report_count + 1 WHERE account_number = ?;",
                         (account,))
    await db.commit()


# ==============================================================================
# User reports (review queue)
# ==============================================================================

async def create_mule_report(
    account_number: str, bank_name: str, source: str, page_url: str | None, db: aiosqlite.Connection,
) -> dict[str, Any]:
    """Queue a report as PENDING; link it if the account is already registered."""
    cursor = await db.execute("SELECT id FROM mule_registry WHERE account_number = ?;", (account_number,))
    row = await cursor.fetchone()
    registry_id = row[0] if row else None
    cursor = await db.execute(
        "INSERT INTO mule_reports (account_number, bank_name, source, page_url, registry_id) VALUES (?, ?, ?, ?, ?);",
        (account_number, bank_name, source, page_url, registry_id),
    )
    report_id = cursor.lastrowid
    if registry_id is not None:  # another sighting of a known mule account
        await db.execute("UPDATE mule_registry SET report_count = report_count + 1 WHERE id = ?;", (registry_id,))
    await db.commit()
    return {"report_id": report_id, "status": "PENDING", "already_registered": registry_id is not None}


async def list_mule_reports(status: str | None, limit: int, db: aiosqlite.Connection) -> list[dict[str, Any]]:
    """Return reports, newest first, optionally filtered by status."""
    where, params = ("WHERE status = ?", [status]) if status else ("", [])
    cursor = await db.execute(
        f"SELECT {', '.join(_REPORT_COLUMNS)} FROM mule_reports {where} "
        f"ORDER BY created_at DESC, report_id DESC LIMIT ?;",
        [*params, limit],
    )
    return [dict(zip(_REPORT_COLUMNS, r)) for r in await cursor.fetchall()]


async def review_mule_report(report_id: int, approve: bool, db: aiosqlite.Connection) -> dict[str, Any] | None:
    """Approve (promote into the registry) or reject a PENDING report."""
    cursor = await db.execute(
        "SELECT account_number, bank_name, status, registry_id FROM mule_reports WHERE report_id = ?;", (report_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    account_number, bank_name, status, registry_id = row
    if status != "PENDING":
        return {"report_id": report_id, "status": status, "registry_id": registry_id, "changed": False}
    if approve:
        record = await add_mule_account(account_number, bank_name, "User report (analyst approved)", 1, db)
        registry_id = record["id"]
    new_status = "APPROVED" if approve else "REJECTED"
    await db.execute(
        "UPDATE mule_reports SET status = ?, registry_id = ?, reviewed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
        "WHERE report_id = ?;",
        (new_status, registry_id, report_id),
    )
    await db.commit()
    return {"report_id": report_id, "status": new_status, "registry_id": registry_id, "changed": True}


# ==============================================================================
# Scan log
# ==============================================================================

async def log_scan(entry: dict[str, Any], db: aiosqlite.Connection) -> int:
    """Append one analysed page to ``scan_log``; returns its id."""
    cursor = await db.execute(
        "INSERT INTO scan_log (source, url, hostname, scheme, verdict, rule, risk_score, bert_score, headline, latency_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (entry["source"], entry["url"][:2048], entry["hostname"][:255], entry["scheme"], entry["verdict"],
         entry.get("rule"), entry["risk_score"], entry.get("bert_score"), entry["headline"][:200],
         entry["latency_ms"]),
    )
    await db.commit()
    return cursor.lastrowid or 0


async def scan_statistics(db: aiosqlite.Connection) -> dict[str, int]:
    """Counts by verdict over the whole log and over the last 24 hours."""
    cursor = await db.execute(
        "SELECT COUNT(*), "
        "SUM(verdict = 'BLOCK_RENDER'), SUM(verdict = 'WARNING'), SUM(verdict = 'SAFE'), "
        "SUM(rule = 'H2_INSECURE_HTTP'), "
        "SUM(created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day')) FROM scan_log;"
    )
    total, blocked, warning, safe, http_warnings, last_24h = await cursor.fetchone()
    cursor = await db.execute("SELECT COUNT(*) FROM mule_registry;")
    (registry,) = await cursor.fetchone()
    cursor = await db.execute("SELECT COUNT(*) FROM mule_reports WHERE status = 'PENDING';")
    (pending,) = await cursor.fetchone()
    return {
        "total_scans": total or 0, "blocked": blocked or 0, "warnings": warning or 0,
        "http_warnings": http_warnings or 0, "safe": safe or 0,
        "last_24h": last_24h or 0, "registry_accounts": registry or 0, "pending_reports": pending or 0,
    }


async def list_scans(
    db: aiosqlite.Connection, verdict: str | None = None, limit: int = 50, offset: int = 0,
) -> list[dict[str, Any]]:
    """Scan-log rows, newest first, optionally filtered by verdict."""
    where, params = ("WHERE verdict = ?", [verdict]) if verdict else ("", [])
    cursor = await db.execute(
        f"SELECT {', '.join(SCAN_COLUMNS)} FROM scan_log {where} ORDER BY scan_id DESC LIMIT ? OFFSET ?;",
        [*params, limit, offset],
    )
    return [dict(zip(SCAN_COLUMNS, r)) for r in await cursor.fetchall()]
