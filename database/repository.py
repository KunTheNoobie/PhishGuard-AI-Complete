"""
PhishGuard-AI — Database Repository Module.
=============================================

Houses the async data-access methods consumed by the service layer.
Each method receives an ``aiosqlite.Connection`` via dependency injection,
ensuring the repository itself remains stateless and testable.

Architecture Layer : Data-Access / Repository Pattern
Thesis Reference   : §5.2 — Asynchronous Persistence Operations
"""

from __future__ import annotations

import logging
from typing import Any, Final

import aiosqlite

logger: Final[logging.Logger] = logging.getLogger("phishguard.repository")


# ==============================================================================
# 1. Mule-Account Lookup
# ==============================================================================

async def check_mule_accounts(
    account_list: list[str],
    db: aiosqlite.Connection,
) -> list[dict[str, Any]]:
    """Cross-reference extracted account numbers against the mule registry.

    Uses a parameterized ``IN`` clause constructed with positional
    placeholders to prevent SQL injection — **never** string-interpolated.

    Parameters
    ----------
    account_list : list[str]
        Account numbers extracted from the sanitized DOM text.
    db : aiosqlite.Connection
        Active database connection (injected).

    Returns
    -------
    list[dict[str, Any]]
        Each dict contains ``account_number``, ``bank_name``, and
        ``report_count`` for every match found in the registry.
    """
    if not account_list:
        return []

    # Build parameterized placeholder string: "?, ?, ?"
    placeholders: str = ", ".join("?" for _ in account_list)
    query: str = (
        f"SELECT account_number, bank_name, report_count "
        f"FROM mule_registry "
        f"WHERE account_number IN ({placeholders});"
    )

    logger.debug(
        "Querying mule_registry for %d account(s): %s",
        len(account_list),
        account_list,
    )

    cursor: aiosqlite.Cursor = await db.execute(query, account_list)
    rows: list[aiosqlite.Row] = await cursor.fetchall()

    flagged: list[dict[str, Any]] = [
        {
            "account_number": row[0],
            "bank_name": row[1],
            "report_count": row[2],
        }
        for row in rows
    ]

    if flagged:
        logger.warning(
            "MULE ALERT — %d flagged account(s) detected: %s",
            len(flagged),
            [f["account_number"] for f in flagged],
        )

    return flagged


# ==============================================================================
# 2. Threat Telemetry Logging
# ==============================================================================

async def log_threat_telemetry(
    url: str,
    score: float,
    db: aiosqlite.Connection,
) -> None:
    """Persist a malicious-URL detection event to the telemetry table.

    This method is designed to be invoked as a **background task** via
    ``BackgroundTasks`` so that response latency is not penalized by the
    write I/O.

    Parameters
    ----------
    url : str
        The URL flagged as malicious by the BERT pipeline.
    score : float
        The BERT confidence score associated with the malicious
        classification.
    db : aiosqlite.Connection
        Active database connection (injected).
    """
    insert_sql: str = (
        "INSERT INTO threat_telemetry (malicious_url, bert_score) "
        "VALUES (?, ?);"
    )

    await db.execute(insert_sql, (url, score))
    await db.commit()

    logger.info(
        "TELEMETRY — Logged malicious URL '%s' (score=%.4f).",
        url,
        score,
    )


# ==============================================================================
# 3. Mule-Account Management (CRUD)
# ==============================================================================

async def add_mule_account(
    account_number: str,
    bank_name: str,
    platform_flagged: str,
    report_count: int,
    db: aiosqlite.Connection,
) -> dict[str, Any]:
    """Insert or update a mule account record in the registry."""
    query = """
    INSERT INTO mule_registry (account_number, bank_name, platform_flagged, report_count)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(account_number) DO UPDATE SET
        report_count = report_count + excluded.report_count,
        bank_name = excluded.bank_name,
        platform_flagged = excluded.platform_flagged;
    """
    await db.execute(
        query,
        (account_number.strip(), bank_name.strip(), platform_flagged.strip(), max(1, report_count)),
    )
    await db.commit()

    cursor = await db.execute(
        "SELECT id, account_number, bank_name, platform_flagged, report_count, date_added "
        "FROM mule_registry WHERE account_number = ?;",
        (account_number.strip(),),
    )
    row = await cursor.fetchone()
    return {
        "id": row[0],
        "account_number": row[1],
        "bank_name": row[2],
        "platform_flagged": row[3],
        "report_count": row[4],
        "date_added": row[5],
    }


async def delete_mule_account(
    mule_id: int,
    db: aiosqlite.Connection,
) -> bool:
    """Delete a mule account record by ID."""
    cursor = await db.execute(
        "DELETE FROM mule_registry WHERE id = ?;",
        (mule_id,),
    )
    await db.commit()
    return cursor.rowcount > 0

