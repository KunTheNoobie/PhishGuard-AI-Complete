"""
PhishGuard-AI — Database Schema and Start-up.
==============================================

Three tables in Third Normal Form:

``mule_registry``
    Reported mule accounts.  ``account_number`` is the compact registry key
    (digits only; DuitNow phones in local 01x form) produced by
    ``services.mule_scanner.normalise_account``.

``mule_reports``
    Review queue of user-submitted reports.  A report never blocks anything;
    only an analyst-approved report is promoted into ``mule_registry``.

``scan_log``
    One row per page analysed — from the extension, the dashboard analyser
    or the QR scanner.  The dashboard's counters and recent-scan table are
    computed from this table only; nothing is simulated.  Query strings and
    fragments are never stored.

Architecture Layer : Data Access / Infrastructure
"""

from __future__ import annotations

import logging
from typing import Final

import aiosqlite

from core.config import DATABASE_PATH

logger: Final[logging.Logger] = logging.getLogger("phishguard.database")

_DDL_MULE_REGISTRY: Final[str] = """
CREATE TABLE IF NOT EXISTS mule_registry (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number   TEXT    NOT NULL UNIQUE CHECK (length(account_number) BETWEEN 6 AND 34),
    bank_name        TEXT    NOT NULL,
    platform_flagged TEXT    NOT NULL DEFAULT 'manual entry',
    report_count     INTEGER NOT NULL DEFAULT 1 CHECK (report_count >= 0),
    date_added       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

_DDL_MULE_REPORTS: Final[str] = """
CREATE TABLE IF NOT EXISTS mule_reports (
    report_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT    NOT NULL CHECK (length(account_number) BETWEEN 6 AND 34),
    bank_name      TEXT    NOT NULL DEFAULT 'Unknown',
    source         TEXT    NOT NULL DEFAULT 'extension',
    page_url       TEXT,
    status         TEXT    NOT NULL DEFAULT 'PENDING'
                           CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    registry_id    INTEGER REFERENCES mule_registry (id) ON DELETE SET NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    reviewed_at    TEXT
);
"""

_DDL_SCAN_LOG: Final[str] = """
CREATE TABLE IF NOT EXISTS scan_log (
    scan_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    source      TEXT    NOT NULL CHECK (source IN ('extension', 'dashboard', 'qr', 'api')),
    url         TEXT    NOT NULL,
    hostname    TEXT    NOT NULL,
    scheme      TEXT    NOT NULL,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('SAFE', 'WARNING', 'BLOCK_RENDER')),
    rule        TEXT,
    risk_score  REAL    NOT NULL CHECK (risk_score BETWEEN 0.0 AND 1.0),
    bert_score  REAL             CHECK (bert_score IS NULL OR bert_score BETWEEN 0.0 AND 1.0),
    headline    TEXT    NOT NULL,
    latency_ms  REAL    NOT NULL
);
"""

SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    _DDL_MULE_REGISTRY,
    _DDL_MULE_REPORTS,
    _DDL_SCAN_LOG,
    "CREATE INDEX IF NOT EXISTS idx_mule_reports_status ON mule_reports (status, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_mule_reports_registry_id ON mule_reports (registry_id);",
    "CREATE INDEX IF NOT EXISTS idx_scan_log_created ON scan_log (created_at);",
    "CREATE INDEX IF NOT EXISTS idx_scan_log_verdict ON scan_log (verdict, created_at);",
    # Superseded by scan_log; dropping it also removes the simulated rows that
    # earlier versions seeded for the dashboard.
    "DROP TABLE IF EXISTS threat_telemetry;",
    # Registry keys written by older versions with spaces or hyphens.
    "UPDATE OR IGNORE mule_registry SET account_number = replace(replace(account_number, '-', ''), ' ', '') "
    "WHERE account_number GLOB '*[- ]*';",
)

# Demonstration registry.  PDRM's Semakmule service has no public API, so the
# registry starts with these sample accounts and grows through analyst-
# approved reports and the dashboard's "Add account" form.
SEED_MULE_ACCOUNTS: Final[list[tuple[str, str, str, int]]] = [
    ("112233445566", "Maybank", "Shopee", 14),
    ("564738291012", "Maybank", "Facebook Marketplace", 8),
    ("156789012345", "Maybank", "Mudah.my", 22),
    ("76001234567890", "CIMB Bank", "WhatsApp", 7),
    ("70009876543210", "CIMB Bank", "Carousell", 5),
    ("3112233445", "Public Bank", "Telegram", 3),
    ("3998877665", "Public Bank", "Lazada", 11),
    ("3567891234", "Public Bank", "Shopee", 17),
    ("21234567890123", "RHB Bank", "Mudah.my", 6),
    ("234567890123", "Hong Leong Bank", "Facebook Marketplace", 9),
    ("012345678901", "Hong Leong Bank", "WhatsApp", 2),
    ("8123456789012", "AmBank", "Shopee", 4),
    ("14001234567890", "Bank Islam", "Telegram", 10),
    ("212345678901", "Bank Rakyat", "Carousell", 13),
    ("012345678912", "Bank Rakyat", "Lazada", 1),
    ("0123456789", "DuitNow phone", "WhatsApp", 19),
    ("0198765432", "DuitNow phone", "Telegram", 15),
    ("980102145678", "DuitNow ID (NRIC)", "Facebook Marketplace", 8),
]

INSERT_SEED: Final[str] = (
    "INSERT OR IGNORE INTO mule_registry (account_number, bank_name, platform_flagged, report_count) "
    "VALUES (?, ?, ?, ?);"
)


async def apply_schema(db: aiosqlite.Connection) -> None:
    """Create tables and indexes, and load the demonstration registry."""
    await db.execute("PRAGMA foreign_keys=ON;")
    for statement in SCHEMA_STATEMENTS:
        await db.execute(statement)
    for account in SEED_MULE_ACCOUNTS:
        await db.execute(INSERT_SEED, account)
    await db.commit()


async def initialize_database(path: str = DATABASE_PATH) -> aiosqlite.Connection:
    """Open the SQLite database in WAL mode and apply the schema."""
    logger.info("Initialising database at '%s' …", path)
    db = await aiosqlite.connect(path)
    await db.execute("PRAGMA journal_mode=WAL;")
    await apply_schema(db)
    cursor = await db.execute("SELECT COUNT(*) FROM mule_registry;")
    (count,) = await cursor.fetchone()
    logger.info("Database ready — %d registry accounts.", count)
    return db
