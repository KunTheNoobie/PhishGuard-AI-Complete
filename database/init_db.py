"""
PhishGuard-AI — Database Initialization Module.
=================================================

Responsible for DDL execution (table creation) and seed-data insertion
during the application's ``lifespan`` cold-start.  All tables conform to
Third Normal Form (3NF) as mandated by the thesis.

Architecture Layer : Data-Access / Repository (Infrastructure)
Thesis Reference   : §5.1 — Persistence Schema Design (3NF)

Tables
------
``mule_registry``
    Stores known mule (money-mule) bank accounts reported across
    Malaysian financial institutions.

``threat_telemetry``
    Append-only log of every malicious URL detected by the BERT pipeline,
    used for post-incident forensics and threat-intelligence dashboards.
"""

from __future__ import annotations

import logging
from typing import Final

import aiosqlite

from core.config import DATABASE_PATH

logger: Final[logging.Logger] = logging.getLogger("phishguard.database")

# ==============================================================================
# DDL — Table Definitions (3NF)
# ==============================================================================

_DDL_MULE_REGISTRY: Final[str] = """
CREATE TABLE IF NOT EXISTS mule_registry (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number   TEXT    NOT NULL UNIQUE,
    bank_name        TEXT    NOT NULL,
    platform_flagged TEXT    NOT NULL DEFAULT 'manual_entry',
    report_count     INTEGER NOT NULL DEFAULT 1 CHECK (report_count >= 0),
    date_added       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

_DDL_THREAT_TELEMETRY: Final[str] = """
CREATE TABLE IF NOT EXISTS threat_telemetry (
    log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    malicious_url TEXT    NOT NULL,
    bert_score    REAL   NOT NULL CHECK (bert_score >= 0.0 AND bert_score <= 1.0),
    timestamp     TEXT   NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# ── Explicit B-Tree Indexes (§4.4) ──
# SQLite's UNIQUE constraint on account_number creates an implicit index,
# but we declare it explicitly for clarity and to align with the thesis.
# The malicious_url index accelerates threat-intelligence lookups.
_IDX_MULE_ACCOUNT: Final[str] = """
CREATE INDEX IF NOT EXISTS idx_mule_account_number
    ON mule_registry (account_number);
"""

_IDX_TELEMETRY_URL: Final[str] = """
CREATE INDEX IF NOT EXISTS idx_telemetry_malicious_url
    ON threat_telemetry (malicious_url);
"""

# ==============================================================================
# Seed Data — Initial Threat Intel Feed
# ==============================================================================
# Initial mock mule accounts loaded for development & integration
# testing. In production, this syncs with PDRM / BNM threat feeds.
_SEED_MULE_ACCOUNTS: Final[list[tuple[str, str, str, int]]] = [
    ("112233445566", "Maybank", "Shopee", 14),
    ("564738291012", "Maybank", "Facebook Marketplace", 8),
    ("76001234567890", "CIMB Bank", "WhatsApp", 7),
    ("70009876543210", "CIMB Bank", "Carousell", 5),
    ("3112233445", "Public Bank", "Telegram", 3),
    ("3998877665", "Public Bank", "Lazada", 11),
    ("21234567890123", "RHB Bank", "Mudah.my", 6),
    ("012345678901", "Hong Leong Bank", "WhatsApp", 2),
    ("234567890123", "Hong Leong Bank", "Facebook Marketplace", 9),
    ("8123456789012", "AmBank", "Shopee", 4),
    ("14001234567890", "Bank Islam", "Telegram", 10),
    ("012345678912", "Bank Rakyat", "Lazada", 1),
    ("212345678901", "Bank Rakyat", "Carousell", 13),
    ("156789012345", "Maybank", "Mudah.my", 22),
    ("3567891234", "Public Bank", "Shopee", 17),
    ("0123456789", "DuitNow (Maybank)", "WhatsApp Scam", 19),
    ("0198765432", "DuitNow (CIMB)", "Telegram Scam", 15),
    ("980102-14-5678", "DuitNow (NRIC)", "Facebook Marketplace", 8),
]

_SEED_THREAT_TELEMETRY: Final[list[tuple[str, float]]] = [
    # Maybank
    ("http://maybznk2u.com.my/auth/login", 0.985),
    ("http://maybank2u-secure-login.top/verify", 0.962),
    ("http://mae-verify-otp.net/update", 0.941),
    ("http://maybank-ccid-update.com/login", 0.978),
    ("http://maybank2u-account-safety.org/auth", 0.953),
    ("http://maybank-tac-portal.net/sms", 0.932),
    # CIMB Bank
    ("http://secure-login-cimb.com/clicks", 0.976),
    ("http://cimb-clicks-secure.com/auth", 0.954),
    ("http://cimb-security-gateway.net/update", 0.923),
    ("http://cimbclicks-auth.top/login", 0.967),
    ("http://cimb-online-verify.net/tac", 0.945),
    ("http://cimb-portal-alerts.org/auth", 0.912),
    # Public Bank
    ("http://pbebank-update-info.net/login", 0.981),
    ("http://pbb-online-auth.top/verify", 0.963),
    ("http://publicbank-ebank.com/auth", 0.947),
    ("http://pbe-secure-portal.org/login", 0.958),
    ("http://pbb-secure-alert.top/verify", 0.934),
    ("http://publicbank-pac-token.net/auth", 0.972),
    # RHB Bank
    ("http://rhb-online-verify.net/auth", 0.952),
    ("http://rhbgroup-secure-auth.top/login", 0.944),
    ("http://rhbnow-login-gateway.com/verify", 0.968),
    ("http://rhb-ebank-portal.net/update", 0.935),
    ("http://rhbnow-otp-token.top/auth", 0.961),
    ("http://rhb-security-center.org/login", 0.927),
    # Hong Leong Bank
    ("http://hlb-connect-secure.com/auth", 0.957),
    ("http://hongleong-auth-verify.top/login", 0.964),
    ("http://hlbb-portal-update.net/verify", 0.938),
    ("http://hlb-connect-online.org/auth", 0.949),
    ("http://hongleong-security-gateway.top/login", 0.971),
    ("http://hlb-tac-verify.net/auth", 0.922),
    # AmBank
    ("http://ambank-amonline-secure.top/auth", 0.963),
    ("http://amonline-verify-auth.com/login", 0.951),
    ("http://ambankgroup-portal.net/update", 0.937),
    ("http://ambank-security-check.org/auth", 0.946),
    ("http://amonline-gateway.top/login", 0.974),
    ("http://ambank-tac-online.net/verify", 0.928),
    # Bank Islam
    ("http://bankislam-internet-auth.com/login", 0.969),
    ("http://bimb-portal-verify.top/auth", 0.955),
    ("http://bankislam-secure-login.net/update", 0.942),
    ("http://bankislam-online-token.org/auth", 0.961),
    ("http://bimb-security-center.top/login", 0.934),
    ("http://bankislam-tac-sms.net/verify", 0.948),
    # Touch 'n Go eWallet
    ("http://tng-digital-claim-bonus.net/claim", 0.973),
    ("http://touchngo-ewallet-auth.top/verify", 0.965),
    ("http://tng-wallet-verify.com/login", 0.952),
    ("http://tngdigital-voucher-claim.org/auth", 0.944),
    ("http://touchngo-security-update.top/claim", 0.982),
    ("http://tng-pin-reset-portal.net/auth", 0.939),
    # GrabPay Malaysia
    ("http://grabpay-reward-verification.top/claim", 0.958),
    ("http://grab-malaysia-bonus.net/auth", 0.947),
    ("http://grabpay-auth-login.com/verify", 0.966),
    ("http://grab-voucher-rebate.org/claim", 0.938),
    ("http://grabpay-security-alert.top/auth", 0.971),
    ("http://grab-driver-merchant.net/login", 0.925),
    # ShopeePay
    ("http://shopeepay-voucher-claim.net/claim", 0.977),
    ("http://shopee-free-gifts.net/login", 0.962),
    ("http://shopeepay-verify-portal.top/auth", 0.953),
    ("http://shopee-coin-rewards.org/claim", 0.941),
    ("http://shopeepay-security-update.top/login", 0.968),
    ("http://shopee-lucky-draw.net/auth", 0.936),
]

_INSERT_SEED: Final[str] = """
INSERT OR IGNORE INTO mule_registry
    (account_number, bank_name, platform_flagged, report_count)
VALUES
    (?, ?, ?, ?);
"""

_INSERT_TELEMETRY_SEED: Final[str] = """
INSERT INTO threat_telemetry
    (malicious_url, bert_score)
VALUES
    (?, ?);
"""


# ==============================================================================
# Public API
# ==============================================================================

async def initialize_database() -> aiosqlite.Connection:
    """Create (or open) the SQLite database, execute DDL, and seed data."""
    logger.info("Initializing database at '%s' …", DATABASE_PATH)

    db: aiosqlite.Connection = await aiosqlite.connect(DATABASE_PATH)

    # ── Enable WAL mode for concurrent readers + single writer ──
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA foreign_keys=ON;")

    # ── DDL: Create tables idempotently ──
    await db.execute(_DDL_MULE_REGISTRY)
    await db.execute(_DDL_THREAT_TELEMETRY)

    # ── Create B-Tree indexes for O(log N) lookups (§4.4) ──
    await db.execute(_IDX_MULE_ACCOUNT)
    await db.execute(_IDX_TELEMETRY_URL)

    # ── Seed: Insert initial threat intel (ignored on conflict) ──
    for account in _SEED_MULE_ACCOUNTS:
        await db.execute(_INSERT_SEED, account)

    # ── Seed: Insert initial telemetry if table is fresh ──
    cursor = await db.execute("SELECT COUNT(*) FROM threat_telemetry;")
    count_row = await cursor.fetchone()
    count = count_row[0] if count_row else 0
    if count < len(_SEED_THREAT_TELEMETRY):
        for threat in _SEED_THREAT_TELEMETRY:
            await db.execute(_INSERT_TELEMETRY_SEED, threat)

    await db.commit()

    logger.info(
        "Database ready — %d mule accounts and %d telemetry records verified.",
        len(_SEED_MULE_ACCOUNTS),
        len(_SEED_THREAT_TELEMETRY),
    )
    return db
