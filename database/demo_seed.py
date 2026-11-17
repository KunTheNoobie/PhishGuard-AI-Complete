"""
Demonstration dataset for an empty database (database/demo_threat_intel.json).

Loaded once at start-up so the dashboard is never empty during a presentation:
45 curated mule-account records, 30 recent scan-log rows (real pipeline verdicts for
OpenPhish feed URLs, public test sites, a mule page and a QR code) and four pending reports.
Set PHISHGUARD_SEED_DEMO=false to disable.  Rows are ordinary rows: the dashboard shows
them like any other, and they can be deleted from the Mule Registry tab.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

import aiosqlite

from database.init_db import INSERT_SEED
from database.repository import create_mule_report

logger: Final[logging.Logger] = logging.getLogger("phishguard.demo_seed")
DATA_FILE: Final[Path] = Path(__file__).with_name("demo_threat_intel.json")

_PENDING_REPORTS: Final[list[tuple[str, str, str]]] = [
    ("5142761033881", "Maybank", "https://secure-parcel-pay.top/track"),
    ("8001234567", "CIMB Bank", "https://carousell-buyer-protect.cc/pay"),
    ("1100223344", "Public Bank", "https://shopee-refund-claim.top/"),
    ("112233445577", "Maybank", "https://lazada-winner-gift.xyz/claim"),
]


async def seed_demo_data(db: aiosqlite.Connection) -> bool:
    """Fill an empty scan_log; returns True when rows were added."""
    if os.getenv("PHISHGUARD_SEED_DEMO", "true").lower() in ("0", "false", "no") or not DATA_FILE.exists():
        return False
    (count,) = await (await db.execute("SELECT COUNT(*) FROM scan_log;")).fetchone()
    if count:
        return False
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    for account in data["mule_accounts"]:
        await db.execute(INSERT_SEED, account)
    now = datetime.now(timezone.utc)
    scans = data["scans"]
    for i, s in enumerate(scans):
        stamp = (now - timedelta(minutes=7 + i * 53 + (i * 17) % 40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        parts = s["url"].split("/")
        host = parts[2].split("@")[-1] if len(parts) > 2 else s["url"]
        await db.execute(
            "INSERT INTO scan_log (created_at, source, url, hostname, scheme, verdict, rule, risk_score, bert_score, headline, latency_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (stamp, s["source"], s["url"][:2048], host[:255], s["url"].split(":")[0], s["verdict"], s["rule"], s["risk_score"],
             s["bert_score"], s["headline"][:200], s["latency_ms"]),
        )
    await db.commit()
    for number, bank, url in _PENDING_REPORTS:
        await create_mule_report(number, bank, "extension", url, db)
    logger.info("Demonstration dataset loaded: %d scans, %d mule accounts", len(scans), len(data["mule_accounts"]))
    return True
