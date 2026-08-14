"""
PhishGuard-AI — STIX 2.1 Cyber Threat Intelligence (CTI) Exporter.
===================================================================

Generates OASIS STIX 2.1 compliant Threat Intelligence Bundles from active
telemetry and mule account registries for ingestion by SIEM, SOAR, and CERT systems.

Architecture Layer: Services / Threat Intelligence Sharing
Thesis Reference : §5.5 — Standardized CTI Interoperability & STIX 2.1 Export
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

import aiosqlite


def generate_stix_id(stix_type: str) -> str:
    """Generate a valid STIX 2.1 UUID identifier."""
    return f"{stix_type}--{uuid.uuid4()}"


def format_stix_timestamp(ts_str: str | None = None) -> str:
    """Format an ISO 8601 timestamp conforming to STIX 2.1 requirements."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def generate_stix_bundle(db: aiosqlite.Connection) -> dict[str, Any]:
    """Compile telemetry threats and mule accounts into a standard STIX 2.1 bundle."""
    created_time = format_stix_timestamp()
    identity_id = "identity--a1b2c3d4-e5f6-47a8-9b0c-1d2e3f4a5b6c"

    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": created_time,
            "modified": created_time,
            "name": "PhishGuard-AI Threat Intelligence Center",
            "identity_class": "system",
            "sectors": ["financial-services", "government"],
            "contact_information": "soc@phishguard-ai.internal",
        }
    ]

    # 1. Fetch malicious URL telemetry
    cursor = await db.execute(
        "SELECT log_id, malicious_url, bert_score, timestamp FROM threat_telemetry ORDER BY log_id DESC LIMIT 50;"
    )
    rows = await cursor.fetchall()
    for row in rows:
        url = row[1]
        score = float(row[2])
        indicator_id = generate_stix_id("indicator")

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": created_time,
            "modified": created_time,
            "name": f"Malicious Financial Phishing URL: {url[:50]}",
            "description": f"URL detected with {score*100:.1f}% confidence by PhishGuard-AI BERT Semantic Engine.",
            "indicator_types": ["malicious-activity", "phishing"],
            "pattern_type": "stix",
            "pattern": f"[url:value = '{url}']",
            "valid_from": created_time,
            "confidence": int(score * 100),
            "created_by_ref": identity_id,
            "labels": ["financial-phishing", "malaysia-banking"],
        })

    # 2. Fetch mule accounts
    mule_cursor = await db.execute(
        "SELECT account_number, bank_name, platform_flagged, report_count FROM mule_registry ORDER BY report_count DESC LIMIT 50;"
    )
    mule_rows = await mule_cursor.fetchall()
    for mule in mule_rows:
        acc = mule[0]
        bank = mule[1]
        platform = mule[2]
        reports = mule[3]
        obs_id = generate_stix_id("observed-data")

        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created": created_time,
            "modified": created_time,
            "first_observed": created_time,
            "last_observed": created_time,
            "number_observed": reports,
            "created_by_ref": identity_id,
            "custom_properties": {
                "x_mule_account_number": acc,
                "x_target_bank": bank,
                "x_flagged_platform": platform,
            },
        })

    return {
        "type": "bundle",
        "id": generate_stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }
