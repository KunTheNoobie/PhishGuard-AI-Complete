"""
PhishGuard-AI — DuitNow QR & EMVCo Quishing Scanner.
=====================================================

Detects and decodes EMVCo-compliant DuitNow QR code payloads (PayNet Standard)
embedded in web pages, transaction strings, and scam links to identify
underlying money-mule accounts and deceptive redirection vectors.

Architecture Layer: Services / Threat Detection
Thesis Reference : §4.6 — Quishing & QR-Based Financial Threat Extraction
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final

import aiosqlite

from database.repository import check_mule_accounts

logger = logging.getLogger(__name__)

# Standard PayNet / DuitNow EMVCo QR Prefix
DUITNOW_QR_HEADER: Final[str] = "000201"
EMVCO_TAG_REGEX: Final[re.Pattern[str]] = re.compile(r"^(\d{2})(\d{2})(.*)$")


def parse_emvco_tlv(payload: str) -> dict[str, str]:
    """Parse a raw EMVCo QR string into a Tag-Length-Value dictionary.

    Format: `[2-digit Tag][2-digit Length][Value]` repeated.
    """
    tlv: dict[str, str] = {}
    idx = 0
    clean = payload.strip()

    while idx < len(clean) - 4:
        tag = clean[idx : idx + 2]
        len_str = clean[idx + 2 : idx + 4]
        if not (tag.isdigit() and len_str.isdigit()):
            break

        length = int(len_str)
        val_start = idx + 4
        val_end = val_start + length
        if val_end > len(clean):
            break

        val = clean[val_start:val_end]
        tlv[tag] = val
        idx = val_end

    return tlv


def extract_duitnow_qr_accounts(raw_text: str) -> list[dict[str, str]]:
    """Scan arbitrary text or DOM content for DuitNow QR payloads or proxy markers.

    Returns a list of extracted proxy identifiers (bank account, phone, or IC).
    """
    extracted: list[dict[str, str]] = []

    # 1. Search for raw EMVCo QR strings (e.g. 00020101021126...)
    emvco_matches = re.findall(r"000201[0-9a-zA-Z\.\-_:/?=&]{10,500}", raw_text)
    for match in emvco_matches:
        tlv = parse_emvco_tlv(match)
        # Check merchant account information tags 26 to 51
        for tag_id in range(26, 52):
            tag_str = f"{tag_id:02d}"
            if tag_str in tlv:
                sub_data = tlv[tag_str]
                # Look for bank accounts or phone numbers inside sub-TLV or raw string
                sub_tlv = parse_emvco_tlv(sub_data)
                for sub_val in sub_tlv.values():
                    clean_val = re.sub(r"[^\d]", "", sub_val)
                    if 10 <= len(clean_val) <= 14:
                        if not any(e["account_number"] == clean_val for e in extracted):
                            extracted.append({
                                "proxy_type": "DuitNow QR / Account",
                                "account_number": clean_val,
                                "raw_qr": match[:30] + "...",
                            })



    # 2. Search for direct QR payload substrings containing DuitNow/PayNet markers
    for proxy_match in re.findall(r"(?:paynet|duitnow)[^0-9]*([0-9]{10,14})", raw_text, re.IGNORECASE):
        if not any(e["account_number"] == proxy_match for e in extracted):
            extracted.append({
                "proxy_type": "DuitNow QR / Payload",
                "account_number": proxy_match,
                "raw_qr": proxy_match,
            })

    # 3. Search for DuitNow deep-link URLs (e.g. https://www.duitnow.my/pay?acc=...)
    duitnow_url_matches = re.findall(
        r"(?:duitnow|paynet)[^\"'\s]*[?&](?:acc|account|proxy|id)=([0-9\-\+]{10,16})",
        raw_text,
        re.IGNORECASE,
    )
    for acc in duitnow_url_matches:
        clean_acc = re.sub(r"[^\d]", "", acc)
        if 10 <= len(clean_acc) <= 14:
            extracted.append({
                "proxy_type": "DuitNow DeepLink",
                "account_number": clean_acc,
                "raw_qr": acc,
            })

    return extracted



async def scan_and_verify_qr(
    raw_text: str,
    db: aiosqlite.Connection,
) -> dict[str, Any]:
    """Inspect text for DuitNow QR quishing payloads and verify against mule registry."""
    found = extract_duitnow_qr_accounts(raw_text)
    if not found:
        return {
            "qr_detected": False,
            "quishing_threat": False,
            "extracted_proxies": [],
            "flagged_accounts": [],
        }

    acc_list = [item["account_number"] for item in found]
    mule_records = await check_mule_accounts(acc_list, db)
    flagged: list[dict[str, Any]] = []

    for mule_record in mule_records:
        flagged.append({
            "account_number": mule_record["account_number"],
            "bank_name": f"{mule_record['bank_name']} (DuitNow QR)",
            "report_count": mule_record.get("report_count", 1),
        })

    return {
        "qr_detected": len(found) > 0,
        "quishing_threat": len(flagged) > 0,
        "extracted_proxies": found,
        "flagged_accounts": flagged,
    }

