"""
PhishGuard-AI — Mule Account Scanner.
======================================

Finds Malaysian bank-account numbers, DuitNow phone numbers and NRIC proxies
in page text and checks them against the mule registry.

Account numbers are written in many ways on scam pages, so every candidate
is reduced to a *compact* digit string before it is matched:

    "514276103388"      contiguous
    "5142 7610 3388"    space-grouped
    "5142-7610-3388"    hyphen-grouped
    "+60 12-345 6789"   DuitNow phone (normalised to 0123456789)
    "980102-14-5678"    NRIC (normalised to 980102145678)

A candidate is reported when its compact form is 10–16 digits.  The bank is
guessed from the issuer's account format; the registry lookup is exact on
the compact form, so a bank guess never causes a block on its own.

Architecture Layer : Service / Detection
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final

import aiosqlite

from core.config import (
    ACCOUNT_MAX_DIGITS,
    ACCOUNT_MIN_DIGITS,
    DUITNOW_PHONE_PATTERN,
    MALAYSIAN_IC_PATTERN,
    MULE_ACCOUNT_PATTERNS,
)
from database.repository import check_mule_accounts
from services.qr_payload import extract_duitnow_accounts

logger: Final[logging.Logger] = logging.getLogger("phishguard.mule_scanner")

# Digit runs, optionally split into 2–6 digit groups by single spaces,
# hyphens or dots, optionally with a leading "+".
_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w+.\-])(\+?\d{2,16}(?:[ .\-]\d{2,8}){0,5})(?![\w]|[.\-]\d)"
)
_PHONE_RE: Final[re.Pattern[str]] = re.compile(rf"^{DUITNOW_PHONE_PATTERN}$")
_IC_RE: Final[re.Pattern[str]] = re.compile(rf"^{MALAYSIAN_IC_PATTERN}$")
_BANK_RES: Final[dict[str, re.Pattern[str]]] = {
    bank: re.compile(rf"^{pattern}$") for bank, pattern in MULE_ACCOUNT_PATTERNS.items()
}


def _luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def normalise_account(raw: str) -> str:
    """Return the compact registry key of an account / phone / ID string."""
    digits = re.sub(r"\D", "", raw or "")
    # +60 12-345 6789 → 0123456789 (DuitNow phone proxies are stored locally formatted)
    if digits.startswith("601") and 11 <= len(digits) <= 12:
        digits = digits[1:]
    return digits


def classify_account(compact: str, raw: str = "") -> str:
    """Best-effort issuer / proxy type of a compact account string."""
    if _IC_RE.match(raw.strip()) and "-" in raw:
        return "DuitNow ID (NRIC)"
    if _PHONE_RE.match(compact):
        return "DuitNow phone"
    for bank, pattern in _BANK_RES.items():
        if pattern.match(compact):
            return bank
    return "Unknown bank"


def extract_accounts(text: str) -> list[dict[str, str]]:
    """Return every distinct account-like number in ``text``."""
    found: dict[str, dict[str, str]] = {}
    for match in _CANDIDATE_RE.finditer(text or ""):
        raw = match.group(1)
        separators = set(re.sub(r"[\d+]", "", raw))
        compact = normalise_account(raw)
        if not ACCOUNT_MIN_DIGITS <= len(compact) <= ACCOUNT_MAX_DIGITS:
            continue
        # Mixed separators ("12 34-56") only make sense for a phone number.
        if len(separators) > 1 and not _PHONE_RE.match(compact):
            continue
        if separators == {"."} and raw.count(".") < 2:
            continue                          # "1234.56" is an amount, not an account
        if len(compact) == 16 and _luhn_valid(compact):
            continue                          # a payment-card number, not a bank account
        found.setdefault(compact, {
            "account_number": compact,
            "as_written": raw,
            "account_type": classify_account(compact, raw),
        })
    for proxy in extract_duitnow_accounts(text or ""):
        compact = normalise_account(proxy["account_number"])
        found.setdefault(compact, {
            "account_number": compact,
            "as_written": proxy["account_number"],
            "account_type": proxy["source"],
        })
    return list(found.values())


class MuleScanner:
    """Extracts account numbers from page text and checks the mule registry."""

    async def scan_and_verify(self, text: str, db: aiosqlite.Connection) -> dict[str, Any]:
        """Extract candidates and return those found in ``mule_registry``."""
        extracted = extract_accounts(text)
        flagged = await check_mule_accounts([e["account_number"] for e in extracted], db)
        if flagged:
            logger.warning("Mule registry match: %s", [f["account_number"] for f in flagged])
        return {
            "accounts_extracted": [e["account_number"] for e in extracted],
            "extracted_details": extracted,
            "flagged_accounts": flagged,
            "mule_detected": bool(flagged),
        }
