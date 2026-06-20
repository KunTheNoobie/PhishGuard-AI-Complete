"""
PhishGuard-AI — Mule Account Scanner Service.
===============================================

Detects Malaysian bank account numbers embedded in web-page text using
**bank-specific** pre-compiled regular expressions, then cross-references
any matches against the ``mule_registry`` table via the repository layer.

Each major Malaysian bank has a distinct account-number format (digit
count and leading-digit convention).  By compiling a targeted pattern per
bank at startup, the scanner significantly reduces false-positive matches
compared to a single generic ``\\d{10,14}`` expression.

A generic fallback pattern (``\\b\\d{10,14}\\b``) is still applied last to
catch account formats from unlisted financial institutions.

Architecture Layer : Service / Detection
Thesis Reference   : §4.4 — Mule Account Pattern Matching & Registry Lookup
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final

import aiosqlite

from core.config import MULE_ACCOUNT_PATTERNS, MULE_ACCOUNT_REGEX
from database.repository import check_mule_accounts

logger: Final[logging.Logger] = logging.getLogger("phishguard.mule_scanner")


class MuleScanner:
    """Pre-compiled bank-specific regex scanner + mule-registry cross-referencer.

    Instantiated **once** during the FastAPI ``lifespan`` and stored in
    ``app.state``.  All compiled patterns are reused across requests
    (zero recompilation overhead).
    """

    def __init__(self) -> None:
        """Compile bank-specific and generic account-number regex patterns."""
        # ── Bank-specific compiled patterns ──
        self._bank_patterns: Final[dict[str, re.Pattern[str]]] = {
            bank: re.compile(pattern)
            for bank, pattern in MULE_ACCOUNT_PATTERNS.items()
        }

        # ── Generic fallback pattern ──
        self._generic_pattern: Final[re.Pattern[str]] = re.compile(
            MULE_ACCOUNT_REGEX
        )

        logger.info(
            "MuleScanner initialised — %d bank-specific patterns + 1 generic fallback.",
            len(self._bank_patterns),
        )

    async def scan_and_verify(
        self,
        text: str,
        db: aiosqlite.Connection,
    ) -> dict[str, Any]:
        """Extract account numbers from text and verify against the registry.

        Pipeline
        --------
        1. Iterate through all bank-specific compiled regex patterns and
           extract candidate account numbers, tagging each with the
           suspected bank name.
        2. Apply the generic fallback pattern to capture any remaining
           10–14 digit sequences not already matched.
        3. Deduplicate the combined matches.
        4. Delegate to ``repository.check_mule_accounts()`` for DB lookup.
        5. Return a structured result dict consumed by the response schema.

        Parameters
        ----------
        text : str
            Sanitized plaintext (post-ETL).
        db : aiosqlite.Connection
            Active database connection (injected via ``app.state``).

        Returns
        -------
        dict[str, Any]
            Keys: ``accounts_extracted``, ``flagged_accounts``,
            ``mule_detected``.
        """
        # ── 1. Bank-specific regex extraction ──
        all_matches: set[str] = set()

        for bank_name, pattern in self._bank_patterns.items():
            bank_matches: list[str] = pattern.findall(text)
            if bank_matches:
                logger.debug(
                    "Regex [%s] extracted %d match(es): %s",
                    bank_name,
                    len(bank_matches),
                    bank_matches,
                )
                all_matches.update(bank_matches)

        # ── 2. Generic fallback for unmatched formats ──
        generic_matches: list[str] = self._generic_pattern.findall(text)
        new_generic = set(generic_matches) - all_matches
        if new_generic:
            logger.debug(
                "Generic fallback extracted %d additional match(es): %s",
                len(new_generic),
                sorted(new_generic),
            )
            all_matches.update(new_generic)

        unique_accounts: list[str] = sorted(all_matches)

        logger.debug(
            "Total unique account(s) extracted: %d",
            len(unique_accounts),
        )

        # ── 3. Registry lookup ──
        flagged: list[dict[str, Any]] = await check_mule_accounts(
            unique_accounts, db
        )

        mule_detected: bool = len(flagged) > 0

        if mule_detected:
            logger.warning(
                "MULE SCAN — %d flagged account(s) in page text.",
                len(flagged),
            )
        else:
            logger.info("MULE SCAN — No flagged accounts detected.")

        return {
            "accounts_extracted": unique_accounts,
            "flagged_accounts": flagged,
            "mule_detected": mule_detected,
        }
