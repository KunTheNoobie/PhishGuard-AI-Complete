"""
PhishGuard-AI — Mule Account Scanner Service.
===============================================

Detects Malaysian bank account numbers embedded in web-page text using
a pre-compiled regular expression, then cross-references any matches
against the ``mule_registry`` table via the repository layer.

The regex ``\\b\\d{10,14}\\b`` targets the standard 10–14 digit format
used by major Malaysian banks (Maybank, CIMB, Public Bank, RHB, etc.).

Architecture Layer : Service / Detection
Thesis Reference   : §4.4 — Mule Account Pattern Matching & Registry Lookup
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final

import aiosqlite

from core.config import MULE_ACCOUNT_REGEX
from database.repository import check_mule_accounts

logger: Final[logging.Logger] = logging.getLogger("phishguard.mule_scanner")


class MuleScanner:
    """Pre-compiled regex scanner + mule-registry cross-referencer.

    Instantiated **once** during the FastAPI ``lifespan`` and stored in
    ``app.state``.  The compiled pattern is reused across all requests
    (zero recompilation overhead).
    """

    def __init__(self) -> None:
        """Compile the account-number regex at construction time."""
        self._pattern: Final[re.Pattern[str]] = re.compile(MULE_ACCOUNT_REGEX)
        logger.info(
            "MuleScanner initialised — pattern: %s",
            self._pattern.pattern,
        )

    async def scan_and_verify(
        self,
        text: str,
        db: aiosqlite.Connection,
    ) -> dict[str, Any]:
        """Extract account numbers from text and verify against the registry.

        Pipeline
        --------
        1. Apply the compiled regex to extract all candidate account numbers.
        2. Deduplicate the matches (``set`` → ``sorted list``).
        3. Delegate to ``repository.check_mule_accounts()`` for DB lookup.
        4. Return a structured result dict consumed by the response schema.

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
        # ── 1. Regex extraction ──
        raw_matches: list[str] = self._pattern.findall(text)
        unique_accounts: list[str] = sorted(set(raw_matches))

        logger.debug(
            "Regex extracted %d raw match(es), %d unique account(s).",
            len(raw_matches),
            len(unique_accounts),
        )

        # ── 2. Registry lookup ──
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
