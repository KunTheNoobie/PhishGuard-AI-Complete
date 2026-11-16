"""
PhishGuard-AI — Shared Rate Limiter.
=====================================

A single SlowAPI ``Limiter`` instance shared by every router, keyed on the
client IP address.  Routes opt in with ``@limiter.limit(...)``:

* analysis and report endpoints use ``RATE_LIMIT`` (default 60/minute);
* the dashboard login endpoint uses ``LOGIN_RATE_LIMIT`` (5/minute) to slow
  down online guessing of the administrative key.

Architecture Layer : Cross-Cutting / Abuse Protection
"""

from __future__ import annotations

from typing import Final

from slowapi import Limiter  # type: ignore[import-untyped]
from slowapi.util import get_remote_address  # type: ignore[import-untyped]

from core.config import RATE_LIMIT

LOGIN_RATE_LIMIT: Final[str] = "5/minute"

limiter: Final[Limiter] = Limiter(
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://",
)
