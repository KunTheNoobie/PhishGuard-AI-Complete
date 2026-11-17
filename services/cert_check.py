"""
Backend certificate check: a fallback for browsers that remember a "Proceed (unsafe)" click.

Once a user proceeds past the browser's red warning, the browser keeps the exception and never reports the
certificate error again, so the extension cannot see it. For an https address that is not trusted and looks
suspicious, the server therefore opens one TLS connection itself and verifies the certificate against the
system trust store. The answer is cached for five minutes. Only public addresses are contacted (same rule as
the page fetcher), with a two-second limit.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import Final

from services.page_fetcher import FetchBlocked, _assert_public

TTL_SECONDS: Final[float] = 300.0
TIMEOUT_SECONDS: Final[float] = 2.0
_cache: dict[tuple[str, int], tuple[float, str | None]] = {}


def _verify(host: str, port: int) -> str | None:
    """Return a short problem description, or None when the certificate is valid."""
    try:
        import certifi  # the same CA bundle the page fetcher (httpx) trusts, independent of the operating system

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return None
    except ssl.SSLCertVerificationError as exc:
        return f"certificate verification failed: {exc.verify_message or exc.reason}"
    except ssl.SSLError as exc:
        return f"TLS error: {exc.reason or exc}"
    except OSError:
        return None  # not reachable within the limit: no evidence of a bad certificate


async def check_certificate(host: str, port: int = 443) -> str | None:
    """Verify the certificate of ``host`` (cached for five minutes); None means valid or unknown."""
    key = (host.lower(), port)
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < TTL_SECONDS:
        return hit[1]
    try:
        await _assert_public(f"https://{host}:{port}/")
        problem = await asyncio.wait_for(asyncio.to_thread(_verify, host, port), timeout=TIMEOUT_SECONDS + 1)
    except (FetchBlocked, asyncio.TimeoutError):
        problem = None
    if len(_cache) > 512:
        _cache.clear()
    _cache[key] = (time.monotonic(), problem)
    return problem
