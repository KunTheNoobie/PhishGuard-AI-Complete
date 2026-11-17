"""
PhishGuard-AI — Safe Live Page Fetcher.
========================================

Downloads the HTML of a URL typed into the dashboard analyser or decoded
from a QR code, so the page's structure and text can be analysed exactly as
if the browser extension had sent it.

Fetching arbitrary URLs from a server is a classic Server-Side Request
Forgery (SSRF) risk (OWASP ASVS V12.6 / API7:2023).  The fetcher therefore:

* allows only ``http`` and ``https`` on ports 80, 443, 8080 and 8443;
* resolves the hostname and refuses private, loopback, link-local,
  multicast, reserved and cloud-metadata addresses — at *every* redirect hop;
* follows at most ``FETCH_MAX_REDIRECTS`` redirects itself;
* reads at most ``FETCH_MAX_BYTES`` of ``text/html`` within a hard timeout;
* never sends cookies or credentials.

Certificate errors are not bypassed; they are reported to the verdict
engine as a warning signal (``W1_TLS_CERTIFICATE``).

Architecture Layer : Service / Infrastructure
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urljoin

import httpx

from core.config import APP_VERSION, FETCH_MAX_BYTES, FETCH_MAX_REDIRECTS, FETCH_TIMEOUT_SECONDS
from services.url_canonicalizer import canonicalize

logger: Final[logging.Logger] = logging.getLogger("phishguard.fetcher")

_ALLOWED_PORTS: Final[frozenset[int]] = frozenset({80, 443, 8080, 8443})
_USER_AGENT: Final[str] = f"Mozilla/5.0 (compatible; PhishGuard-AI/{APP_VERSION}; +security-scanner)"


class FetchBlocked(ValueError):
    """The URL points somewhere the fetcher must not go."""


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int | None = None
    html: str = ""
    redirects: list[str] = field(default_factory=list)
    tls_error: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.tls_error is None and bool(self.html)


async def _assert_public(url: str) -> None:
    c = canonicalize(url)
    if c.scheme not in ("http", "https"):
        raise FetchBlocked(f"Only http and https links can be fetched (got '{c.scheme}').")
    port = c.port or (443 if c.scheme == "https" else 80)
    if port not in _ALLOWED_PORTS:
        raise FetchBlocked(f"Port {port} is not allowed for live fetching.")
    if not c.hostname:
        raise FetchBlocked("The link has no hostname.")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(c.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchBlocked(f"The domain {c.hostname} does not resolve.") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global or address.is_multicast:
            raise FetchBlocked(f"{c.hostname} resolves to a private or reserved address ({address}); refused.")


async def fetch_page(url: str) -> FetchResult:
    """Fetch ``url`` with SSRF protection; never raises for network errors."""
    result = FetchResult(requested_url=url, final_url=url)
    current = url
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=FETCH_TIMEOUT_SECONDS, verify=True,
            headers={"User-Agent": _USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
        ) as client:
            for _ in range(FETCH_MAX_REDIRECTS + 1):
                await _assert_public(current)
                async with client.stream("GET", current) as response:
                    result.status_code = response.status_code
                    if response.is_redirect and "location" in response.headers:
                        current = urljoin(current, response.headers["location"])
                        result.redirects.append(current)
                        continue
                    content_type = response.headers.get("content-type", "")
                    if "html" not in content_type and "text/plain" not in content_type:
                        result.error = f"The link returned {content_type or 'unknown content'}, not a web page."
                        break
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) >= FETCH_MAX_BYTES:
                            break
                    result.html = body[:FETCH_MAX_BYTES].decode(response.encoding or "utf-8", errors="replace")
                    break
            else:
                result.error = f"More than {FETCH_MAX_REDIRECTS} redirects."
    except FetchBlocked as exc:
        result.error = str(exc)
    except httpx.ConnectError as exc:
        cause: BaseException | None = exc
        while cause is not None and not isinstance(cause, ssl.SSLCertVerificationError):
            cause = cause.__cause__ or cause.__context__
        if cause is not None or "CERTIFICATE_VERIFY_FAILED" in str(exc):
            result.tls_error = getattr(cause, "verify_message", None) or "certificate verification failed"
        else:
            result.error = f"Could not connect to the website ({exc.__class__.__name__})."
    except httpx.TimeoutException:
        result.error = f"The website did not respond within {FETCH_TIMEOUT_SECONDS:.0f} seconds."
    except httpx.HTTPError as exc:
        result.error = f"Fetching failed ({exc.__class__.__name__})."
    result.final_url = current
    logger.info("Fetched %s -> %s (status=%s, %d bytes, tls_error=%s, error=%s)", url, current,
                result.status_code, len(result.html), result.tls_error, result.error)
    return result
