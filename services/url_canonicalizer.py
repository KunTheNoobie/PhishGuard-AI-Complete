"""
PhishGuard-AI — URL Canonicalisation.
======================================

Reduces a URL to the form a browser actually navigates to before any rule
looks at it, and records every trick it had to undo:

* **Userinfo spoofing** — ``https://maybank2u.com.my@evil-login.top/`` goes to
  ``evil-login.top``; everything before ``@`` is a user name.
* **IDN homoglyphs** — ``xn--mybank2u-...`` is decoded to Unicode, and a
  *skeleton* maps look-alike Cyrillic / Greek / full-width characters to
  Latin (``mаybank`` with a Cyrillic ``а`` becomes ``maybank``).
* **Numeric IP forms** — ``http://3232235777/`` or ``http://0xC0A80101/`` are
  the same host as ``192.168.1.1``.
* **Browser quirks** — backslashes treated as slashes, percent-encoded or
  upper-case hostnames, trailing dots and default ports.

The query string and fragment are dropped from ``display_url`` so that scan
logs never store tokens or personal data carried in URLs.

Architecture Layer : Service / Pre-processing
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import unquote, urlsplit

# Look-alike characters mapped to the Latin letter they imitate (a subset of
# the Unicode confusables list covering the scripts seen in phishing).
_CONFUSABLES: Final[dict[str, str]] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k",
    "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ү": "y",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w",
    # Latin look-alikes
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l",
}

_SCHEME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_CONTROL_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x20\x7f]")


@dataclass
class CanonicalURL:
    """A URL as the browser sees it, plus the tricks that were undone."""

    original: str
    scheme: str
    hostname: str                 # ASCII (punycode) form, lower case
    unicode_hostname: str         # IDN decoded for display
    skeleton_hostname: str        # confusables mapped to Latin, for brand matching
    port: int | None
    path: str
    userinfo: str
    display_url: str              # scheme://host[:port]/path, no query or fragment
    model_url: str                # URL without scheme or "www.", the BERT input form
    query: str = ""
    is_ip: bool = False
    is_idn: bool = False
    mixed_script: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def has_userinfo(self) -> bool:
        return bool(self.userinfo)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def fetch_url(self) -> str:
        """The URL to request: real host, path and query, no user name or fragment."""
        return self.display_url + (f"?{self.query}" if self.query else "")


def _decode_idn(hostname: str) -> str:
    labels = []
    for label in hostname.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def _encode_idn(hostname: str) -> str:
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def skeleton(text: str) -> str:
    """Map look-alike characters to Latin after NFKC normalisation."""
    normalised = unicodedata.normalize("NFKC", text.lower())
    out = "".join(_CONFUSABLES.get(ch, ch) for ch in normalised)
    # Strip combining marks (é -> e) so accented look-alikes collapse too.
    return "".join(ch for ch in unicodedata.normalize("NFKD", out) if not unicodedata.combining(ch))


def _scripts(text: str) -> set[str]:
    scripts = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0] if name else "UNKNOWN")
    return scripts


def _parse_numeric_ip(host: str) -> str | None:
    """Return dotted IPv4 for integer / hex / octal host forms, else None."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    values = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                values.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                values.append(int(part, 8))
            else:
                values.append(int(part, 10))
        except ValueError:
            return None
    # inet_aton semantics: the last part fills the remaining bytes.
    if any(v > 255 for v in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return None
    number = 0
    for v in values[:-1]:
        number = number * 256 + v
    number = number * (256 ** (5 - len(values))) + values[-1]
    if number > 0xFFFFFFFF:
        return None
    return str(ipaddress.IPv4Address(number))


def canonicalize(raw_url: str) -> CanonicalURL:
    """Canonicalise ``raw_url`` the way a browser would before navigating."""
    original = raw_url or ""
    notes: list[str] = []
    text = _CONTROL_RE.sub("", original.strip())
    if not _SCHEME_RE.match(text):
        text = "http://" + text
    # Browsers treat "\" as "/" in http(s) URLs (e.g. https://bank.com\@evil.top).
    if "\\" in text:
        text = text.replace("\\", "/")
        notes.append("Backslashes in the URL were treated as slashes, as a browser does")

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
        notes.append(f"Text before '@' ({unquote(userinfo)[:60]}) is a user name, not the website")

    host = netloc
    port: int | None = None
    if host.startswith("["):                       # IPv6 literal
        end = host.find("]")
        port_part = host[end + 1:]
        host = host[1:end]
        if port_part.startswith(":") and port_part[1:].isdigit():
            port = int(port_part[1:])
    elif ":" in host:
        host, _, port_text = host.rpartition(":")
        if port_text.isdigit():
            port = int(port_text)
    host = unquote(host).strip().rstrip(".").lower()
    if (scheme, port) in {("http", 80), ("https", 443)}:
        port = None

    # Hostnames typed in Unicode are converted to punycode for matching.
    if any(ord(ch) > 127 for ch in host):
        host = _encode_idn(host)

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        dotted = _parse_numeric_ip(host)
        if dotted:
            notes.append(f"Numeric host '{host}' is the IP address {dotted}")
            host, is_ip = dotted, True

    unicode_host = _decode_idn(host)
    is_idn = unicode_host != host
    skel = skeleton(unicode_host)
    mixed = False
    if is_idn:
        scripts = _scripts(unicode_host.replace(".", ""))
        mixed = len(scripts - {"DIGIT"}) > 1
        notes.append(f"Internationalised domain decoded: {host} → {unicode_host}")
        if skel != unicode_host:
            notes.append(f"Look-alike characters normalised: {unicode_host} → {skel}")

    path = parts.path or "/"
    port_text = f":{port}" if port else ""
    display_host = f"[{host}]" if ":" in host else host
    display_url = f"{scheme}://{display_host}{port_text}{path}"
    # BERT was fine-tuned on raw URL strings without scheme or "www.", tricks
    # included, so it receives the URL as written rather than the cleaned form.
    model_url = text.split("://", 1)[-1]
    if model_url.lower().startswith("www."):
        model_url = model_url[4:]

    return CanonicalURL(
        original=original, scheme=scheme, hostname=host, unicode_hostname=unicode_host,
        skeleton_hostname=skel, port=port, path=path, userinfo=unquote(userinfo),
        display_url=display_url, model_url=model_url, query=parts.query, is_ip=is_ip, is_idn=is_idn,
        mixed_script=mixed, notes=notes,
    )
