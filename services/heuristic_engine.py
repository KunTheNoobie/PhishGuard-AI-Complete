"""
PhishGuard-AI — Domain & Network Security Heuristic Engine.
============================================================

Performs zero-latency structural and network anomaly detection on target URLs,
including:
    1. Raw IPv4 / IPv6 address host detection.
    2. Punycode (IDN homoglyph) lookalike attacks.
    3. Disposable & high-risk TLD profiling (.top, .xyz, .tk, .buzz).
    4. Excessive subdomain nesting & deceptive keyword prefixing.

Architecture Layer: Services / Threat Intelligence
Thesis Reference : §3.4 — Network & Structural Domain Heuristics
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Final
from urllib.parse import urlparse

# High-risk TLDs disproportionately observed in disposable phishing campaigns
HIGH_RISK_TLDS: Final[set[str]] = {
    "top", "xyz", "tk", "buzz", "club", "work", "click", "gq", "cf", "ml", "ga", "fit", "rest", "surf"
}

# Deceptive security keywords commonly prefixed as subdomains
DECEPTIVE_SUBDOMAINS: Final[set[str]] = {
    "login", "verify", "secure", "auth", "security", "update", "banking", "online", "portal"
}


def analyze_url_heuristics(raw_url: str) -> dict[str, Any]:
    """Inspect a URL and evaluate heuristic risk vectors.

    Returns risk score adjustment and identified threat indicators.
    """
    clean_url = raw_url.strip()
    if "://" not in clean_url:
        clean_url = f"http://{clean_url}"

    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    indicators: list[str] = []
    heuristic_penalty: float = 0.0

    # 1. Check for raw IP address hostname
    try:
        ipaddress.ip_address(hostname)
        indicators.append("Host is a raw numeric IP address (Common evasion technique)")
        heuristic_penalty += 0.45
    except ValueError:
        pass

    # 2. Check for Punycode / IDN Homoglyphs
    if hostname.startswith("xn--") or ".xn--" in hostname:
        indicators.append("Punycode (IDN Homoglyph) character set detected")
        heuristic_penalty += 0.40

    # 3. Check for High-Risk TLDs
    parts = hostname.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        if tld in HIGH_RISK_TLDS:
            indicators.append(f"High-risk disposable TLD detected (.{tld})")
            heuristic_penalty += 0.35

    # 4. Check for Excessive Subdomain Depth
    if len(parts) >= 4:
        indicators.append(f"Excessive subdomain nesting ({len(parts)} levels)")
        heuristic_penalty += 0.20

    # 5. Check for Deceptive Keyword Subdomains
    for sub in parts[:-2]:
        if sub in DECEPTIVE_SUBDOMAINS:
            indicators.append(f"Deceptive keyword subdomain detected: '{sub}'")
            heuristic_penalty += 0.25
            break

    # 6. Check for Non-Standard Ports
    if port and port not in (80, 443, 8000, 3000, 5000):
        indicators.append(f"Non-standard web port ({port})")
        heuristic_penalty += 0.15

    return {
        "hostname": hostname,
        "is_ip_address": any("raw numeric IP" in i for i in indicators),
        "is_punycode": any("Punycode" in i for i in indicators),
        "indicators": indicators,
        "heuristic_score": min(1.0, round(heuristic_penalty, 2)),
        "is_suspicious": len(indicators) > 0,
    }
