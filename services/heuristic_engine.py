"""
PhishGuard-AI — Structural URL Heuristics.
===========================================

Zero-latency checks on the shape of the URL, independent of any model:

1. Raw IPv4 / IPv6 host, including integer and hex forms.
2. Userinfo before ``@`` that hides the real host.
3. Punycode / mixed-script internationalised hostnames.
4. Disposable, high-abuse top-level domains.
5. Excessive subdomain nesting and deceptive keyword subdomains.
6. Non-standard ports.
7. Free hosting platforms where anyone can publish a page (web.app,
   vercel.app, appspot.com ...), heavily abused for throw-away phishing.

"Strong" indicators are evasion techniques a legitimate consumer site has no
reason to use; the verdict engine treats them differently from weak ones.

Architecture Layer : Service / Detection
"""

from __future__ import annotations

from typing import Any, Final

from services.domain_utils import registrable_domain, subdomain_labels
from services.url_canonicalizer import CanonicalURL, canonicalize

HIGH_RISK_TLDS: Final[frozenset[str]] = frozenset({
    "top", "xyz", "tk", "buzz", "club", "work", "click", "gq", "cf", "ml", "ga", "fit",
    "rest", "surf", "icu", "cyou", "sbs", "cfd", "monster", "quest",
})

DECEPTIVE_SUBDOMAINS: Final[frozenset[str]] = frozenset({
    "login", "verify", "secure", "auth", "security", "update", "banking", "online",
    "portal", "account", "signin", "wallet",
})

_STANDARD_PORTS: Final[frozenset[int]] = frozenset({80, 443, 8000, 8080})

FREE_HOSTING_SUFFIXES: Final[frozenset[str]] = frozenset({
    "appspot.com", "web.app", "firebaseapp.com", "vercel.app", "netlify.app", "github.io",
    "pages.dev", "workers.dev", "glitch.me", "repl.co", "replit.app", "onrender.com",
    "herokuapp.com", "hf.space", "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com",
    "square.site", "godaddysites.com", "webflow.io", "framer.website", "ngrok-free.app", "ngrok.io",
})


def analyze_url_heuristics(url: str | CanonicalURL) -> dict[str, Any]:
    """Return the structural indicators found in ``url``."""
    c = url if isinstance(url, CanonicalURL) else canonicalize(url)
    host = c.hostname
    strong: list[str] = []
    weak: list[str] = []

    if c.is_ip:
        strong.append(f"The website address is a raw IP address ({host}) instead of a domain name")
    if c.has_userinfo:
        strong.append(
            f"The address hides its real destination: '{c.userinfo[:60]}' before '@' is ignored "
            f"and the browser actually opens {host}"
        )
    if c.is_idn:
        (strong if c.mixed_script or c.skeleton_hostname != c.unicode_hostname else weak).append(
            f"Internationalised domain ({c.unicode_hostname}) that can imitate Latin letters"
        )

    tld = host.rsplit(".", 1)[-1] if "." in host and not c.is_ip else ""
    if tld in HIGH_RISK_TLDS:
        strong.append(f"High-abuse top-level domain (.{tld})")

    sub_labels = [] if c.is_ip else [lbl for lbl in subdomain_labels(host) if lbl != "www"]
    if len(sub_labels) >= 3:
        weak.append(f"Unusually deep subdomain nesting ({len(sub_labels)} levels below {registrable_domain(host)})")
    deceptive = next((s for s in sub_labels if s in DECEPTIVE_SUBDOMAINS), None)
    if deceptive:
        weak.append(f"Deceptive keyword subdomain '{deceptive}'")

    if c.port and c.port not in _STANDARD_PORTS:
        weak.append(f"Non-standard web port ({c.port})")

    free_host = next((sfx for sfx in FREE_HOSTING_SUFFIXES if host == sfx or host.endswith("." + sfx)), None)
    if free_host:
        weak.append(f"Hosted on a free publishing platform ({free_host}) where anyone can create a page")

    indicators = strong + weak
    score = min(1.0, round(0.35 * len(strong) + 0.15 * len(weak), 2))
    return {
        "hostname": host,
        "registrable_domain": registrable_domain(host) if not c.is_ip else host,
        "is_ip_address": c.is_ip,
        "has_userinfo": c.has_userinfo,
        "free_hosting": free_host is not None,
        "is_punycode": c.is_idn,
        "indicators": indicators,
        "strong_indicators": strong,
        "heuristic_score": score,
        "is_suspicious": bool(indicators),
        "is_strong": bool(strong),
    }
