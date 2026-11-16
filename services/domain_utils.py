"""
PhishGuard-AI — Domain Parsing Utilities.
==========================================

Small, dependency-free helpers shared by the heuristic engine, the brand
profiler and the verdict engine:

* ``extract_hostname``     — tolerant hostname extraction from a URL.
* ``registrable_domain``   — eTLD+1 using a compact multi-label suffix table
                             (``maybank2u.com.my`` rather than ``com.my``).
* ``subdomain_labels``     — labels left of the registrable domain.
* ``host_tokens``          — hostname split on dots and hyphens.
* ``strip_scheme``         — URL without scheme / leading ``www.``; this is
                             the form in which URLs appear in the corpus the
                             BERT classifier was fine-tuned on.
* ``levenshtein``          — bounded edit distance for look-alike detection.

Architecture Layer : Services / Shared Utilities
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlparse

# Multi-label public suffixes that matter for this project's target region.
# A full Public Suffix List is deliberately avoided to keep the hot path
# allocation-free; unknown suffixes fall back to the last label.
_MULTI_LABEL_SUFFIXES: Final[frozenset[str]] = frozenset({
    "com.my", "net.my", "org.my", "gov.my", "edu.my", "mil.my", "name.my",
    "com.sg", "edu.sg", "gov.sg", "org.sg", "net.sg",
    "co.id", "or.id", "go.id", "ac.id", "web.id",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "co.kr", "co.nz", "co.in", "co.th", "co.za",
    "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.ph", "com.vn", "com.br",
})


def extract_hostname(raw_url: str) -> str:
    """Return the lower-cased hostname of ``raw_url`` ('' if unparsable)."""
    candidate = (raw_url or "").strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        return (urlparse(candidate).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def registrable_domain(hostname: str) -> str:
    """Return the registrable domain (eTLD+1) of ``hostname``."""
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_labels(hostname: str) -> list[str]:
    """Return the labels to the left of the registrable domain."""
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    kept = len(registrable_domain(hostname).split(".")) if hostname else 0
    return labels[: max(0, len(labels) - kept)]


def host_tokens(hostname: str) -> list[str]:
    """Split a hostname into alphanumeric tokens on dots and hyphens."""
    return [tok for tok in hostname.lower().replace("-", ".").split(".") if tok]


def strip_scheme(raw_url: str) -> str:
    """Return ``raw_url`` without its scheme and without a leading ``www.``."""
    stripped = (raw_url or "").strip().split("://", 1)[-1]
    return stripped[4:] if stripped.lower().startswith("www.") else stripped


def levenshtein(a: str, b: str, max_distance: int = 2) -> int:
    """Edit distance between ``a`` and ``b``; returns ``max_distance + 1`` early
    once the distance is certain to exceed ``max_distance``."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (char_a != char_b),
            ))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]
