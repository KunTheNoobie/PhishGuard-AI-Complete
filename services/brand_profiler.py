"""
PhishGuard-AI — Brand Impersonation Profiler.
==============================================

Decides whether a page pretends to be one of the protected brands in
``core/brands.py``.  Three tiers of evidence carry very different
false-positive risk, so they are reported separately:

``brand_in_hostname``  (strong)
    A protected brand string sits inside a hostname the brand does not own:
    ``maybank2u-secure-login.top``, ``cimb-verify.com``.
``lookalike_domain``   (strong)
    A hostname token imitates a brand by homoglyphs or a one/two-letter edit:
    ``rnaybank2u.com``, ``maybznk2u.com.my``, or Cyrillic ``mаybank2u.com``.
``brand_mentioned``    (weak)
    The brand is only named in page text, as in a news article.  Never enough
    on its own.

Matching runs on the canonical hostname *and* its homoglyph skeleton, so IDN
tricks cannot hide a brand string.

Architecture Layer : Service / Detection
"""

from __future__ import annotations

import re
from typing import Any, Final

from core.brands import BRANDS, brand_for_domain
from services.domain_utils import host_tokens, levenshtein
from services.url_canonicalizer import CanonicalURL, canonicalize

_HOMOGLYPHS: Final[tuple[tuple[str, str], ...]] = (
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("5", "s"), ("3", "e"), ("4", "a"),
)

_LOOKALIKE_TARGETS: Final[dict[str, str]] = {
    target: name for name, info in BRANDS.items() for target in info["lookalikes"]
}

_KEYWORD_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    (name, re.compile(r"\b(?:" + "|".join(re.escape(k) for k in info["keywords"]) + r")\b", re.IGNORECASE))
    for name, info in BRANDS.items()
    if info["keywords"]
]


def _normalise_homoglyphs(token: str) -> str:
    for fake, real in _HOMOGLYPHS:
        token = token.replace(fake, real)
    return token


def _brand_in_host(host: str) -> tuple[str, list[str]] | None:
    tokens = set(host_tokens(host))
    for name, info in BRANDS.items():
        hits = [s for s in info["host_strings"] if s in host]
        hits += sorted(tokens & set(info["host_tokens"]))
        if hits:
            return name, sorted(set(hits))
    return None


def _find_lookalike(host: str) -> tuple[str, str] | None:
    candidates = set(host_tokens(host)) | {label.replace("-", "") for label in host.split(".")}
    for token in sorted(candidates):
        if len(token) < 6:
            continue
        normalised = _normalise_homoglyphs(token)
        for target, brand in _LOOKALIKE_TARGETS.items():
            if token == target:
                continue  # an exact brand string is the brand-in-hostname tier
            if normalised == target:
                return brand, target
            allowed = 1 if len(target) <= 8 else 2
            if abs(len(token) - len(target)) <= allowed and levenshtein(token, target, allowed) <= allowed:
                return brand, target
    return None


def profile_brand_impersonation(url: str | CanonicalURL, text_content: str = "") -> dict[str, Any]:
    """Return the impersonation evidence for a page."""
    c = url if isinstance(url, CanonicalURL) else canonicalize(url)
    host, skel = c.hostname, c.skeleton_hostname
    result: dict[str, Any] = {
        "target_brand": None,
        "brand_category": None,
        "is_official_domain": False,
        "is_impersonation": False,
        "brand_in_hostname": False,
        "lookalike_domain": False,
        "brand_mentioned": False,
        "matched_brand_cues": [],
        "hostname": host,
    }

    owner = brand_for_domain(host)
    if owner:
        result.update(target_brand=owner, brand_category=BRANDS[owner]["category"], is_official_domain=True)
        return result

    for candidate_host, via_skeleton in ((host, False), (skel, True)):
        if via_skeleton and candidate_host == host:
            continue
        hit = _brand_in_host(candidate_host)
        if hit:
            name, cues = hit
            if via_skeleton:
                cues = [f"'{cue}' spelled with look-alike characters" for cue in cues]
            result.update(target_brand=name, brand_category=BRANDS[name]["category"], is_impersonation=True,
                          brand_in_hostname=not via_skeleton, lookalike_domain=via_skeleton,
                          matched_brand_cues=cues)
            return result

    lookalike = _find_lookalike(skel)
    if lookalike:
        name, target = lookalike
        result.update(target_brand=name, brand_category=BRANDS[name]["category"], is_impersonation=True,
                      lookalike_domain=True, matched_brand_cues=[f"look-alike of '{target}'"])
        return result

    lowered = (text_content or "").lower()
    if lowered:
        for name, pattern in _KEYWORD_PATTERNS:
            mentions = sorted({m.group(0).lower() for m in pattern.finditer(lowered)})
            if mentions:
                result.update(target_brand=name, brand_category=BRANDS[name]["category"],
                              brand_mentioned=True, matched_brand_cues=mentions[:5])
                return result
    return result
