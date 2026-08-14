"""
PhishGuard-AI — Brand Impersonation Index (BII) & Profiler.
============================================================

Calculates a deterministic Brand Impersonation Index (BII) by cross-referencing
detected financial brand keywords, logo identities, and domain origin against
whitelisted authoritative Malaysian banking infrastructures.

Architecture Layer: Services / Threat Attribution
Thesis Reference : §4.7 — Brand Impersonation Profiling & Attribution Metrics
"""

from __future__ import annotations

import re
from typing import Any, Final
from urllib.parse import urlparse

# Canonical Malaysian financial institutions and their official domain registries
MALAYSIAN_FINANCIAL_BRANDS: Final[dict[str, dict[str, Any]]] = {
    "Maybank": {
        "official_domains": {"maybank2u.com.my", "maybank.com", "maybank.com.my"},
        "keywords": ["maybank", "maybank2u", "mae", "malayan banking"],
    },
    "CIMB Bank": {
        "official_domains": {"cimbclicks.com.my", "cimb.com.my", "cimbbank.com.my"},
        "keywords": ["cimb", "cimbclicks", "cimb bank", "octo"],
    },
    "Public Bank": {
        "official_domains": {"pbebank.com", "pbebank.com.my", "publicbank.com.my"},
        "keywords": ["pbebank", "public bank", "pbe", "pb enterprise"],
    },
    "RHB Bank": {
        "official_domains": {"rhbgroup.com", "rhbnow.com", "rhbbank.com.my"},
        "keywords": ["rhb", "rhbgroup", "rhb now", "rhb bank"],
    },
    "Hong Leong Bank": {
        "official_domains": {"hlb.com.my", "hongleongconnect.my"},
        "keywords": ["hong leong", "hlb", "hlb connect", "hong leong bank"],
    },
    "AmBank": {
        "official_domains": {"ambank.com.my", "ambankgroup.com"},
        "keywords": ["ambank", "ambank online", "amonline"],
    },
    "Bank Islam": {
        "official_domains": {"bankislam.com.my", "bankislam.biz"},
        "keywords": ["bank islam", "transact bank islam"],
    },
    "Bank Rakyat": {
        "official_domains": {"bankrakyat.com.my", "irakyat.com.my"},
        "keywords": ["bank rakyat", "irakyat"],
    },
    "DuitNow / PayNet": {
        "official_domains": {"duitnow.my", "paynet.my"},
        "keywords": ["duitnow", "paynet", "duitnow qr"],
    },
    "Touch 'n Go eWallet": {
        "official_domains": {"touchngo.com.my", "tngdigital.com.my"},
        "keywords": ["touch n go", "tng ewallet", "touch 'n go"],
    },
}


def profile_brand_impersonation(raw_url: str, text_content: str = "") -> dict[str, Any]:
    """Calculate the Brand Impersonation Index (BII) for a given page context."""
    clean_url = raw_url.strip()
    if "://" not in clean_url:
        clean_url = f"http://{clean_url}"

    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    combined_corpus = f"{hostname} {text_content}".lower()

    detected_brand: str | None = None
    is_official_domain: bool = False
    impersonation_score: float = 0.0
    matched_cues: list[str] = []

    # Iterate through known financial brand profiles
    for brand_name, brand_info in MALAYSIAN_FINANCIAL_BRANDS.items():
        official_domains = brand_info["official_domains"]
        keywords = brand_info["keywords"]

        # Check if current hostname is official
        if any(hostname == d or hostname.endswith("." + d) for d in official_domains):
            is_official_domain = True
            detected_brand = brand_name
            impersonation_score = 0.0
            break

        # Check if page contains brand keywords
        brand_matches = [kw for kw in keywords if re.search(r"\b" + re.escape(kw) + r"\b", combined_corpus)]
        if brand_matches:
            detected_brand = brand_name
            matched_cues.extend(brand_matches)
            # High-confidence impersonation because brand cues are present on an unauthorized domain
            impersonation_score = 0.92
            if any(kw in hostname for kw in keywords):
                impersonation_score = 0.98  # Brand name inside deceptive domain
            break

    return {
        "target_brand": detected_brand or "None / Unaffiliated",
        "is_impersonation": (detected_brand is not None and not is_official_domain),
        "is_official_domain": is_official_domain,
        "impersonation_index": round(impersonation_score, 3),
        "matched_brand_cues": list(set(matched_cues)),
        "hostname": hostname,
    }
