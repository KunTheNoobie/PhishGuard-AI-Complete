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

# Canonical Global and Regional financial and tech institutions and their official domain registries
GLOBAL_FINANCIAL_AND_TECH_BRANDS: Final[dict[str, dict[str, Any]]] = {
    # ── Malaysian Financial Infrastructure ──
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

    # ── Global Tech & Cloud Giants ──
    "Google": {
        "official_domains": {"google.com", "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com", "gmail.com"},
        "keywords": ["google login", "google account", "gmail verification", "google drive shared", "google workspace"],
    },
    "Microsoft": {
        "official_domains": {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com"},
        "keywords": ["microsoft 365", "office 365", "outlook login", "onedrive shared", "microsoft security alert"],
    },
    "Apple": {
        "official_domains": {"apple.com", "icloud.com", "itunes.apple.com"},
        "keywords": ["apple id", "icloud verification", "apple pay locked", "apple security alert"],
    },
    "Amazon": {
        "official_domains": {"amazon.com", "amazon.com.my", "aws.amazon.com", "primevideo.com"},
        "keywords": ["amazon order", "amazon suspended", "prime membership", "aws console"],
    },
    "Meta / WhatsApp": {
        "official_domains": {"whatsapp.com", "web.whatsapp.com", "facebook.com", "instagram.com", "meta.com"},
        "keywords": ["whatsapp web", "whatsapp code", "facebook security", "instagram verification badge"],
    },

    # ── Global Fintech & Payment Gateways ──
    "PayPal": {
        "official_domains": {"paypal.com", "paypal.me"},
        "keywords": ["paypal", "paypal invoice", "paypal transfer", "paypal security"],
    },
    "Netflix": {
        "official_domains": {"netflix.com"},
        "keywords": ["netflix", "netflix membership", "netflix payment failed", "netflix reactivate"],
    },
    "Crypto / Web3": {
        "official_domains": {"binance.com", "coinbase.com", "metamask.io", "kraken.com", "trustwallet.com"},
        "keywords": ["binance", "coinbase", "metamask", "seed phrase", "private key recovery", "claim airdrop"],
    },

    # ── Global Financial & Banking ──
    "Chase / BoA / Wells Fargo": {
        "official_domains": {"chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com"},
        "keywords": ["chase online", "bank of america", "wells fargo", "citibank login"],
    },
    "HSBC / Standard Chartered / Barclays": {
        "official_domains": {"hsbc.com", "hsbc.com.my", "hsbc.co.uk", "sc.com", "standardchartered.com", "barclays.co.uk"},
        "keywords": ["hsbc", "hsbcnet", "standard chartered", "barclays online"],
    },
    "DBS / OCBC / UOB": {
        "official_domains": {"dbs.com", "dbs.com.sg", "posb.com.sg", "ocbc.com", "ocbc.com.sg", "uob.com", "uob.com.sg"},
        "keywords": ["dbs ibanking", "posb digibank", "ocbc internet banking", "uob personal internet banking"],
    },
    "Global Logistics (DHL/FedEx)": {
        "official_domains": {"dhl.com", "fedex.com", "ups.com", "pos.com.my"},
        "keywords": ["dhl parcel", "fedex tracking", "customs fee unpaid", "package delivery held"],
    },
}

# Backward compatibility alias
MALAYSIAN_FINANCIAL_BRANDS = GLOBAL_FINANCIAL_AND_TECH_BRANDS


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

    # Iterate through known financial and tech brand profiles
    for brand_name, brand_info in GLOBAL_FINANCIAL_AND_TECH_BRANDS.items():
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
