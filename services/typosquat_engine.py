"""
PhishGuard-AI Homoglyph & Typosquatting Pre-Emptive Radar
Generates and inspects potential phishing permutations across protected institutions.
"""

from typing import List, Dict, Any
import unicodedata

# 10 Tracked Malaysian Entities and their primary domains
PROTECTED_INSTITUTIONS = [
    {"brand": "Maybank", "primary_domain": "maybank2u.com.my", "logo": "🦁"},
    {"brand": "CIMB Bank", "primary_domain": "cimbclicks.com.my", "logo": "🔴"},
    {"brand": "Public Bank", "primary_domain": "pbebank.com", "logo": "🏢"},
    {"brand": "RHB Bank", "primary_domain": "rhbgroup.com", "logo": "🔷"},
    {"brand": "Hong Leong Bank", "primary_domain": "hlb.com.my", "logo": "🔵"},
    {"brand": "AmBank", "primary_domain": "ambank.com.my", "logo": "🦅"},
    {"brand": "Bank Islam", "primary_domain": "bankislam.biz", "logo": "🟢"},
    {"brand": "Touch 'n Go eWallet", "primary_domain": "tngdigital.com.my", "logo": "📱"},
    {"brand": "GrabPay Malaysia", "primary_domain": "grab.com", "logo": "🚗"},
    {"brand": "ShopeePay", "primary_domain": "shopee.com.my", "logo": "🛍️"},
]

HOMOGLYPH_MAP = {
    'a': ['\u0430', '\u00e0', '\u00e1', '\u0105'],  # Cyrillic small letter a, accented a
    'c': ['\u0441', '\u0107', '\u010d'],            # Cyrillic small letter es
    'e': ['\u0435', '\u00e9', '\u00e8', '\u0113'],  # Cyrillic small letter ie
    'i': ['\u0456', '\u00ed', '\u00ec', '1', 'l'],  # Cyrillic small letter Byelorussian-Ukrainian i
    'o': ['\u043e', '\u00f3', '\u00f2', '0'],       # Cyrillic small letter o, digit 0
    'p': ['\u0440'],                                # Cyrillic small letter er
    's': ['\u0455', '5', '$'],                      # Cyrillic small letter dze
    'u': ['\u00fc', '\u00f9', '\u00fa', 'v'],       # u variants
    'x': ['\u0445'],                                # Cyrillic small letter ha
    'y': ['\u0443', '\u00fd'],                      # Cyrillic small letter u
}

HIGH_RISK_TLDS = [".top", ".xyz", ".cc", ".icu", ".vip", ".buzz", ".club", ".link", ".online", ".site"]
PHISHING_SUFFIXES = ["login", "verify", "auth", "secure", "update", "tac", "otp", "portal", "helpdesk"]

def generate_typosquats_for_domain(domain_base: str, limit: int = 15) -> List[Dict[str, Any]]:
    """
    Generates pre-emptive typosquats, homoglyphs, and subdomains.
    """
    squats = []
    clean_base = domain_base.split('.')[0]
    
    # 1. Homoglyphs (IDN/Punycode)
    for i, char in enumerate(clean_base):
        if char.lower() in HOMOGLYPH_MAP:
            for sub in HOMOGLYPH_MAP[char.lower()][:2]:
                homo_str = clean_base[:i] + sub + clean_base[i+1:]
                try:
                    puny = homo_str.encode('idna').decode('ascii')
                except Exception:
                    puny = f"xn--{homo_str}"
                squats.append({
                    "variant": f"{homo_str}.com",
                    "punycode": f"{puny}.com",
                    "technique": "IDN Homoglyph Attack",
                    "risk_score": 95,
                    "risk_tier": "CRITICAL",
                    "status": "PRE_EMPTIVELY_FLAGGED"
                })

    # 2. Phishing keywords & Hyphenation
    for suffix in PHISHING_SUFFIXES[:4]:
        for tld in HIGH_RISK_TLDS[:3]:
            squats.append({
                "variant": f"{clean_base}-{suffix}{tld}",
                "punycode": f"{clean_base}-{suffix}{tld}",
                "technique": "Hyphenated Credential Lure",
                "risk_score": 88,
                "risk_tier": "HIGH",
                "status": "PRE_EMPTIVELY_FLAGGED"
            })

    # 3. Omission & Transposition
    if len(clean_base) > 4:
        # Vowel drop
        no_vowels = ''.join([c for c in clean_base if c not in 'aeiou'])
        if no_vowels and no_vowels != clean_base:
            squats.append({
                "variant": f"{no_vowels}.com",
                "punycode": f"{no_vowels}.com",
                "technique": "Vowel Omission Typosquat",
                "risk_score": 80,
                "risk_tier": "HIGH",
                "status": "PRE_EMPTIVELY_FLAGGED"
            })
        
        # Character swap
        swapped = clean_base[0] + clean_base[2] + clean_base[1] + clean_base[3:]
        squats.append({
            "variant": f"{swapped}.com.my",
            "punycode": f"{swapped}.com.my",
            "technique": "Transposition Typosquat",
            "risk_score": 85,
            "risk_tier": "HIGH",
            "status": "PRE_EMPTIVELY_FLAGGED"
        })

    return squats[:limit]

def get_complete_typosquat_radar() -> Dict[str, Any]:
    """
    Generates the entire pre-emptive protection radar across all 10 tracked entities.
    """
    total_variants = 0
    brand_reports = []

    for inst in PROTECTED_INSTITUTIONS:
        variants = generate_typosquats_for_domain(inst["primary_domain"], limit=6)
        total_variants += len(variants)
        brand_reports.append({
            "brand": inst["brand"],
            "primary_domain": inst["primary_domain"],
            "logo": inst["logo"],
            "monitored_variants_count": len(variants),
            "variants": variants
        })

    return {
        "status": "ACTIVE_RADAR",
        "total_tracked_brands": len(PROTECTED_INSTITUTIONS),
        "total_pre_emptive_variants": total_variants,
        "institutions": brand_reports
    }
