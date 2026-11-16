"""
PhishGuard-AI — Brand Impersonation Index (BII) & Profiler.
============================================================

Calculates a deterministic Brand Impersonation Index (BII) by cross-referencing
brand cues against the authoritative domains of each institution.

Three evidence tiers are distinguished, because they carry very different
false-positive risk:

``brand_in_hostname``
    A protected brand string is embedded in a hostname that the brand does
    not own (``maybank2u-secure-login.top``).  Strong evidence.
``lookalike_domain``
    A hostname token is a homoglyph or near-miss edit of a protected brand
    string (``rnaybank2u.com``, ``maybznk2u.com.my``).  Strong evidence.
``brand_mentioned``
    The brand is merely named in the page text (a news article about
    Maybank).  Weak evidence: never sufficient on its own.

``is_impersonation`` is true only for the two strong tiers.  The verdict
engine still requires at least one independent corroborating signal before
a page is blocked.

Architecture Layer: Services / Threat Attribution
Thesis Reference : §4.7 — Brand Impersonation Profiling & Attribution Metrics
"""

from __future__ import annotations

import re
from typing import Any, Final

from services.domain_utils import extract_hostname, host_tokens, levenshtein

# Canonical Global and Regional financial and tech institutions and their official domain registries
GLOBAL_FINANCIAL_AND_TECH_BRANDS: Final[dict[str, dict[str, Any]]] = {
    # ── Malaysian Financial Infrastructure ──
    "Maybank": {
        "official_domains": {"maybank2u.com.my", "maybank.com", "maybank.com.my", "maybank2e.com", "maybank2u.com"},
        "keywords": ["maybank", "maybank2u", "mae", "malayan banking"],
    },
    "CIMB Bank": {
        "official_domains": {"cimbclicks.com.my", "cimb.com.my", "cimbbank.com.my", "cimb.com", "cimbocto.com.my"},
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
        "official_domains": {"ambank.com.my", "ambankgroup.com", "amonline.com.my"},
        "keywords": ["ambank", "ambank online", "amonline"],
    },
    "Bank Islam": {
        "official_domains": {"bankislam.com.my", "bankislam.biz", "bankislam.com"},
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
        "keywords": ["touch n go", "tng ewallet", "touch 'n go", "tng"],
    },
    "BSN": {
        "official_domains": {"bsn.com.my", "mybsn.com.my"},
        "keywords": ["bank simpanan nasional", "mybsn"],
    },
    "GrabPay": {
        "official_domains": {"grab.com", "grab.com.my"},
        "keywords": ["grabpay", "grab pay"],
    },
    "ShopeePay": {
        "official_domains": {"shopee.com.my", "shopeepay.com.my"},
        "keywords": ["shopeepay", "shopee pay"],
    },
    "Boost": {
        "official_domains": {"myboost.com.my", "boost-my.com", "myboost.co"},
        "keywords": ["boost e-wallet", "boost ewallet"],
    },
    # ── Malaysian Government Agencies & Utilities (frequently impersonated) ──
    "LHDN": {
        "official_domains": {"hasil.gov.my"},
        "keywords": ["lhdn", "lembaga hasil dalam negeri"],
    },
    "KWSP / EPF": {
        "official_domains": {"kwsp.gov.my"},
        "keywords": ["kwsp", "i-akaun", "epf"],
    },
    "PDRM": {
        "official_domains": {"rmp.gov.my"},
        "keywords": ["pdrm", "polis diraja malaysia"],
    },
    "JPJ": {
        "official_domains": {"jpj.gov.my"},
        "keywords": ["jpj", "jabatan pengangkutan jalan"],
    },
    "Bank Negara Malaysia": {
        "official_domains": {"bnm.gov.my"},
        "keywords": ["bank negara malaysia", "bnm"],
    },
    "TNB": {
        "official_domains": {"tnb.com.my", "mytnb.com.my"},
        "keywords": ["tnb", "tenaga nasional"],
    },
    "Pos Malaysia": {
        "official_domains": {"pos.com.my"},
        "keywords": ["pos malaysia", "poslaju"],
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
        "official_domains": {"dhl.com", "fedex.com", "ups.com"},
        "keywords": ["dhl parcel", "fedex tracking", "customs fee unpaid", "package delivery held"],
    },
}

# Backward compatibility alias
MALAYSIAN_FINANCIAL_BRANDS = GLOBAL_FINANCIAL_AND_TECH_BRANDS

# ------------------------------------------------------------------------------
# Hostname evidence tables
# ------------------------------------------------------------------------------
# Distinctive brand strings searched as substrings of the hostname, and short
# brand tokens that must match a whole hostname token.  Generic words
# ("apple", "boost", "grab", "mae", "octo") are deliberately excluded because
# they occur in unrelated legitimate hostnames.
_HOST_SUBSTRINGS: Final[dict[str, tuple[str, ...]]] = {
    "Maybank": ("maybank", "malayanbanking"),
    "CIMB Bank": ("cimbclicks", "cimbbank", "cimb-clicks", "cimbocto"),
    "Public Bank": ("pbebank", "publicbank", "public-bank"),
    "RHB Bank": ("rhbgroup", "rhbnow", "rhbbank"),
    "Hong Leong Bank": ("hongleong", "hong-leong", "hlbconnect"),
    "AmBank": ("ambank", "amonline"),
    "Bank Islam": ("bankislam", "bank-islam"),
    "Bank Rakyat": ("bankrakyat", "bank-rakyat", "irakyat"),
    "BSN": ("mybsn",),
    "DuitNow / PayNet": ("duitnow", "paynet"),
    "Touch 'n Go eWallet": ("touchngo", "touch-n-go", "tngdigital", "tngewallet"),
    "GrabPay": ("grabpay", "grab-pay"),
    "ShopeePay": ("shopeepay", "shopee-pay"),
    "Boost": ("boost-ewallet", "boostewallet", "myboost"),
    "Bank Negara Malaysia": ("banknegara", "bank-negara"),
    "TNB": ("mytnb",),
    "Pos Malaysia": ("pos-malaysia", "posmalaysia", "poslaju"),
    "Microsoft": ("microsoft", "office365"),
    "Apple": ("apple-id", "appleid", "icloud"),
    "PayPal": ("paypal",),
    "Netflix": ("netflix",),
    "Crypto / Web3": ("binance", "coinbase", "metamask", "trustwallet"),
}

_HOST_TOKENS: Final[dict[str, frozenset[str]]] = {
    "CIMB Bank": frozenset({"cimb"}),
    "Public Bank": frozenset({"pbe", "pbb"}),
    "RHB Bank": frozenset({"rhb"}),
    "Hong Leong Bank": frozenset({"hlb", "hlbb"}),
    "Touch 'n Go eWallet": frozenset({"tng"}),
    "LHDN": frozenset({"lhdn"}),
    "KWSP / EPF": frozenset({"kwsp"}),
    "PDRM": frozenset({"pdrm"}),
    "JPJ": frozenset({"jpj"}),
    "Bank Negara Malaysia": frozenset({"bnm"}),
    "TNB": frozenset({"tnb"}),
}

# Canonical strings a typosquatter imitates (>= 6 characters).
_LOOKALIKE_TARGETS: Final[dict[str, str]] = {
    "maybank2u": "Maybank", "maybank": "Maybank",
    "cimbclicks": "CIMB Bank", "pbebank": "Public Bank", "publicbank": "Public Bank",
    "rhbgroup": "RHB Bank", "hongleong": "Hong Leong Bank", "hongleongconnect": "Hong Leong Bank",
    "ambank": "AmBank", "amonline": "AmBank", "bankislam": "Bank Islam",
    "bankrakyat": "Bank Rakyat", "irakyat": "Bank Rakyat",
    "touchngo": "Touch 'n Go eWallet", "duitnow": "DuitNow / PayNet",
    "grabpay": "GrabPay", "shopeepay": "ShopeePay",
    "paypal": "PayPal", "netflix": "Netflix", "binance": "Crypto / Web3",
}

# Visual homoglyph substitutions commonly used in typosquatted Latin domains.
_HOMOGLYPHS: Final[tuple[tuple[str, str], ...]] = (
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("5", "s"), ("3", "e"),
)


def _normalise_homoglyphs(token: str) -> str:
    for fake, real in _HOMOGLYPHS:
        token = token.replace(fake, real)
    return token


def _is_official(hostname: str, official_domains: set[str]) -> bool:
    return any(hostname == d or hostname.endswith("." + d) for d in official_domains)


def _find_lookalike(hostname: str) -> tuple[str, str] | None:
    """Return ``(brand, target)`` if a hostname token imitates a brand string."""
    candidates = set(host_tokens(hostname))
    for label in hostname.split("."):
        candidates.add(label.replace("-", ""))
    for token in sorted(candidates):
        if len(token) < 6:
            continue
        normalised = _normalise_homoglyphs(token)
        for target, brand in _LOOKALIKE_TARGETS.items():
            if token == target:
                continue  # exact brand string: handled by the substring tier
            if normalised == target:
                return brand, target
            allowed = 1 if len(target) <= 8 else 2
            if abs(len(token) - len(target)) <= allowed and levenshtein(token, target, allowed) <= allowed:
                return brand, target
    return None


def profile_brand_impersonation(raw_url: str, text_content: str = "") -> dict[str, Any]:
    """Calculate the Brand Impersonation Index (BII) for a given page context.

    Returns
    -------
    dict
        ``target_brand``, ``is_official_domain``, ``is_impersonation`` (strong
        hostname evidence only), ``brand_in_hostname``, ``lookalike_domain``,
        ``brand_mentioned`` (weak, text only), ``impersonation_index`` in
        [0, 1], ``matched_brand_cues`` and ``hostname``.
    """
    hostname = extract_hostname(raw_url)
    text_lower = (text_content or "").lower()

    result: dict[str, Any] = {
        "target_brand": "None / Unaffiliated",
        "is_impersonation": False,
        "is_official_domain": False,
        "brand_in_hostname": False,
        "lookalike_domain": False,
        "brand_mentioned": False,
        "impersonation_index": 0.0,
        "matched_brand_cues": [],
        "hostname": hostname,
    }

    # 1. Official domain of any protected brand: authoritative, never impersonation.
    for brand_name, brand_info in GLOBAL_FINANCIAL_AND_TECH_BRANDS.items():
        if _is_official(hostname, brand_info["official_domains"]):
            result.update(target_brand=brand_name, is_official_domain=True)
            return result

    # 2. Strong tier: protected brand string embedded in a foreign hostname.
    tokens = set(host_tokens(hostname))
    brand_names = list(dict.fromkeys([*_HOST_SUBSTRINGS, *_HOST_TOKENS]))
    for brand_name in brand_names:
        hits = [n for n in _HOST_SUBSTRINGS.get(brand_name, ()) if n in hostname]
        hits += sorted(tokens & _HOST_TOKENS.get(brand_name, frozenset()))
        if hits:
            result.update(
                target_brand=brand_name, is_impersonation=True, brand_in_hostname=True,
                impersonation_index=0.98, matched_brand_cues=sorted(set(hits)),
            )
            return result

    # 3. Strong tier: homoglyph / near-miss look-alike of a protected brand string.
    lookalike = _find_lookalike(hostname)
    if lookalike is not None:
        brand_name, target = lookalike
        result.update(
            target_brand=brand_name, is_impersonation=True, lookalike_domain=True,
            impersonation_index=0.95, matched_brand_cues=[f"look-alike of '{target}'"],
        )
        return result

    # 4. Weak tier: the brand is only named in the page text.
    for brand_name, brand_info in GLOBAL_FINANCIAL_AND_TECH_BRANDS.items():
        mentions = [kw for kw in brand_info["keywords"]
                    if re.search(r"\b" + re.escape(kw) + r"\b", text_lower)]
        if mentions:
            result.update(
                target_brand=brand_name, brand_mentioned=True,
                impersonation_index=0.35, matched_brand_cues=sorted(set(mentions)),
            )
            return result

    return result
