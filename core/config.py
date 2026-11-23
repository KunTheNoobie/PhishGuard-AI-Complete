"""
PhishGuard-AI — Application Configuration.
===========================================

Every runtime constant in one place.  Values come from environment variables
(or a local ``.env`` file) with safe defaults, following the Twelve-Factor
App approach.

Architecture Layer : Core / Cross-Cutting Concerns
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from core.brands import official_domains

# Load a local ``.env`` (if present) before any setting is read.  Real
# environment variables always win over the file (override=False).
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
except ImportError:  # python-dotenv is optional at runtime
    pass


# ==============================================================================
# 1. Application metadata
# ==============================================================================
APP_TITLE: Final[str] = "PhishGuard-AI"
APP_VERSION: Final[str] = "4.1.0"
APP_DESCRIPTION: Final[str] = (
    "Real-time phishing and scam protection for every website. Each page is checked "
    "by a fine-tuned BERT URL classifier, page-structure (DOM) analysis, a YOLOv8n "
    "logo detector, brand-impersonation profiling, Malaysian mule-account matching and "
    "HTTPS transport checks, and the corroborated verdict is explained in plain language."
)

# ==============================================================================
# 2. Authentication
# ==============================================================================
# Development key shared by the browser extension (API key) and the SOC
# dashboard (admin key).  Override both in .env / the hosting platform's
# secrets for anything beyond a demonstration.
DEFAULT_DEV_API_KEY: Final[str] = "12345678"

API_SECRET_TOKEN: Final[str] = os.getenv("PHISHGUARD_API_KEY", DEFAULT_DEV_API_KEY)
ADMIN_API_TOKEN: Final[str] = os.getenv("PHISHGUARD_ADMIN_KEY", "") or API_SECRET_TOKEN
USING_DEFAULT_API_KEY: Final[bool] = DEFAULT_DEV_API_KEY in (API_SECRET_TOKEN, ADMIN_API_TOKEN)

# Lifetime of a dashboard browser session created by POST /auth/login.
DASHBOARD_SESSION_TTL_SECONDS: Final[int] = int(os.getenv("PHISHGUARD_SESSION_TTL", "28800"))  # 8 h

# ==============================================================================
# 3. CORS and rate limiting
# ==============================================================================
CORS_ALLOWED_ORIGINS: Final[list[str]] = [
    origin.strip()
    for origin in os.getenv(
        "PHISHGUARD_CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000,https://phishguard-ai-backend-j74v.onrender.com"
    ).split(",")
    if origin.strip()
]
# Extension pages (popup) call the API from a chrome-extension:// origin.
CORS_ORIGIN_REGEX: Final[str] = r"^chrome-extension://[a-p]{32}$"

RATE_LIMIT: Final[str] = os.getenv("PHISHGUARD_RATE_LIMIT", "60/minute")

# ==============================================================================
# 4. Storage
# ==============================================================================
DATABASE_PATH: Final[str] = os.getenv("PHISHGUARD_DB_PATH", "phishguard.db")

# ==============================================================================
# 5. Models
# ==============================================================================
# bert-base-uncased fine-tuned for one epoch on 439,476 labelled URLs
# (Kaggle "phishing_site_urls", 80/20 split).  It is a URL classifier: it is
# fed the scheme-stripped URL, never page text.
BERT_MODEL_NAME: Final[str] = os.getenv("PHISHGUARD_BERT_MODEL", "./phishguard_custom_model")
ENABLE_SEMANTIC_ENGINE: Final[bool] = os.getenv("PHISHGUARD_ENABLE_SEMANTIC", "true").lower() not in {
    "0", "false", "no",
}
# P(phishing) at or above which BERT counts as a positive signal.  A positive
# BERT signal never blocks a page on its own.
MALICIOUS_THRESHOLD: Final[float] = float(os.getenv("PHISHGUARD_MALICIOUS_THRESHOLD", "0.75"))

# YOLOv8n logo detector (Module 2).
VISUAL_MODEL_PATH: Final[str] = os.getenv("PHISHGUARD_VISUAL_MODEL", "visual_identity/models/best.pt")
VISUAL_CONFIDENCE_THRESHOLD: Final[float] = float(os.getenv("PHISHGUARD_VISUAL_CONFIDENCE", "0.85"))
VISUAL_IMAGE_SIZE: Final[int] = int(os.getenv("PHISHGUARD_VISUAL_IMAGE_SIZE", "960"))
ENABLE_VISUAL_ENGINE: Final[bool] = os.getenv("PHISHGUARD_ENABLE_VISUAL", "true").lower() not in {
    "0", "false", "no",
}

# ==============================================================================
# 6. Live page fetching (dashboard analyser and QR scanner)
# ==============================================================================
FETCH_TIMEOUT_SECONDS: Final[float] = float(os.getenv("PHISHGUARD_FETCH_TIMEOUT", "8"))
FETCH_MAX_BYTES: Final[int] = int(os.getenv("PHISHGUARD_FETCH_MAX_BYTES", str(1_500_000)))
FETCH_MAX_REDIRECTS: Final[int] = 5

# ==============================================================================
# 7. Whitelists
# ==============================================================================
# Official domains of every protected brand (see core/brands.py).
TRUSTED_DOMAINS: Final[frozenset[str]] = official_domains()

# Widely used platforms that are not impersonation targets in core/brands.py.
# SECURITY: never list a suffix under which anyone can publish pages
# (web.app, vercel.app, netlify.app, github.io, hf.space, wordpress.com ...):
# a subdomain match would whitelist attacker-controlled content.
GLOBAL_SAFE_DOMAINS: Final[frozenset[str]] = frozenset({
    # Search, reference and education
    "bing.com", "duckduckgo.com", "yahoo.com", "wikipedia.org", "wikimedia.org",
    "coursera.org", "edx.org", "khanacademy.org", "udemy.com", "w3.org", "mozilla.org",
    # Social, messaging and media
    "youtube.com", "youtu.be", "messenger.com", "threads.net", "x.com", "twitter.com",
    "linkedin.com", "reddit.com", "tiktok.com", "telegram.org", "discord.com", "zoom.us",
    "slack.com", "netflix.com", "spotify.com",
    # Technology and developer platforms
    "github.com", "gitlab.com", "stackoverflow.com", "python.org", "pypi.org", "npmjs.com",
    "docker.com", "cloudflare.com", "amazon.com", "aws.amazon.com", "apple.com",
    # Malaysian news, marketplaces and services
    "thestar.com.my", "malaysiakini.com", "nst.com.my", "bharian.com.my",
    "freemalaysiatoday.com", "mudah.my", "carousell.com.my", "myeg.com.my",
    # Malaysian government and universities (registry-controlled suffixes)
    "gov.my", "edu.my", "tarc.edu.my", "tarumt.edu.my",
    # Other government suffixes
    "gov.sg", "gov.uk",
})

ALL_TRUSTED_DOMAINS: Final[frozenset[str]] = TRUSTED_DOMAINS | GLOBAL_SAFE_DOMAINS

# ==============================================================================
# 8. Mule-account extraction (Malaysia)
# ==============================================================================
# Patterns are applied to the *compact* form of a candidate (separators
# removed), so "5142 7610 3388" and "5142-7610-3388" both match Maybank.
MULE_ACCOUNT_PATTERNS: Final[dict[str, str]] = {
    "Maybank": r"[15]\d{11}",
    "CIMB Bank": r"7\d{13}",
    "Public Bank": r"3\d{9}",
    "RHB Bank": r"2\d{13}",
    "AmBank": r"8\d{12}",
    "Bank Islam": r"1\d{13}",
    "Hong Leong Bank": r"[02]\d{9,11}",
    "Bank Rakyat": r"[02]\d{11}",
}
DUITNOW_PHONE_PATTERN: Final[str] = r"(?:60|0)1\d{8,9}"
MALAYSIAN_IC_PATTERN: Final[str] = r"\d{6}-?\d{2}-?\d{4}"
ACCOUNT_MIN_DIGITS: Final[int] = 10
ACCOUNT_MAX_DIGITS: Final[int] = 16

# ==============================================================================
# 9. Verdicts and scam lexicon
# ==============================================================================
VERDICT_SAFE: Final[str] = "SAFE"
VERDICT_WARNING: Final[str] = "WARNING"
VERDICT_BLOCK: Final[str] = "BLOCK_RENDER"

BILINGUAL_SCAM_KEYWORDS: Final[list[str]] = [
    # English
    "urgent verification", "immediate verification", "account suspension", "account suspended",
    "flagged for suspicious", "pdrm verification", "transfer verification", "avoid account closure",
    "avoid suspension", "verify account now", "update login details", "unauthorized login",
    "security alert", "temporary freeze", "reactivate account", "security deposit",
    "verify immediately", "claim e-wallet credit", "confirm identity", "billing error",
    "wire transfer required", "unusual sign-in activity", "click to restore access",
    "payment failed", "update payment method", "re-authenticate", "unlock wallet",
    "parcel on hold", "delivery failed", "redelivery fee", "customs fee", "unpaid toll",
    "your package could not be delivered",
    # Bahasa Melayu
    "akaun digantung", "akaun disekat", "tindakan segera", "pengesahan keselamatan",
    "saman tertunggak", "pdrm saman", "tuntutan bantuan tunai", "bantuan e-wallet",
    "kemaskini maklumat", "bayaran deposit", "cukai lhdn tertunggak", "sekat kad debit",
    "log masuk tidak sah", "kemaskini perbankan", "tebus hadiah", "akaun anda dibekukan",
    "pembayaran disekat", "bungkusan anda", "penghantaran gagal",
    # Chinese
    "账号异常", "账户冻结", "立即验证", "紧急通知", "安全警报", "更新支付信息", "解除冻结", "实名认证",
    # Bahasa Indonesia
    "akun diblokir", "verifikasi segera", "transaksi mencurigakan",
]
