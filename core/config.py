"""
PhishGuard-AI — Application Configuration Module.
==================================================

Centralizes all runtime constants, feature flags, and environment-driven
configuration values.  Follows the Twelve-Factor App methodology by
preferring environment variables with sensible defaults.

Architecture Layer: Core / Cross-Cutting Concerns
Thesis Reference : §3.1 — System Configuration & Operational Parameters
"""

from __future__ import annotations

import os
from typing import Final


# ==============================================================================
# 1. APPLICATION METADATA
# ==============================================================================
APP_TITLE: Final[str] = "PhishGuard-AI"
APP_DESCRIPTION: Final[str] = (
    "Enterprise-grade, real-time Anti-Phishing Browser Security Suite. "
    "Performs semantic NLP analysis and mule-account scanning on raw DOM payloads."
)
APP_VERSION: Final[str] = "2.0.0"

# ==============================================================================
# 2. SECURITY CONSTANTS
# ==============================================================================
# The bearer token expected in the Authorization header.
# In production this MUST be injected via a secrets manager (e.g., HashiCorp
# Vault, AWS Secrets Manager) — **never** hard-coded.
API_SECRET_TOKEN: Final[str] = os.getenv(
    "PHISHGUARD_API_KEY",
    "phishguard_secret_key_2026",
)

# ==============================================================================
# 3. RATE LIMITING
# ==============================================================================
# Maximum requests per minute per client IP.  Enforced by SlowAPI.
RATE_LIMIT: Final[str] = os.getenv("PHISHGUARD_RATE_LIMIT", "10/minute")

# ==============================================================================
# 4. DATABASE
# ==============================================================================
# Relative path for the aiosqlite database file.
DATABASE_PATH: Final[str] = os.getenv(
    "PHISHGUARD_DB_PATH",
    "phishguard.db",
)

# ==============================================================================
# 5. ML / NLP ENGINE
# ==============================================================================
# Hugging Face model identifier — used during the lifespan cold-start.
# Points to the PhishGuard custom fine-tuned BERT model trained on a
# 500K phishing URL dataset for binary classification (LEGITIMATE / PHISHING).
BERT_MODEL_NAME: Final[str] = os.getenv(
    "PHISHGUARD_BERT_MODEL",
    "./phishguard_custom_model",
)

# Set PHISHGUARD_ENABLE_SEMANTIC=false for Cheon's visual-only demo when
# the BERT model file has not been pulled from Git LFS yet.
ENABLE_SEMANTIC_ENGINE: Final[bool] = os.getenv(
    "PHISHGUARD_ENABLE_SEMANTIC",
    "true",
).lower() not in {"0", "false", "no"}

# Confidence threshold above which a DOM payload is flagged as malicious.
# label 1 = "PHISHING" at or above this threshold triggers BLOCK_RENDER.
MALICIOUS_THRESHOLD: Final[float] = float(
    os.getenv("PHISHGUARD_MALICIOUS_THRESHOLD", "0.75")
)

# Known-legitimate Malaysian financial institution domains. When the incoming
# URL matches one of these domains or its subdomains, the semantic endpoint can
# bypass BERT to prevent official banking pages from being false positives.
TRUSTED_DOMAINS: Final[frozenset[str]] = frozenset({
    "maybank2u.com.my",
    "maybank.com",
    "maybank.com.my",
    "pbebank.com",
    "pbebank.com.my",
    "publicbank.com.my",
    "cimbclicks.com.my",
    "cimb.com.my",
    "cimbbank.com.my",
    "hlb.com.my",
    "hongleongconnect.my",
    "rhbgroup.com",
    "rhbnow.com",
    "rhbbank.com.my",
    "ambankgroup.com",
    "ambank.com.my",
    "bankislam.com",
    "bankislam.com.my",
    "bankrakyat.com.my",
    "bsn.com.my",
    "affinbank.com.my",
    "affinonline.com",
    "alliancebank.com.my",
    "standardchartered.com.my",
    "hsbc.com.my",
    "uob.com.my",
    "ocbc.com.my",
    "bankmuamalat.com.my",
    "agrobank.com.my",
})

TRUSTED_DOMAIN_CONFIDENCE: Final[float] = float(
    os.getenv("PHISHGUARD_TRUSTED_CONFIDENCE", "0.99")
)

# ==============================================================================
# 5b. GLOBAL SAFE DOMAINS (well-known legitimate platforms)
# ==============================================================================
# Major global platforms that the BERT model frequently misclassifies as
# phishing due to login-related vocabulary.  These are checked alongside
# TRUSTED_DOMAINS; a match on either set bypasses BERT inference.
GLOBAL_SAFE_DOMAINS: Final[frozenset[str]] = frozenset({
    # Google
    "google.com",
    "google.com.my",
    "googleapis.com",
    "accounts.google.com",
    "mail.google.com",
    # YouTube
    "youtube.com",
    "youtu.be",
    # WhatsApp
    "whatsapp.com",
    "web.whatsapp.com",
    # Facebook / Meta
    "facebook.com",
    "messenger.com",
    "instagram.com",
    "threads.net",
    # Microsoft
    "microsoft.com",
    "live.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "microsoftonline.com",
    "bing.com",
    "linkedin.com",
    "github.com",
    # Apple
    "apple.com",
    "icloud.com",
    # Amazon
    "amazon.com",
    "amazon.com.my",
    "aws.amazon.com",
    # Twitter / X
    "twitter.com",
    "x.com",
    # Other major platforms
    "reddit.com",
    "wikipedia.org",
    "spotify.com",
    "netflix.com",
    "twitch.tv",
    "discord.com",
    "telegram.org",
    "web.telegram.org",
    "zoom.us",
    "dropbox.com",
    "paypal.com",
    "shopee.com.my",
    "lazada.com.my",
    "grab.com",
    # Malaysian government / education
    "gov.my",
    "edu.my",
    "tarc.edu.my",
    # User added safe domains
    "pixiv.net",
})

# ==============================================================================
# 6. VISUAL IDENTITY ENGINE
# ==============================================================================
VISUAL_MODEL_PATH: Final[str] = os.getenv(
    "PHISHGUARD_VISUAL_MODEL",
    "visual_identity/models/best.pt",
)

VISUAL_CONFIDENCE_THRESHOLD: Final[float] = float(
    os.getenv("PHISHGUARD_VISUAL_CONFIDENCE", "0.85")
)

# ==============================================================================
# 7. MULE SCANNER
# ==============================================================================
# Regex pattern matching 10–14 digit Malaysian bank account numbers.
MULE_ACCOUNT_REGEX: Final[str] = r"\b\d{10,14}\b"

# Bank-specific regex patterns for major Malaysian financial institutions.
# The generic fallback above is still applied after these targeted patterns.
MULE_ACCOUNT_PATTERNS: Final[dict[str, str]] = {
    "Maybank": r"\b[15]\d{11}\b",
    "CIMB Bank": r"\b7\d{13}\b",
    "Public Bank": r"\b3\d{9}\b",
    "RHB Bank": r"\b2\d{13}\b",
    "Hong Leong Bank": r"\b[02]\d{9,11}\b",
    "AmBank": r"\b8\d{12}\b",
    "Bank Islam": r"\b1\d{13}\b",
    "Bank Rakyat": r"\b[02]\d{11}\b",
}

# ==============================================================================
# 8. ORCHESTRATION VERDICTS
# ==============================================================================
VERDICT_BLOCK: Final[str] = "BLOCK_RENDER"
VERDICT_SAFE: Final[str] = "SAFE"
