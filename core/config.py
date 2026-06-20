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

# Confidence threshold above which a DOM payload is flagged as malicious.
# label 1 = "PHISHING" at or above this threshold triggers BLOCK_RENDER.
MALICIOUS_THRESHOLD: Final[float] = float(
    os.getenv("PHISHGUARD_MALICIOUS_THRESHOLD", "0.75")
)

# ==============================================================================
# 6. MULE SCANNER
# ==============================================================================
# Generic fallback regex matching 10–14 digit Malaysian bank account numbers.
MULE_ACCOUNT_REGEX: Final[str] = r"\b\d{10,14}\b"

# Bank-specific regex patterns for major Malaysian financial institutions.
# Each pattern is tuned to the account-number format issued by that bank,
# significantly reducing false positives compared to the generic fallback.
MULE_ACCOUNT_PATTERNS: Final[dict[str, str]] = {
    "Maybank":          r"\b[15]\d{11}\b",      # 12 digits, starts with 1 or 5
    "CIMB Bank":        r"\b7\d{13}\b",          # 14 digits, starts with 7
    "Public Bank":      r"\b3\d{9}\b",           # 10 digits, starts with 3
    "RHB Bank":         r"\b2\d{13}\b",          # 14 digits, starts with 2
    "Hong Leong Bank":  r"\b[02]\d{9,11}\b",     # 10–12 digits, starts with 0 or 2
    "AmBank":           r"\b8\d{12}\b",          # 13 digits, starts with 8
    "Bank Islam":       r"\b1\d{13}\b",          # 14 digits, starts with 1
    "Bank Rakyat":      r"\b[02]\d{11}\b",       # 12 digits, starts with 0 or 2
}

# ==============================================================================
# 7. ORCHESTRATION VERDICTS
# ==============================================================================
VERDICT_BLOCK: Final[str] = "BLOCK_RENDER"
VERDICT_SAFE: Final[str] = "SAFE"
