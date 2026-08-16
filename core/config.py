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
    "Enterprise-grade SOC Cyber Defense & Multi-Vector Threat Intelligence Platform v3.0. "
    "Performs real-time BERT semantic NLP classification, Brand Homoglyph profiling, Mule syndicate tracking, "
    "NSRC 997 & National Fraud Portal gateway orchestration, TAXII 2.1 STIX syndication, Quishing QR inspection, "
    "Pre-emptive Typosquatting radar, and Autonomous Incident Playbooks."
)
APP_VERSION: Final[str] = "3.0.0"

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
})

TRUSTED_DOMAIN_CONFIDENCE: Final[float] = float(
    os.getenv("PHISHGUARD_TRUSTED_CONFIDENCE", "0.99")
)

# ==============================================================================
# 5b. GLOBAL SAFE DOMAINS (well-known legitimate platforms worldwide)
# ==============================================================================
# Major global platforms and financial infrastructure that users browse daily.
# These are checked alongside TRUSTED_DOMAINS to ensure 0 false positives on official sites.
GLOBAL_SAFE_DOMAINS: Final[frozenset[str]] = frozenset({
    # ── Search Engines & AI Platforms ──
    "google.com", "google.com.my", "googleapis.com", "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com", "play.google.com",
    "bing.com", "yahoo.com", "mail.yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "deepmind.google", "gemini.google.com", "huggingface.co", "perplexity.ai",

    # ── Social, Messaging & Media Platforms ──
    "youtube.com", "youtu.be", "whatsapp.com", "web.whatsapp.com", "facebook.com", "messenger.com", "instagram.com", "threads.net", "meta.com", "business.facebook.com",
    "twitter.com", "x.com", "t.co", "linkedin.com", "reddit.com", "pinterest.com", "tumblr.com", "tiktok.com", "snapchat.com",
    "discord.com", "discordapp.com", "telegram.org", "web.telegram.org", "signal.org", "wechat.com", "line.me", "skype.com", "teams.microsoft.com", "zoom.us", "zoom.com", "slack.com",

    # ── Tech Giants, OS & Hardware ──
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "github.com",
    "apple.com", "icloud.com", "itunes.apple.com", "developer.apple.com",
    "amazon.com", "amazon.com.my", "aws.amazon.com", "primevideo.com", "twitch.tv",
    "samsung.com", "sony.com", "playstation.com", "xbox.com", "nintendo.com", "steamcommunity.com", "steampowered.com", "epicgames.com", "roblox.com",

    # ── Global Financial & Banking Institutions ──
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com", "capitalone.com", "americanexpress.com", "discover.com", "usbank.com", "pnc.com", "td.com", "tdbank.com", "schwab.com", "fidelity.com", "vanguard.com",
    "hsbc.com", "hsbc.com.my", "hsbc.co.uk", "barclays.co.uk", "barclays.com", "lloydsbank.com", "natwest.com", "santander.com", "santander.co.uk", "bnpparibas.com", "db.com", "ubs.com", "credit-suisse.com", "ing.com", "bbva.com",
    "dbs.com", "dbs.com.sg", "posb.com.sg", "ocbc.com", "ocbc.com.sg", "uob.com", "uob.com.sg", "sc.com", "standardchartered.com", "boc.cn", "icbc.com.cn", "ccb.com", "mufg.jp", "smbc.co.jp", "mizuho-fg.co.jp", "hangseng.com", "hkbea.com",

    # ── Global Fintech, Payments & Wallets ──
    "paypal.com", "paypal.me", "stripe.com", "wise.com", "revolut.com", "square.com", "squareup.com", "venmo.com", "zellepay.com", "klarna.com", "adyen.com", "shopify.com", "myshopify.com",
    "touchngo.com.my", "tngdigital.com.my", "grab.com", "foodpanda.com", "foodpanda.my", "boost-my.com", "myboost.com.my", "bigpayme.com", "duitnow.my", "paynet.my",

    # ── Global Crypto & Web3 (Official) ──
    "binance.com", "coinbase.com", "kraken.com", "crypto.com", "kucoin.com", "okx.com", "bybit.com", "metamask.io", "trustwallet.com", "etherscan.io", "blockchain.com", "coinmarketcap.com", "coingecko.com",

    # ── Cloud, Hosting, CDN & Developer Ecosystem ──
    "cloudflare.com", "fastly.com", "akamai.com", "digitalocean.com", "heroku.com", "vercel.com", "vercel.app", "netlify.com", "netlify.app", "render.com", "firebaseapp.com", "web.app", "supabase.com",
    "gitlab.com", "bitbucket.org", "stackoverflow.com", "npmjs.com", "pypi.org", "docker.com", "w3.org", "mozilla.org", "developer.mozilla.org",

    # ── Productivity, Design & Enterprise SaaS ──
    "canva.com", "figma.com", "adobe.com", "notion.so", "miro.com", "trello.com", "atlassian.com", "jira.com", "salesforce.com", "hubspot.com", "zendesk.com", "asana.com", "monday.com", "clickup.com",
    "dropbox.com", "box.com", "wordpress.com", "medium.com", "substack.com", "patreon.com", "intuit.com", "turbotax.com", "quickbooks.com",

    # ── E-Commerce & Marketplaces (Global & Regional) ──
    "shopee.com.my", "shopee.sg", "shopee.co.id", "shopee.tw", "shopee.vn", "lazada.com.my", "lazada.sg", "lazada.co.id",
    "alibaba.com", "aliexpress.com", "taobao.com", "jd.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com", "etsy.com", "mudah.my", "carousell.com.my", "carousell.sg", "rakuten.co.jp",

    # ── Streaming, Music & Media ──
    "netflix.com", "spotify.com", "disneyplus.com", "hulu.com", "hbomax.com", "max.com", "vimeo.com", "soundcloud.com", "crunchyroll.com",

    # ── Global News, Reference & Education ──
    "wikipedia.org", "archive.org", "quora.com", "cnn.com", "bbc.com", "nytimes.com", "theguardian.com", "reuters.com", "bloomberg.com", "forbes.com", "wsj.com", "theverge.com", "techcrunch.com", "wired.com",
    "thestar.com.my", "malaysiakini.com", "freemalaysiatoday.com", "nst.com.my", "bharian.com.my", "sinchew.com.my", "orientaldaily.com.my",
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org",

    # ── Government, Public Sector & Education TLDs / Domains ──
    "gov.my", "edu.my", "tarc.edu.my", "um.edu.my", "usm.my", "utm.my", "upm.edu.my", "ukm.my", "hasil.gov.my", "epf.gov.my", "kwsp.gov.my", "myeg.com.my", "jpa.gov.my", "moe.gov.my", "moh.gov.my", "mcmc.gov.my",
    "gov.sg", "edu.sg", "nus.edu.sg", "ntu.edu.sg", "gov.uk", "ac.uk", "ox.ac.uk", "cam.ac.uk", "mit.edu", "stanford.edu", "harvard.edu", "europa.eu", "un.org", "who.int",
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
    "DuitNow Mobile / Phone": r"\b(?:\+?601[0-9]|01[0-9])[- ]?[0-9]{7,8}\b",
    "DuitNow National ID / IC": r"\b\d{6}-\d{2}-\d{4}\b",
}

DUITNOW_PHONE_REGEX: Final[str] = r"\b(?:\+?601[0-9]|01[0-9])[- ]?[0-9]{7,8}\b"
MALAYSIAN_IC_REGEX: Final[str] = r"\b\d{6}-\d{2}-\d{4}\b"

# ==============================================================================
# 8. ORCHESTRATION VERDICTS & MULTI-LINGUAL GLOBAL SCAM LEXICON
# ==============================================================================
VERDICT_BLOCK: Final[str] = "BLOCK_RENDER"
VERDICT_SAFE: Final[str] = "SAFE"

BILINGUAL_SCAM_KEYWORDS: Final[list[str]] = [
    # English (Global Phishing Lures)
    "urgent verification", "immediate verification", "account suspension", "account suspended",
    "flagged for suspicious", "pdrm verification", "authorized pdrm", "transfer verification",
    "avoid account closure", "avoid suspension", "verify account now", "update login details",
    "unauthorized login", "security alert", "temporary freeze", "reactivate account",
    "transfer deposit", "security deposit", "verify immediately", "claim e-wallet credit",
    "confirm identity", "billing error", "wire transfer required", "unusual sign-in activity",
    "click to restore access", "payment failed", "update payment method", "re-authenticate",
    "security verification code", "crypto recovery", "wallet validation", "unlock wallet",
    # Bahasa Melayu & Manglish
    "akaun digantung", "akaun disekat", "tindakan segera", "pengesahan keselamatan",
    "saman tertunggak", "pdrm saman", "tuntutan bantuan tunai", "bantuan e-wallet",
    "kemaskini maklumat", "tukar kata laluan", "bayaran deposit", "cukai lhdn tertunggak",
    "sekat kad debit", "log masuk tidak sah", "pengesahan maybank", "pengesahan cimb",
    "kemaskini perbankan", "tebus hadiah", "akaun anda dibekukan", "pembayaran disekat",
    # Chinese (Simplified & Traditional)
    "账号异常", "账户冻结", "立即验证", "紧急通知", "安全警报", "更新支付信息",
    "交通罚单", "解除冻结", "实名认证", "密码已过期", "微信安全验证", "支付宝风控",
    # Bahasa Indonesia
    "akun diblokir", "verifikasi segera", "peringatan keamanan", "transaksi mencurigakan",
    "perbarui kata sandi", "klaim saldo e-wallet",
]

