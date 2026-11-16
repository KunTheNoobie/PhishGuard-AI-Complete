"""
PhishGuard-AI — Corroborated Verdict Engine.
=============================================

Single source of truth for turning independent detection signals into the
``BLOCK_RENDER`` / ``SAFE`` orchestration directive.  Both the extension
endpoint (``/api/v1/analyze/semantics``) and the dashboard quick-scan use
this module so the two paths can never drift apart.

Design rationale
----------------
Evaluation on the Malaysian benchmark (``evaluation/``) showed that no
single probabilistic signal is safe to act on alone: the URL-trained BERT
classifier assigns a high phishing probability to many legitimate deep
links, and a brand name appearing in page text is equally common in news
articles and in phishing clones.  The engine therefore blocks only when
independent signals *corroborate* each other.  The single exception is a
match against the mule-account registry, which is a deterministic lookup
of a reported account rather than an inference.

Signals
-------
``mule``            registry match (deterministic)
``brand_host``      protected brand string inside a foreign hostname
``lookalike``       homoglyph / near-miss look-alike of a protected brand
``brand_mention``   brand named in page text on a non-official domain
``bert``            BERT phishing verdict at or above the configured threshold
``heuristic``       any structural URL anomaly
``heuristic_strong``raw-IP host, punycode host or high-risk TLD
``credential_form`` DOM contains a password / OTP / card input field
``credential_text`` text explicitly requests credentials (word-boundary match)
``scam_language``   coercion / urgency phrase from the multilingual lexicon

Architecture Layer : Service / Decision Orchestration
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

from core.config import BILINGUAL_SCAM_KEYWORDS, VERDICT_BLOCK, VERDICT_SAFE

# ------------------------------------------------------------------------------
# Credential-request detection
# ------------------------------------------------------------------------------
# Unambiguous credential vocabulary, matched on word boundaries.
_CREDENTIAL_TERMS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:pass\s?word|passcode|kata\s+laluan|user\s?name|user\s+id|id\s+pengguna|"
    r"log\s?in|log\s+masuk|sign\s?in|cvv|cvc|seed\s+phrase|private\s+key|"
    r"card\s+number|nombor\s+kad|security\s+code|kod\s+keselamatan|"
    r"verification\s+code|kod\s+pengesahan)\b",
    re.IGNORECASE,
)

# Short tokens ("pin", "tac", "otp", "pac") are ordinary substrings of words
# such as "shopping" or "contact" and ordinary words in their own right
# ("pin this recipe").  They count only inside an explicit request context.
_SHORT_SECRET: Final[str] = r"(?:tac|otp|pin|pac)"
_SHORT_SECRET_CONTEXT: Final[re.Pattern[str]] = re.compile(
    r"\b(?:enter|key\s+in|masukkan|submit|provide|confirm|sahkan|isi)\b(?:\W+\w+){0,4}?\W+" + _SHORT_SECRET + r"\b"
    r"|\b" + _SHORT_SECRET + r"\W+(?:code|kod|number|nombor|anda)\b"
    r"|\b(?:your|anda|6-digit|6\s+digit)\W+(?:\w+\W+)?" + _SHORT_SECRET + r"\b",
    re.IGNORECASE,
)

# CJK has no word boundaries; these terms are unambiguous on their own.
_CJK_CREDENTIAL_TERMS: Final[tuple[str, ...]] = ("密码", "密碼", "验证码", "驗證碼", "登录", "登錄")

# DOM-level evidence: a field that actually collects a secret.
_PASSWORD_INPUT: Final[re.Pattern[str]] = re.compile(
    r"<input\b[^>]*\btype\s*=\s*[\"']?password\b", re.IGNORECASE
)
_SENSITIVE_INPUT: Final[re.Pattern[str]] = re.compile(
    r"<input\b[^>]*\b(?:name|id|autocomplete|placeholder)\s*=\s*[\"']?[^\"'>]*"
    r"(?:one-time-code|cc-number|cc-csc|card[-_ ]?num|cardnumber|\bcvv\b|\bcvc\b|\botp\b|\btac\b|\bpin\b)",
    re.IGNORECASE,
)

_SCAM_PHRASES: Final[tuple[str, ...]] = tuple(kw.lower() for kw in BILINGUAL_SCAM_KEYWORDS)


def has_credential_form(raw_html: str) -> bool:
    """True if the raw DOM contains a password, OTP/TAC/PIN or card field."""
    if not raw_html or "<" not in raw_html:
        return False
    return bool(_PASSWORD_INPUT.search(raw_html) or _SENSITIVE_INPUT.search(raw_html))


def has_credential_text(text: str) -> bool:
    """True if visible text explicitly asks for credentials."""
    if not text:
        return False
    if _CREDENTIAL_TERMS.search(text) or _SHORT_SECRET_CONTEXT.search(text):
        return True
    return any(term in text for term in _CJK_CREDENTIAL_TERMS)


def has_scam_language(text: str) -> bool:
    """True if the text contains a phrase from the multilingual scam lexicon."""
    lowered = (text or "").lower()
    return any(phrase in lowered for phrase in _SCAM_PHRASES)


# ------------------------------------------------------------------------------
# Verdict
# ------------------------------------------------------------------------------

@dataclass
class Verdict:
    """Outcome of the corroboration rules."""

    is_threat: bool
    verdict: str
    risk_score: float
    rule: str | None = None
    indicators: list[str] = field(default_factory=list)
    signals: dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "is_threat": self.is_threat,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "rule": self.rule,
            "indicators": list(self.indicators),
            "signals": dict(self.signals),
        }


def collect_signals(
    *,
    bert_result: dict[str, Any],
    mule_result: dict[str, Any],
    brand_result: dict[str, Any],
    heuristic_result: dict[str, Any],
    sanitized_text: str,
    raw_content: str = "",
) -> dict[str, bool]:
    """Reduce the raw service outputs to the boolean signal vector."""
    content_is_html = "<" in (raw_content or "") and ">" in (raw_content or "")
    credential_form = has_credential_form(raw_content)
    credential_text = has_credential_text(sanitized_text)
    return {
        "mule": bool(mule_result.get("mule_detected") or mule_result.get("flagged_accounts")),
        "brand_host": bool(brand_result.get("brand_in_hostname")),
        "lookalike": bool(brand_result.get("lookalike_domain")),
        "brand_mention": bool(brand_result.get("brand_mentioned")),
        "bert": bool(bert_result.get("is_malicious")),
        "heuristic": bool(heuristic_result.get("is_suspicious")),
        "heuristic_strong": bool(heuristic_result.get("is_strong")),
        "credential_form": credential_form,
        "credential_text": credential_text,
        # When the client supplies real markup, only an actual input field
        # counts as a credential request for the higher-risk rules.  Plain-text
        # submissions fall back to the textual cue.
        "credential_request": credential_form if content_is_html else credential_text,
        "scam_language": has_scam_language(sanitized_text),
    }


def decide(
    *,
    is_trusted: bool,
    bert_result: dict[str, Any],
    mule_result: dict[str, Any],
    brand_result: dict[str, Any],
    heuristic_result: dict[str, Any],
    sanitized_text: str,
    raw_content: str = "",
) -> Verdict:
    """Apply the corroboration rules and return the orchestration verdict."""
    s = collect_signals(
        bert_result=bert_result, mule_result=mule_result, brand_result=brand_result,
        heuristic_result=heuristic_result, sanitized_text=sanitized_text, raw_content=raw_content,
    )
    brand = brand_result.get("target_brand", "a protected brand")
    cues = ", ".join(brand_result.get("matched_brand_cues", [])) or brand
    any_credential = s["credential_form"] or s["credential_text"]

    def blocked(rule: str, score: float, *indicators: str) -> Verdict:
        extra = list(heuristic_result.get("indicators", [])) if s["heuristic"] else []
        return Verdict(True, VERDICT_BLOCK, score, rule, [*indicators, *extra], s)

    # R1 — deterministic registry hit.  Applies even on trusted domains is NOT
    # desirable (marketplaces legitimately host user content), so trusted
    # domains are reported but never blocked.
    if is_trusted:
        notes = ["Domain is on the trusted whitelist"]
        if s["mule"]:
            notes.append("Registered mule account displayed on a trusted domain (reported, not blocked)")
        return Verdict(False, VERDICT_SAFE, 0.0, None, notes, s)

    if s["mule"]:
        accounts = ", ".join(str(a.get("account_number")) for a in mule_result.get("flagged_accounts", []))
        return blocked("R1_MULE_REGISTRY", 0.99, f"Account found in mule registry: {accounts}")

    if s["brand_host"] and (any_credential or s["scam_language"] or s["bert"] or s["heuristic"]):
        return blocked("R2_BRAND_IN_HOSTNAME", 0.97,
                       f"Hostname embeds protected brand '{brand}' ({cues}) on a domain it does not own")

    if s["lookalike"] and (any_credential or s["bert"] or s["heuristic_strong"]):
        return blocked("R3_LOOKALIKE_DOMAIN", 0.95, f"Hostname is a {cues} ({brand})")

    if s["brand_mention"] and s["credential_request"] and (s["bert"] or s["heuristic"] or s["scam_language"]):
        return blocked("R4_BRAND_CLONE", 0.93,
                       f"Page presents itself as '{brand}' and requests credentials on an unaffiliated domain")

    if s["credential_request"] and s["scam_language"] and (s["bert"] or s["heuristic"]):
        return blocked("R5_COERCIVE_CREDENTIAL_REQUEST", 0.90,
                       "Coercive or urgent language combined with a credential request")

    if s["heuristic_strong"] and s["bert"] and (any_credential or s["scam_language"] or s["brand_mention"]):
        return blocked("R6_EVASIVE_INFRASTRUCTURE", 0.90,
                       "Evasive hosting (raw IP, punycode or disposable TLD) with phishing content cues")

    # Not corroborated: surface the residual suspicion as a low advisory score.
    confidence = float(bert_result.get("confidence", 0.0))
    p_phish = confidence if bert_result.get("label") == "PHISHING" else 1.0 - confidence
    weak = sum(s[k] for k in ("bert", "heuristic", "brand_mention", "scam_language", "credential_request",
                              "brand_host", "lookalike"))
    advisory = round(min(0.49, 0.10 * weak + 0.10 * p_phish), 4)
    notes = []
    if s["bert"]:
        notes.append("URL classifier raised suspicion but no independent signal corroborated it")
    if s["brand_mention"]:
        notes.append(f"Mentions '{brand}' (informational)")
    return Verdict(False, VERDICT_SAFE, advisory, None, notes, s)
