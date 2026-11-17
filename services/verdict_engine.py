"""
PhishGuard-AI — Corroborated Verdict Engine.
=============================================

Turns the independent detection signals into one of three verdicts and
explains it in plain language:

``SAFE``          green — HTTPS and no corroborated threat.
``WARNING``       amber — not secure (plain HTTP, certificate error) or a
                  single strong impersonation cue that nothing corroborated.
``BLOCK_RENDER``  red   — a corroborated phishing / scam pattern, or a
                  password / payment form sent over unencrypted HTTP.

Design rule: no probabilistic signal blocks a page on its own.  Evaluation
showed that the URL-trained BERT model and a brand name in page text are
each wrong too often (78% of legitimate Malaysian pages were blocked when
BERT acted alone).  A block therefore needs independent evidence, except for
deterministic facts: a registry match (R1), a URL that hides its real host
behind ``@`` (R7), and a sensitive form on an unencrypted page (H1).

Rules (first match wins)
------------------------
R1  account on the page is in the mule registry
R7  userinfo before '@' disguises the real destination
R2  protected brand inside a foreign hostname + any corroborating cue
R3  look-alike / homoglyph of a brand + credentials, BERT, strong structure or logo
R8  bank logo detected (YOLOv8n) on a foreign domain + credentials, BERT, scam wording or structure
R4  brand named in text + credential request + BERT, structure or scam wording
R5  credential request + coercive wording + BERT or structure
R6  evasive hosting (raw IP, punycode, abused TLD) + BERT + content cue
R9  password / card / OTP form on a free hosting platform + BERT, brand mention or scam wording
H1  password / card / OTP form on plain HTTP                 → BLOCK
H2  plain HTTP                                                → WARNING
W1  certificate could not be verified (server-side fetch)     → WARNING
W2  single strong impersonation cue, uncorroborated           → WARNING
W3  password / card / OTP form on a free hosting platform     → WARNING

Architecture Layer : Service / Decision
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

from core.brands import BRANDS
from core.config import BILINGUAL_SCAM_KEYWORDS, VERDICT_BLOCK, VERDICT_SAFE, VERDICT_WARNING
from services.url_canonicalizer import CanonicalURL

# ------------------------------------------------------------------------------
# Page-content detectors
# ------------------------------------------------------------------------------
_CREDENTIAL_TERMS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:pass\s?word|passcode|kata\s+laluan|user\s?name|user\s+id|id\s+pengguna|log\s?in|log\s+masuk|"
    r"sign\s?in|cvv|cvc|seed\s+phrase|private\s+key|card\s+number|nombor\s+kad|security\s+code|"
    r"kod\s+keselamatan|verification\s+code|kod\s+pengesahan)\b",
    re.IGNORECASE,
)
# "pin", "tac", "otp" are substrings of ordinary words; count them only in a request context.
_SHORT_SECRET: Final[str] = r"(?:tac|otp|pin|pac)"
_SHORT_SECRET_CONTEXT: Final[re.Pattern[str]] = re.compile(
    r"\b(?:enter|key\s+in|masukkan|submit|provide|confirm|sahkan|isi)\b(?:\W+\w+){0,4}?\W+" + _SHORT_SECRET + r"\b"
    r"|\b" + _SHORT_SECRET + r"\W+(?:code|kod|number|nombor|anda)\b"
    r"|\b(?:your|anda|6-digit|6\s+digit)\W+(?:\w+\W+)?" + _SHORT_SECRET + r"\b",
    re.IGNORECASE,
)
_CJK_CREDENTIAL_TERMS: Final[tuple[str, ...]] = ("密码", "密碼", "验证码", "驗證碼", "登录", "登錄")

_PASSWORD_INPUT: Final[re.Pattern[str]] = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password\b", re.IGNORECASE)
_PAYMENT_INPUT: Final[re.Pattern[str]] = re.compile(
    r"<input\b[^>]*\b(?:name|id|autocomplete|placeholder)\s*=\s*[\"']?[^\"'>]*"
    r"(?:cc-number|cc-csc|cc-exp|card[-_ ]?num|cardnumber|\bcvv\b|\bcvc\b|expiry)",
    re.IGNORECASE,
)
_SECRET_INPUT: Final[re.Pattern[str]] = re.compile(
    r"<input\b[^>]*\b(?:name|id|autocomplete|placeholder)\s*=\s*[\"']?[^\"'>]*"
    r"(?:one-time-code|\botp\b|\btac\b|\bpin\b)",
    re.IGNORECASE,
)
_SCAM_PHRASES: Final[tuple[str, ...]] = tuple(kw.lower() for kw in BILINGUAL_SCAM_KEYWORDS)


def detect_sensitive_fields(raw_html: str) -> list[str]:
    """Return the kinds of sensitive input the page's HTML contains."""
    if not raw_html or "<" not in raw_html:
        return []
    kinds = []
    if _PASSWORD_INPUT.search(raw_html):
        kinds.append("password")
    if _PAYMENT_INPUT.search(raw_html):
        kinds.append("payment card")
    if _SECRET_INPUT.search(raw_html):
        kinds.append("OTP / TAC / PIN")
    return kinds


def has_credential_form(raw_html: str) -> bool:
    """True if the DOM contains a password, payment-card or OTP/TAC/PIN field."""
    return bool(detect_sensitive_fields(raw_html))


def has_credential_text(text: str) -> bool:
    """True if visible text explicitly asks for credentials."""
    if not text:
        return False
    if _CREDENTIAL_TERMS.search(text) or _SHORT_SECRET_CONTEXT.search(text):
        return True
    return any(term in text for term in _CJK_CREDENTIAL_TERMS)


def scam_phrases(text: str) -> list[str]:
    """Phrases from the multilingual scam lexicon that occur in ``text``."""
    lowered = (text or "").lower()
    return [phrase for phrase in _SCAM_PHRASES if phrase in lowered]


def has_scam_language(text: str) -> bool:
    return bool(scam_phrases(text))


# ------------------------------------------------------------------------------
# Verdict
# ------------------------------------------------------------------------------
RISK_LEVEL: Final[dict[str, str]] = {VERDICT_SAFE: "safe", VERDICT_WARNING: "warning", VERDICT_BLOCK: "dangerous"}


@dataclass
class Verdict:
    """Outcome of the rules, with its plain-language explanation."""

    verdict: str
    risk_score: float
    rule: str | None
    headline: str
    explanation: str
    reasons: list[dict[str, str]] = field(default_factory=list)
    signals: dict[str, bool] = field(default_factory=dict)

    @property
    def is_threat(self) -> bool:
        return self.verdict == VERDICT_BLOCK

    @property
    def risk_level(self) -> str:
        return RISK_LEVEL[self.verdict]

    @property
    def indicators(self) -> list[str]:
        return [r["text"] for r in self.reasons if r["severity"] in ("high", "medium")]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict, "risk_level": self.risk_level, "risk_score": self.risk_score,
            "rule": self.rule, "headline": self.headline, "explanation": self.explanation,
            "reasons": list(self.reasons), "signals": dict(self.signals),
        }


_BRAND_STRINGS: Final[tuple[str, ...]] = tuple(
    s for info in BRANDS.values() for s in (*info["host_strings"], *info["host_tokens"]) if len(s) >= 3
)


def _userinfo_spoof(c: CanonicalURL) -> bool:
    """A user name that looks like a domain or names a brand exists only to fool the reader."""
    info = c.userinfo.lower()
    return bool(info) and ("." in info or any(b in info for b in _BRAND_STRINGS))


def _brand_name(brand_result: dict[str, Any], visual_result: dict[str, Any] | None) -> str:
    """The brand to name in a message: the one in the address, else the one whose logo was seen, else a generic phrase."""
    if brand_result.get("target_brand"):
        return brand_result["target_brand"]
    logos = (visual_result or {}).get("detected_logos") or []
    return logos[0]["brand"] if logos else "protected brand"


def collect_signals(
    *,
    canon: CanonicalURL,
    bert_result: dict[str, Any],
    mule_result: dict[str, Any],
    brand_result: dict[str, Any],
    heuristic_result: dict[str, Any],
    visual_result: dict[str, Any] | None,
    sanitized_text: str,
    raw_content: str,
    tls_error: str | None = None,
) -> dict[str, bool]:
    """Reduce the raw service outputs to the boolean signal vector."""
    content_is_html = "<" in (raw_content or "") and ">" in (raw_content or "")
    fields = detect_sensitive_fields(raw_content)
    credential_text = has_credential_text(sanitized_text)
    visual = visual_result or {}
    return {
        "mule": bool(mule_result.get("flagged_accounts")),
        "userinfo_spoof": _userinfo_spoof(canon),
        "brand_host": bool(brand_result.get("brand_in_hostname")),
        "lookalike": bool(brand_result.get("lookalike_domain")),
        "brand_mention": bool(brand_result.get("brand_mentioned")),
        "visual_mismatch": visual.get("risk_level") in ("dangerous", "suspicious") and bool(visual.get("detected_logos")),
        "bert": bool(bert_result.get("is_malicious")),
        "heuristic": bool(heuristic_result.get("is_suspicious")),
        "heuristic_strong": bool(heuristic_result.get("is_strong")),
        "free_hosting": bool(heuristic_result.get("free_hosting")),
        "credential_form": bool(fields),
        "credential_text": credential_text,
        # With real markup only an actual input field counts as a credential
        # request; plain-text submissions fall back to the wording.
        "credential_request": bool(fields) if content_is_html else credential_text,
        "scam_language": has_scam_language(sanitized_text),
        "insecure_http": canon.scheme == "http",
        "tls_error": bool(tls_error),
    }


def _reasons(
    s: dict[str, bool], *, canon: CanonicalURL, is_trusted: bool, bert_result: dict[str, Any],
    mule_result: dict[str, Any], brand_result: dict[str, Any], heuristic_result: dict[str, Any],
    visual_result: dict[str, Any] | None, sanitized_text: str, raw_content: str, tls_error: str | None,
) -> list[dict[str, str]]:
    """Human-readable reasons, most serious first."""
    out: list[tuple[int, str, str]] = []
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}

    def add(sev: str, text: str) -> None:
        out.append((rank[sev], sev, text))

    brand = _brand_name(brand_result, visual_result)
    host = canon.hostname
    p_phish = float(bert_result.get("phishing_probability", 0.0))

    for acc in mule_result.get("flagged_accounts", []):
        add("high", f"Account {acc['account_number']} on this page is in the mule-account registry "
                    f"({acc.get('bank_name', 'bank unknown')}, reported {acc.get('report_count', 1)} time(s)).")
    if s["userinfo_spoof"]:
        add("high", f"The link is disguised: '{canon.userinfo[:60]}' before '@' is only a user name; "
                    f"the browser really opens {host}.")
    if s["brand_host"]:
        cues = ", ".join(brand_result.get("matched_brand_cues", []))
        add("high", f"The address uses the name of {brand} ({cues}), but {host} does not belong to {brand}.")
    if s["lookalike"]:
        cues = ", ".join(brand_result.get("matched_brand_cues", []))
        add("high", f"The address imitates {brand} ({cues}).")
    if s["visual_mismatch"]:
        logos = ", ".join(sorted({d.get("brand", "?") for d in (visual_result or {}).get("detected_logos", [])}))
        add("high", f"The page shows the {logos} logo, but {host} is not an official {logos} website.")
    fields = detect_sensitive_fields(raw_content)
    if fields:
        add("high" if s["insecure_http"] else "medium",
            f"The page asks for sensitive data ({', '.join(fields)})"
            + (" over an unencrypted connection, so it can be read by anyone on the network." if s["insecure_http"] else "."))
    elif s["credential_text"] and s["credential_request"]:
        add("medium", "The page text asks for log-in details or a security code.")
    phrases = scam_phrases(sanitized_text)
    if phrases:
        add("medium", "Urgent or threatening wording typical of scams: " + ", ".join(f"'{p}'" for p in phrases[:3]) + ".")
    if s["bert"]:
        add("medium", f"The AI URL model rates this address {p_phish:.0%} likely to be phishing.")
    for text in heuristic_result.get("strong_indicators", []):
        if "before '@'" not in text or not s["userinfo_spoof"]:
            add("medium", text + ".")
    for text in heuristic_result.get("indicators", []):
        if text not in heuristic_result.get("strong_indicators", []):
            add("low", text + ".")
    if s["insecure_http"]:
        add("medium", "The connection is not encrypted (HTTP). Anything you type or see can be read "
                      "or changed by others on the network.")
    if s["tls_error"]:
        add("medium", f"The site's security certificate could not be verified ({tls_error}).")
    if s["brand_mention"] and not (s["brand_host"] or s["lookalike"]):
        add("info", f"Mentions {brand}; this alone is not suspicious.")

    if is_trusted:
        owner = brand_result.get("target_brand")
        add("ok", f"{host} is an official {owner} domain." if brand_result.get("is_official_domain") and owner
            else f"{host} is a well-known website on the trusted list.")
    if not s["insecure_http"]:
        add("ok", "The connection is encrypted (HTTPS).")
    if bert_result.get("skipped"):
        add("ok", "AI URL check skipped for a trusted domain.")
    elif not s["bert"] and "phishing_probability" in bert_result:
        add("ok", f"The AI URL model rates this address {1 - p_phish:.0%} likely to be legitimate.")
    if not s["mule"]:
        n = len(mule_result.get("accounts_extracted", []))
        add("ok", f"{n} account number(s) checked; none is in the mule registry." if n
            else "No bank-account numbers found on the page.")
    if not (s["brand_host"] or s["lookalike"] or s["visual_mismatch"]) and not is_trusted:
        add("ok", "No impersonation of a protected brand found.")

    out.sort(key=lambda item: item[0])
    return [{"severity": sev, "text": text} for _, sev, text in out]


_HEADLINES: Final[dict[str, str]] = {
    "R1_MULE_REGISTRY": "Known scam bank account on this page",
    "R7_USERINFO_SPOOF": "Disguised link hides the real website",
    "R2_BRAND_IN_HOSTNAME": "Fake {brand} website",
    "R3_LOOKALIKE_DOMAIN": "Look-alike of {brand}",
    "R8_VISUAL_BRAND_MISMATCH": "Copy of the {brand} website",
    "R4_BRAND_CLONE": "Fake {brand} log-in page",
    "R5_COERCIVE_CREDENTIAL_REQUEST": "Scam page asking for your details",
    "R6_EVASIVE_INFRASTRUCTURE": "Phishing page on evasive hosting",
    "R9_FREE_HOSTING_CREDENTIAL_FORM": "Log-in form on a throw-away hosting site",
    "H1_HTTP_SENSITIVE_FORM": "Unencrypted page asking for passwords or payment",
    "H2_INSECURE_HTTP": "Not secure: unencrypted connection (HTTP)",
    "W1_TLS_CERTIFICATE": "Security certificate could not be verified",
    "W2_UNCORROBORATED_IMPERSONATION": "Possible impersonation of {brand}",
    "W3_FREE_HOSTING_FORM": "Log-in form on a free hosting site",
}


def decide(
    *,
    canon: CanonicalURL,
    is_trusted: bool,
    bert_result: dict[str, Any],
    mule_result: dict[str, Any],
    brand_result: dict[str, Any],
    heuristic_result: dict[str, Any],
    sanitized_text: str,
    raw_content: str = "",
    visual_result: dict[str, Any] | None = None,
    tls_error: str | None = None,
) -> Verdict:
    """Apply the rules and return the explained verdict."""
    s = collect_signals(
        canon=canon, bert_result=bert_result, mule_result=mule_result, brand_result=brand_result,
        heuristic_result=heuristic_result, visual_result=visual_result, sanitized_text=sanitized_text,
        raw_content=raw_content, tls_error=tls_error,
    )
    reasons = _reasons(
        s, canon=canon, is_trusted=is_trusted, bert_result=bert_result, mule_result=mule_result,
        brand_result=brand_result, heuristic_result=heuristic_result, visual_result=visual_result,
        sanitized_text=sanitized_text, raw_content=raw_content, tls_error=tls_error,
    )
    brand = _brand_name(brand_result, visual_result)
    any_credential = s["credential_form"] or s["credential_text"]

    def make(verdict: str, rule: str | None, score: float) -> Verdict:
        headline = _HEADLINES.get(rule or "", "").format(brand=brand) if rule else (
            f"Official {brand} website" if is_trusted and brand_result.get("is_official_domain")
            else "Trusted website" if is_trusted else "No threats found")
        serious = [r["text"] for r in reasons if r["severity"] in ("high", "medium")]
        if verdict == VERDICT_BLOCK:
            explanation = "PhishGuard blocked this page. " + " ".join(serious[:3])
        elif verdict == VERDICT_WARNING:
            explanation = "Be careful on this page. " + " ".join(serious[:2])
        else:
            explanation = ("The connection is encrypted and none of the checks found a phishing or scam pattern."
                           if not serious else
                           "No corroborated threat. " + serious[0] + " Nothing else supports it, so the page is allowed.")
        return Verdict(verdict, round(score, 4), rule, headline, explanation.strip(), reasons, s)

    # Trusted domains: only transport security can lower the verdict.
    if is_trusted:
        if s["insecure_http"] and s["credential_request"]:
            return make(VERDICT_BLOCK, "H1_HTTP_SENSITIVE_FORM", 0.90)
        if s["insecure_http"]:
            return make(VERDICT_WARNING, "H2_INSECURE_HTTP", 0.50)
        return make(VERDICT_SAFE, None, 0.0)

    if s["mule"]:
        return make(VERDICT_BLOCK, "R1_MULE_REGISTRY", 0.99)
    if s["userinfo_spoof"]:
        return make(VERDICT_BLOCK, "R7_USERINFO_SPOOF", 0.96)
    if s["brand_host"] and (any_credential or s["scam_language"] or s["bert"] or s["heuristic"] or s["visual_mismatch"]):
        return make(VERDICT_BLOCK, "R2_BRAND_IN_HOSTNAME", 0.97)
    if s["lookalike"] and (any_credential or s["bert"] or s["heuristic_strong"] or s["visual_mismatch"]):
        return make(VERDICT_BLOCK, "R3_LOOKALIKE_DOMAIN", 0.95)
    if s["visual_mismatch"] and (s["credential_request"] or s["bert"] or s["scam_language"] or s["heuristic"]):
        return make(VERDICT_BLOCK, "R8_VISUAL_BRAND_MISMATCH", 0.94)
    if s["brand_mention"] and s["credential_request"] and (s["bert"] or s["heuristic"] or s["scam_language"]):
        return make(VERDICT_BLOCK, "R4_BRAND_CLONE", 0.93)
    if s["credential_request"] and s["scam_language"] and (s["bert"] or s["heuristic"]):
        return make(VERDICT_BLOCK, "R5_COERCIVE_CREDENTIAL_REQUEST", 0.90)
    if s["heuristic_strong"] and s["bert"] and (any_credential or s["scam_language"] or s["brand_mention"]):
        return make(VERDICT_BLOCK, "R6_EVASIVE_INFRASTRUCTURE", 0.90)
    if s["free_hosting"] and s["credential_form"] and (s["bert"] or s["brand_mention"] or s["scam_language"]):
        return make(VERDICT_BLOCK, "R9_FREE_HOSTING_CREDENTIAL_FORM", 0.90)
    if s["insecure_http"] and s["credential_request"]:
        return make(VERDICT_BLOCK, "H1_HTTP_SENSITIVE_FORM", 0.90)
    if s["insecure_http"]:
        return make(VERDICT_WARNING, "H2_INSECURE_HTTP", 0.55)
    if s["tls_error"]:
        return make(VERDICT_WARNING, "W1_TLS_CERTIFICATE", 0.60)
    if s["brand_host"] or s["lookalike"] or s["visual_mismatch"]:
        return make(VERDICT_WARNING, "W2_UNCORROBORATED_IMPERSONATION", 0.65)
    if s["free_hosting"] and s["credential_form"]:
        return make(VERDICT_WARNING, "W3_FREE_HOSTING_FORM", 0.60)

    # Not corroborated: keep the residual suspicion as a low advisory score.
    p_phish = float(bert_result.get("phishing_probability", 0.0))
    weak = sum(s[k] for k in ("bert", "heuristic", "brand_mention", "scam_language", "credential_request"))
    return make(VERDICT_SAFE, None, min(0.49, 0.10 * weak + 0.10 * p_phish))
