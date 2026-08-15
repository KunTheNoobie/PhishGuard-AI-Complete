"""
PhishGuard-AI — Batch Forensic Inspector Service.
Analyzes batches of URLs, raw email headers (.eml), and SMS transcripts
in parallel across NLP, Mule Scanner, Brand Profiler, and Heuristic engines.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

from services.brand_profiler import profile_brand_impersonation
from services.heuristic_engine import analyze_url_heuristics
from services.mule_scanner import MuleScanner
from services.nlp_engine import predict_phishing_probability

mule_scanner = MuleScanner()

# Regex patterns for email and URL extraction
URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+",
    re.IGNORECASE,
)
EMAIL_HEADER_FROM = re.compile(r"^From:\s*(.*?)$", re.MULTILINE | re.IGNORECASE)
EMAIL_HEADER_SUBJECT = re.compile(r"^Subject:\s*(.*?)$", re.MULTILINE | re.IGNORECASE)
EMAIL_HEADER_DKIM = re.compile(r"dkim=(pass|fail|neutral|none)", re.IGNORECASE)
EMAIL_HEADER_SPF = re.compile(r"spf=(pass|fail|neutral|softfail|none)", re.IGNORECASE)
EMAIL_HEADER_DMARC = re.compile(r"dmarc=(pass|fail|none)", re.IGNORECASE)


def parse_raw_email(raw_text: str) -> dict[str, Any]:
    """Extract headers, authentication results, and payload artifacts from raw email text."""
    from_match = EMAIL_HEADER_FROM.search(raw_text)
    subject_match = EMAIL_HEADER_SUBJECT.search(raw_text)

    from_header = from_match.group(1).strip() if from_match else "Unknown Sender"
    subject_header = subject_match.group(1).strip() if subject_match else "No Subject"

    # Authentication audit
    dkim_match = EMAIL_HEADER_DKIM.search(raw_text)
    spf_match = EMAIL_HEADER_SPF.search(raw_text)
    dmarc_match = EMAIL_HEADER_DMARC.search(raw_text)

    auth_audit = {
        "dkim": dkim_match.group(1).upper() if dkim_match else "NONE",
        "spf": spf_match.group(1).upper() if spf_match else "NONE",
        "dmarc": dmarc_match.group(1).upper() if dmarc_match else "NONE",
    }

    # Extract all embedded URLs
    extracted_urls = list(set(URL_REGEX.findall(raw_text)))

    # Detect mule accounts inside email body
    mule_matches = mule_scanner.scan_text(raw_text)

    # NLP analysis on subject + body
    nlp_prob, label = predict_phishing_probability(raw_text[:2000])

    # Check for authentication failure spoofing risk
    spoof_risk = False
    if auth_audit["spf"] in ("FAIL", "SOFTFAIL") or auth_audit["dkim"] == "FAIL":
        spoof_risk = True

    return {
        "from": from_header,
        "subject": subject_header,
        "authentication_audit": auth_audit,
        "spoof_risk": spoof_risk,
        "extracted_urls": extracted_urls,
        "mule_matches": [
            {"account": m.account_number, "bank": m.bank_name, "raw": m.matched_text}
            for m in mule_matches
        ],
        "nlp_score": round(nlp_prob, 4),
        "nlp_label": label,
        "body_preview": raw_text[:300].strip(),
    }


def inspect_batch_urls(urls: list[str]) -> dict[str, Any]:
    """Run parallel multi-vector security evaluations on a list of URLs."""
    start_time = time.perf_counter()
    results: list[dict[str, Any]] = []
    high_risk_count = 0

    clean_urls = [u.strip() for u in urls if u.strip() and u.strip().startswith("http")][:50]

    for url in clean_urls:
        nlp_prob, label = predict_phishing_probability(url)
        heuristics = analyze_url_heuristics(url)
        brand_prof = profile_brand_impersonation(url)
        mule_hits = mule_scanner.scan_text(url)

        # Composite score
        base_score = max(nlp_prob, heuristics.get("heuristic_penalty", 0.0))
        if brand_prof.get("is_impersonation"):
            base_score = max(base_score, 0.88)
        composite_score = min(0.99, max(0.05, round(base_score, 4)))

        if composite_score >= 0.60:
            high_risk_count += 1

        results.append({
            "url": url,
            "domain": urlparse(url).netloc,
            "composite_score": composite_score,
            "verdict": "CRITICAL_PHISH" if composite_score >= 0.85 else ("SUSPICIOUS" if composite_score >= 0.60 else "BENIGN"),
            "target_brand": brand_prof.get("target_brand", "Unknown / Generic"),
            "is_brand_spoof": brand_prof.get("is_impersonation", False),
            "heuristic_flags": heuristics.get("indicators", []),
            "mule_accounts": [m.account_number for m in mule_hits],
        })

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "total_analyzed": len(results),
        "high_risk_count": high_risk_count,
        "benign_count": len(results) - high_risk_count,
        "execution_time_ms": elapsed_ms,
        "results": results,
    }
