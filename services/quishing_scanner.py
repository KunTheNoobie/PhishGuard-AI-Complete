"""services/quishing_scanner.py — Quishing (QR-Code Phishing) & Deceptive Payload Analyzer.

Extracts, decodes, and forensically audits QR-code payloads (such as fake PDRM parking summons,
forged DuitNow merchant stickers, and deceptive document redirects) against PhishGuard multi-vector AI.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse


def scan_quishing_payload(
    raw_payload: str,
    target_context: str = "QR Code Scan",
) -> dict[str, Any]:
    """Analyze a decoded QR-code payload or image link for phishing indicators."""
    text = (raw_payload or "").strip()

    # Detect DuitNow QR URI Scheme (e.g. duitnow://pay?acc=112233445566&bank=Maybank)
    is_duitnow_uri = "duitnow:" in text.lower() or "paynet" in text.lower() or "dnow" in text.lower()
    
    extracted_mule_accounts: list[str] = []
    extracted_urls: list[str] = []
    
    # Extract embedded URLs
    url_matches = re.findall(r"https?://[^\s<>\"']+", text)
    for u in url_matches:
        extracted_urls.append(u)

    # Extract account numbers (numeric 9-16 digits)
    account_matches = re.findall(r"\b\d{9,16}\b", text)
    for acc in account_matches:
        extracted_mule_accounts.append(acc)

    # If raw payload is itself a URL
    if not extracted_urls and (text.startswith("http://") or text.startswith("https://") or ".com" in text or ".my" in text or ".top" in text):
        extracted_urls.append(text if "://" in text else f"http://{text}")

    # Evaluate Risk Score
    risk_factors: list[str] = []
    base_score = 0.15

    lower_text = text.lower()
    if any(k in lower_text for k in ["maybank", "cimb", "pbb", "rhb", "hlb", "islam", "tng", "duitnow"]):
        risk_factors.append("Financial Brand Keyword Impersonation inside QR Payload")
        base_score += 0.35

    if any(k in lower_text for k in ["saman", "pdrm", "traffic", "dbkl", "jpj", "fine"]):
        risk_factors.append("PDRM / Government Fine Urgency Trigger (Quishing Summon Scam)")
        base_score += 0.40

    if any(k in lower_text for k in [".top", ".xyz", ".cc", "free", "claim", "voucher", "verify"]):
        risk_factors.append("Suspicious TLD or Fraudulent Promotional Lure")
        base_score += 0.30

    if is_duitnow_uri or extracted_mule_accounts:
        risk_factors.append("Direct Peer-to-Peer / Unregistered Mule Account Exfiltration Target")
        base_score += 0.25

    final_score = round(min(0.99, max(0.05, base_score)), 3)
    verdict = "MALICIOUS QUISHING (High-Risk QR Phishing)" if final_score >= 0.75 else \
              "SUSPICIOUS QR PAYLOAD (Elevated Caution)" if final_score >= 0.50 else "BENIGN QR CONTENT"

    primary_url = extracted_urls[0] if extracted_urls else ""
    return {
        "raw_payload": text,
        "context": target_context,
        "quishing_score": final_score,
        "verdict": verdict,
        "is_duitnow_scheme": is_duitnow_uri,
        "extracted_destination_urls": extracted_urls,
        "primary_url": primary_url,
        "extracted_mule_accounts": extracted_mule_accounts,
        "risk_factors": risk_factors or ["No immediate deception triggers found."],
        "recommended_action": "BLOCK & SINKHOLE QR DESTINATION" if final_score >= 0.75 else "PROCEED WITH CAUTION",
    }
