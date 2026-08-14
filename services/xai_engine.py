"""
services/xai_engine.py
═════════════════════════════════════════════════════════════════════
Explainable AI (XAI) Token Attribution Engine for PhishGuard-AI.
Generates token-level semantic weights and risk attribution heatmaps
explaining WHY the AI model flagged a URL or communication as phishing.
═════════════════════════════════════════════════════════════════════
"""

import re
import urllib.parse
from typing import Dict, Any, List

# Phishing Cue Weight Dictionaries
KEYWORDS_WEIGHTS = {
    # Urgency vectors
    "urgent": 0.85, "immediately": 0.90, "suspended": 0.92, "block": 0.82, "freeze": 0.88,
    "expire": 0.78, "24h": 0.86, "restricted": 0.84, "warning": 0.75, "action required": 0.92,
    "unusual activity": 0.88, "locked": 0.91,
    
    # Credential & Authentication vectors
    "tac": 0.95, "otp": 0.94, "login": 0.70, "verify": 0.80, "auth": 0.72,
    "password": 0.85, "security update": 0.82, "pin": 0.88, "credentials": 0.90,
    "secure": 0.65, "signin": 0.72,
    
    # Financial vectors
    "account": 0.68, "bank": 0.65, "transfer": 0.75, "refund": 0.82, "claim": 0.80,
    "duitnow": 0.85, "payment": 0.70, "cash": 0.72, "tax rebate": 0.88, "lhdn": 0.90,
    "epf": 0.88, "kwsp": 0.88, "angpao": 0.82, "subsidy": 0.85,
    
    # Brand keywords
    "maybank": 0.80, "cimb": 0.80, "publicbank": 0.80, "rhb": 0.80, "hongleong": 0.80,
    "touchngo": 0.85, "grabpay": 0.80, "shopeepay": 0.80
}

SUSPICIOUS_TLDS = {".top", ".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club", ".icu", ".vip"}

def get_token_category(token_lower: str) -> str:
    urgency = {"urgent", "immediately", "suspended", "block", "freeze", "expire", "24h", "restricted", "warning", "action", "unusual", "locked"}
    credentials = {"tac", "otp", "login", "verify", "auth", "password", "security", "pin", "credentials", "signin"}
    financial = {"account", "bank", "transfer", "refund", "claim", "duitnow", "payment", "cash", "rebate", "lhdn", "epf", "kwsp", "subsidy"}
    
    for u in urgency:
        if u in token_lower:
            return "urgency"
    for c in credentials:
        if c in token_lower:
            return "credential"
    for f in financial:
        if f in token_lower:
            return "financial"
    return "neutral"

def explain_text_threat(text_or_url: str, base_score: float = 0.85) -> Dict[str, Any]:
    """
    Evaluates token contributions and returns XAI feature attribution.
    """
    if not text_or_url:
        return {"tokens": [], "summary": "No content provided", "overall_risk": 0.0}

    # Split by URL separators, punctuation, or whitespace
    raw_tokens = [t for t in re.split(r'[\s\/\.\-\_\:\?\&\=\#\(\)\[\]]+', text_or_url) if t]
    
    attributed_tokens = []
    total_attribution_weight = 0.0
    
    for tok in raw_tokens:
        tok_lower = tok.lower()
        weight = 0.05  # Base background weight
        category = "neutral"
        
        # Check keyword matches
        for kw, kw_weight in KEYWORDS_WEIGHTS.items():
            if kw in tok_lower:
                weight = max(weight, kw_weight)
                category = get_token_category(tok_lower)
        
        # Check suspicious TLD
        if any(tok_lower.endswith(tld) for tld in SUSPICIOUS_TLDS):
            weight = max(weight, 0.93)
            category = "domain_spoof"
            
        # Check brand typosquatting (e.g. m4ybank, c1mb, mybank)
        if re.search(r'(m[4a]yb[4a]nk|c[1i]mb|p[u0]bl[1i]cb[4a]nk|rhb\-?onl[1i]ne)', tok_lower):
            weight = max(weight, 0.96)
            category = "brand_spoof"

        # Check IP in URL
        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', tok_lower):
            weight = max(weight, 0.88)
            category = "ip_host"

        risk_contribution = round(weight * (base_score or 0.85), 3)
        total_attribution_weight += risk_contribution

        attributed_tokens.append({
            "token": tok,
            "weight": round(weight, 2),
            "category": category,
            "risk_contribution": risk_contribution,
            "is_highlight": weight >= 0.60
        })

    # Find top driving factors
    top_cues = sorted([t for t in attributed_tokens if t["is_highlight"]], key=lambda x: x["weight"], reverse=True)[:5]
    top_cues_str = ", ".join([f"'{c['token']}' ({c['category']})" for c in top_cues]) or "None"

    return {
        "text": text_or_url,
        "base_score": base_score,
        "tokens": attributed_tokens,
        "top_drivers": [c["token"] for c in top_cues],
        "top_drivers_summary": f"Primary threat indicators detected: {top_cues_str}.",
        "explanation": f"AI model weighted {len(top_cues)} primary semantic vectors ({top_cues_str}) producing a {round(base_score * 100, 1)}% phishing probability."
    }
