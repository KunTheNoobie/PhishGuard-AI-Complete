"""
PhishGuard-AI Multi-Vector Risk Scoring Matrix
Fuses neural NLP, structural heuristics, mule syndicate links, SSL/TLS trust, and brand vectors.
"""

from typing import Dict, Any, Optional
from services.heuristic_engine import analyze_url_heuristics
from services.brand_profiler import profile_brand_impersonation
from services.ssl_analyzer import analyze_target_ssl

def compute_multi_vector_risk(
    url: str,
    text_content: Optional[str] = None,
    bert_score: float = 0.0,
    mule_detected: bool = False,
    mule_count: int = 0
) -> Dict[str, Any]:
    """
    Computes a weighted 5-factor composite risk assessment.
    """
    # 1. Neural Score (35%)
    w_bert = min(max(bert_score, 0.0), 1.0) * 35.0

    # 2. Heuristics & TLD (20%)
    heuristics = analyze_url_heuristics(url)
    h_score = heuristics.get("heuristic_score", 0.0)
    w_heuristics = min(max(h_score, 0.0), 1.0) * 20.0

    # 3. Mule Account Syndicate Link (20%)
    if mule_detected or mule_count > 0:
        w_mule = min(20.0, 15.0 + (mule_count * 2.5))
    else:
        w_mule = 0.0

    # 4. SSL / TLS Trust (15%)
    ssl_data = analyze_target_ssl(url)
    ssl_risk = ssl_data.get("spoof_risk_score", 0.0) / 100.0
    w_ssl = min(max(ssl_risk, 0.0), 1.0) * 15.0

    # 5. Brand Spoofing (10%)
    brand_data = profile_brand_impersonation(url, text_content or url)
    brand_risk = 1.0 if brand_data.get("impersonation_detected") else 0.1
    w_brand = brand_risk * 10.0

    # Composite Score (0 - 100)
    composite_score = round(w_bert + w_heuristics + w_mule + w_ssl + w_brand, 1)

    if composite_score >= 80.0:
        verdict = "CRITICAL_THREAT"
        risk_tier = "CRITICAL"
        color = "#f87171"
    elif composite_score >= 50.0:
        verdict = "SUSPICIOUS_PHISH"
        risk_tier = "ELEVATED"
        color = "#fbbf24"
    elif composite_score >= 25.0:
        verdict = "MONITORED_ANOMALY"
        risk_tier = "MONITORED"
        color = "#60a5fa"
    else:
        verdict = "CLEAN_LEGITIMATE"
        risk_tier = "LOW"
        color = "#34d399"

    return {
        "composite_score": composite_score,
        "verdict": verdict,
        "risk_tier": risk_tier,
        "color": color,
        "vectors": {
            "neural_nlp_score": round(w_bert, 1),
            "heuristic_tld_score": round(w_heuristics, 1),
            "mule_syndicate_score": round(w_mule, 1),
            "ssl_tls_provenance_score": round(w_ssl, 1),
            "brand_impersonation_score": round(w_brand, 1)
        },
        "target_brand": brand_data.get("matched_brand") or "Generic Target",
        "heuristics_summary": heuristics.get("indicators", []),
        "ssl_summary": ssl_data.get("verdict", "Unknown")
    }
