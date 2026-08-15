"""
PhishGuard-AI — MITRE ATT&CK® v14 Matrix Mapping Service.
=========================================================

Maps detected financial phishing, quishing, mule syndicates, and
credential harvesting activities directly to official MITRE ATT&CK
Enterprise and Mobile tactics & techniques.

Architecture Layer: Services / Threat Intelligence
Thesis Reference  : §5.4 — CTI Taxonomy & MITRE ATT&CK Framework
"""

from __future__ import annotations

from typing import Any, Final


MITRE_TACTICS: Final[list[dict[str, Any]]] = [
    {
        "tactic_id": "TA0001",
        "name": "Initial Access",
        "techniques": [
            {
                "technique_id": "T1566.002",
                "name": "Spearphishing Link",
                "description": "Adversaries send deceptive links leading to fake banking login portals.",
                "observed_in": "SMS Phishing (Smishing), Email Campaigns, WhatsApp/Telegram lures",
                "risk_level": "CRITICAL",
                "mitigation": "M1049: Antivirus/Antimalware & Browser DOM Semantic Inspection (PhishGuard-AI)"
            },
            {
                "technique_id": "T1566.001",
                "name": "Spearphishing Attachment",
                "description": "Adversaries attach malicious .html/.eml payloads or PDF summons containing scam links.",
                "observed_in": "Fake LHDN tax refunds, PDRM summons notices",
                "risk_level": "HIGH",
                "mitigation": "M1031: Network Intrusion Prevention"
            }
        ]
    },
    {
        "tactic_id": "TA0006",
        "name": "Credential Access",
        "techniques": [
            {
                "technique_id": "T1556",
                "name": "Modify Authentication Process (TAC/OTP Harvesting)",
                "description": "Adversaries intercept or deceive victims into disclosing 6-digit banking SMS TACs or app OTPs.",
                "observed_in": "Maybank Secure2u, CIMB Messenger TAC, Public Bank PAC",
                "risk_level": "CRITICAL",
                "mitigation": "M1054: Software Configuration (FIDO2 / WebAuthn Hardware Tokens)"
            },
            {
                "technique_id": "T1539",
                "name": "Steal Web Session Cookie",
                "description": "Adversaries deploy Reverse-Proxy frameworks (Evilginx) to capture authenticated session tokens.",
                "observed_in": "Adversary-in-the-Middle (AiTM) banking proxies",
                "risk_level": "HIGH",
                "mitigation": "M1050: Exploit Protection & Domain Pinning"
            }
        ]
    },
    {
        "tactic_id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
            {
                "technique_id": "T1608.003",
                "name": "Stage Capabilities: Install SSL Certificate",
                "description": "Adversaries provision Let's Encrypt / cPanel free DV certificates on disposable TLDs (.top, .xyz).",
                "observed_in": "Domain-Validated SSL on lookalike domains",
                "risk_level": "MEDIUM",
                "mitigation": "M1038: Execution Prevention via Automated CT Log Auditing"
            },
            {
                "technique_id": "T1036.007",
                "name": "Masquerading: Double File Extension & Homoglyphs",
                "description": "Adversaries register Punycode IDN homoglyphs (e.g., Cyrillic 'а' replacing Latin 'a') to mimic Maybank/CIMB.",
                "observed_in": "Pre-Emptive Typosquatting Campaigns",
                "risk_level": "HIGH",
                "mitigation": "M1036: Brand Impersonation Index & Visual Logo Verification"
            }
        ]
    },
    {
        "tactic_id": "TA0040",
        "name": "Impact (Financial Exfiltration)",
        "techniques": [
            {
                "technique_id": "T1657",
                "name": "Financial Theft & Mule Syndicates",
                "description": "Adversaries redirect stolen victim funds into rapid-layering commercial mule accounts.",
                "observed_in": "Bukit Aman CCID SemakMule, BNM NFP, DuitNow P2P proxies",
                "risk_level": "CRITICAL",
                "mitigation": "M1058: Multi-Bank Instant Account Freezing & NSRC 997 Alerting"
            }
        ]
    }
]


def generate_mitre_attack_matrix(active_telemetry_count: int = 141) -> dict[str, Any]:
    """Compile the complete MITRE ATT&CK v14 enterprise matrix mapping."""
    total_techniques = sum(len(t["techniques"]) for t in MITRE_TACTICS)
    
    tactics_summary = []
    for t in MITRE_TACTICS:
        tactics_summary.append({
            "tactic_id": t["tactic_id"],
            "name": t["name"],
            "technique_count": len(t["techniques"]),
            "techniques": t["techniques"]
        })

    return {
        "framework": "MITRE ATT&CK® Enterprise & Mobile v14.1",
        "matrix_name": "PhishGuard Financial Threat Matrix",
        "total_tactics": len(MITRE_TACTICS),
        "total_techniques_covered": total_techniques,
        "active_telemetry_correlated": active_telemetry_count,
        "tactics": tactics_summary,
    }
