"""
PhishGuard-AI — Automated YARA & Suricata/Snort IDS Rule Generator.
===================================================================

Synthesizes ready-to-deploy YARA file signatures and Suricata / Snort
network inspection rules from live active phishing domains, credential
harvesting keywords, and mule syndicate signatures.

Architecture Layer: Services / Threat Intelligence
Thesis Reference  : §5.5 — Automated SIEM & Network Rule Synthesis
"""

from __future__ import annotations

import time
from typing import Any


def generate_phishguard_yara_rules(active_domains: list[str] | None = None) -> str:
    """Generate dynamic YARA rule block for scanning downloaded phishing kits and HTML files."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    
    domain_strings = ""
    if active_domains:
        for idx, d in enumerate(active_domains[:10]):
            clean_d = d.replace('"', '\\"').strip()
            if clean_d:
                domain_strings += f'        $ioc_domain_{idx + 1} = "{clean_d}" nocase\n'

    yara_code = f"""/*
 * PhishGuard-AI Auto-Generated YARA Ruleset v3.0
 * Generated: {timestamp}
 * Reference: Enterprise Threat Intelligence & Financial Phishing Kit Detection
 */

rule PhishGuard_Malaysian_Banking_PhishKit {{
    meta:
        description = "Detects phishing kits harvesting Malaysian banking credentials, TAC/OTPs, and IC numbers"
        author = "PhishGuard-AI Autonomous Defense Engine"
        version = "3.0"
        reference = "https://phishguard.ai/cti"
        date = "{time.strftime('%Y-%m-%d')}"
        severity = "CRITICAL"

    strings:
        // Banking Brand Keywords
        $bank1 = "Maybank2u" nocase
        $bank2 = "CIMB Clicks" nocase
        $bank3 = "PBE Bank" nocase
        $bank4 = "Public Bank Online" nocase
        $bank5 = "RHB Now" nocase
        $bank6 = "Hong Leong Connect" nocase
        $bank7 = "Touch 'n Go eWallet" nocase

        // Credential & TAC Harvesting Forms
        $tac1 = "Enter SMS TAC" nocase
        $tac2 = "Masukkan Kod TAC" nocase
        $tac3 = "Request TAC" nocase
        $tac4 = "Kemaskini Nombor Telefon" nocase
        $nric = "Nombor Kad Pengenalan" nocase

        // Deceptive Action Urgency
        $urg1 = "Akaun anda telah digantung" nocase
        $urg2 = "Account has been suspended" nocase
        $urg3 = "Verify within 24 hours" nocase
        $urg4 = "Tuntutan Bantuan Tunai" nocase
{domain_strings}
    condition:
        (1 of ($bank*)) and (1 of ($tac*)) and (1 of ($urg*))
}}

rule PhishGuard_DuitNow_EMVCo_Quishing_Payload {{
    meta:
        description = "Detects EMVCo QR code payloads impersonating PayNet DuitNow proxy schemes"
        author = "PhishGuard-AI Quishing Radar"
        severity = "HIGH"

    strings:
        $emvco_hdr = "0002010102"
        $duitnow_aid = "my.com.paynet.duitnow" nocase
        $paynet_mcc = "5303458"

    condition:
        all of them
}}
"""
    return yara_code


def generate_suricata_snort_rules(active_domains: list[str] | None = None) -> str:
    """Generate dynamic Suricata and Snort IDS/IPS network inspection signatures."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    dynamic_rules = ""
    if active_domains:
        for idx, d in enumerate(active_domains[:5]):
            sid = 3000100 + idx
            clean_d = d.replace('"', '\\"').strip()
            if clean_d:
                dynamic_rules += f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHISHGUARD ACTIVE IOC - Intercepted Request to Flagged Domain {clean_d}"; flow:established,to_server; http.host; content:"{clean_d}"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)\n'

    suricata_rules = f"""# ═════════════════════════════════════════════════════════════════════
# PhishGuard-AI Auto-Generated Suricata / Snort IDS Ruleset v3.0
# Ingested: {timestamp}
# ═════════════════════════════════════════════════════════════════════

# Rule 1: HTTP Host Header Matching Fake Maybank2u Domain
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHISHGUARD MALICIOUS HOST - Maybank2u Phishing Domain Encountered"; flow:established,to_server; http.host; content:"maybank2u-"; nocase; content:".top"; endswith; classtype:trojan-activity; sid:3000001; rev:1;)

# Rule 2: HTTP POST Body Exfiltrating 6-Digit Banking TAC
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHISHGUARD CREDENTIAL HARVEST - Exfiltration of Malaysian Banking SMS TAC"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"tac="; nocase; pcre:"/tac=[0-9]{{6}}/i"; classtype:credential-theft; sid:3000002; rev:1;)

# Rule 3: DNS Query to High-Risk Disposible TLD (.top / .xyz lookalike)
alert dns $HOME_NET any -> any 53 (msg:"PHISHGUARD DNS QUERY - Request to High-Risk Banking Typosquat Domain"; dns.query; content:"cimbclicks-"; nocase; content:".xyz"; endswith; classtype:bad-unknown; sid:3000003; rev:1;)

# Rule 4: DuitNow Scam Account Exfiltration Payload
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PHISHGUARD MULE SYNDICATE - Stolen Fund Redirection to Flagged Account"; flow:established,to_server; http.request_body; content:"account_number="; nocase; classtype:trojan-activity; sid:3000004; rev:1;)

{dynamic_rules}"""
    return suricata_rules
