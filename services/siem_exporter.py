"""
services/siem_exporter.py
═════════════════════════════════════════════════════════════════════
Enterprise SIEM Exporter & DNS Sinkhole Firewall Blacklist Engine.
Generates ArcSight/Splunk CEF, Syslog RFC 5424, and DNS Firewall
rules (Pi-hole, BIND RPZ, Suricata/Snort, Windows Hosts).
═════════════════════════════════════════════════════════════════════
"""

import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Any

def generate_cef_export(logs: List[Dict[str, Any]]) -> str:
    """
    Exports threat telemetry in ArcSight / Splunk Common Event Format (CEF:0).
    """
    cef_lines = [
        "# PhishGuard-AI Threat Telemetry & SIEM Incident Feed",
        "# Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension",
        f"# Exported: {datetime.now(timezone.utc).isoformat()}",
        ""
    ]
    
    for log in logs:
        log_id = log.get("log_id", 0)
        url = log.get("malicious_url", "unknown")
        bert_score = float(log.get("bert_score", 0.85))
        severity = int(round(bert_score * 10))  # Scale 1-10
        ts = log.get("timestamp", datetime.now(timezone.utc).isoformat())
        
        # Parse domain
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or url.split('/')[0]
        except Exception:
            domain = "unknown"
            
        extension = (
            f"request={url} "
            f"dstHost={domain} "
            f"cn1={bert_score:.4f} cn1Label=ConfidenceScore "
            f"cat=Phishing/Impersonation "
            f"act=Blocked "
            f"rt={ts}"
        )
        
        cef_line = f"CEF:0|PhishGuard-AI|ThreatEngine|3.0|PHISH-{log_id:05d}|Phishing Vector Intercepted|{severity}|{extension}"
        cef_lines.append(cef_line)
        
    return "\n".join(cef_lines)


def generate_syslog_export(logs: List[Dict[str, Any]]) -> str:
    """
    Exports threat telemetry in standard Syslog RFC 5424 format.
    """
    syslog_lines = [
        f"# PhishGuard-AI Syslog RFC 5424 Export ({len(logs)} Events)",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        ""
    ]
    
    for log in logs:
        log_id = log.get("log_id", 0)
        url = log.get("malicious_url", "unknown")
        bert_score = float(log.get("bert_score", 0.85))
        pri = 134  # Facility: local0 (16), Severity: Alert (1) -> 16*8 + 6 = 134
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or url.split('/')[0]
        except Exception:
            domain = "unknown"

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sd = f'[threat@54321 id="{log_id}" domain="{domain}" confidence="{bert_score:.2f}" action="quarantined"]'
        msg = f"PhishGuard AI intercepted malicious phishing domain: {url}"
        
        syslog_lines.append(f"<{pri}>1 {ts} phishguard-soc phishguard-engine 1204 THREAT-{log_id} {sd} {msg}")
        
    return "\n".join(syslog_lines)


def generate_sinkhole_rules(domains: List[str], format_type: str = "pihole") -> str:
    """
    Generates DNS sinkhole, firewall blocklists, and IDS drop rules.
    Formats: pihole, hosts, bind, suricata
    """
    clean_domains = sorted(list(set([d.strip().lower() for d in domains if d and d.strip()])))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    if format_type == "hosts":
        lines = [
            f"# PhishGuard-AI Active Threat Sinkhole (Hosts format)",
            f"# Updated: {ts}",
            f"# Total Blocked Domains: {len(clean_domains)}",
            "127.0.0.1 localhost",
            ""
        ]
        for d in clean_domains:
            lines.append(f"0.0.0.0 {d}")
        return "\n".join(lines)
        
    elif format_type == "bind":
        lines = [
            f"; PhishGuard-AI BIND 9 RPZ (Response Policy Zone) Rule Database",
            f"; Generated: {ts}",
            f"$TTL 300",
            f"@ IN SOA localhost. root.localhost. ({int(datetime.now().timestamp())} 3600 600 86400 300)",
            f"  IN NS  localhost.",
            ""
        ]
        for d in clean_domains:
            lines.append(f"{d} CNAME .")
            lines.append(f"*.{d} CNAME .")
        return "\n".join(lines)
        
    elif format_type == "suricata":
        lines = [
            f"# PhishGuard-AI Suricata / Snort IDS Network Threat Signature Ruleset",
            f"# Generated: {ts}",
            ""
        ]
        for idx, d in enumerate(clean_domains, start=9000100):
            lines.append(
                f'drop http any any -> any any (msg:"PhishGuard Blocklist - {d}"; content:"{d}"; http_header; classtype:trojan-activity; sid:{idx}; rev:1;)'
            )
        return "\n".join(lines)
        
    else:  # default pihole / adguard
        lines = [
            f"# PhishGuard-AI Pi-hole / AdGuard Home DNS Blocklist",
            f"# Generated: {ts}",
            f"# Total Domains: {len(clean_domains)}",
            ""
        ]
        for d in clean_domains:
            lines.append(f"0.0.0.0 {d}")
        return "\n".join(lines)
