"""
PhishGuard-AI — SOC Incident Webhook Notifier.
==============================================

Dispatches structured security alerts to Discord, Slack, and generic SOC Webhook
endpoints when critical phishing threats or mule accounts are intercepted.

Architecture Layer: Services / Alerting & Integration
Thesis Reference : §5.6 — Automated SOC Alerting & Incident Propagation
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Configurable webhook URL via environment
SOC_WEBHOOK_URL: str | None = os.getenv("PHISHGUARD_SOC_WEBHOOK", None)


async def dispatch_threat_webhook(
    event_type: str,
    threat_data: dict[str, Any],
    webhook_url: str | None = None,
) -> bool:
    """Send an asynchronous incident notification payload to a configured webhook."""
    target_url = webhook_url or SOC_WEBHOOK_URL
    if not target_url:
        return False  # No webhook configured

    # Format structured message (Discord/Slack compatible embed)
    payload = {
        "username": "PhishGuard-AI Security Bot",
        "avatar_url": "https://raw.githubusercontent.com/KunTheNoobie/PhishGuard-AI-Complete/main/chrome_extension/icons/icon128.png",
        "content": f"🚨 **CRITICAL SECURITY ALERT: {event_type.upper()} Intercepted**",
        "embeds": [
            {
                "title": "PhishGuard-AI Threat Interception Report",
                "color": 15682628,  # Red hex #ef4444
                "fields": [
                    {
                        "name": "Targeted URL",
                        "value": f"`{threat_data.get('malicious_url') or threat_data.get('url') or 'N/A'}`",
                        "inline": False,
                    },
                    {
                        "name": "BERT Threat Score",
                        "value": f"{float(threat_data.get('bert_score') or threat_data.get('score') or 0)*100:.1f}%",
                        "inline": True,
                    },
                    {
                        "name": "Target Institution",
                        "value": threat_data.get("targeted_institution") or "Financial Banking Sector",
                        "inline": True,
                    },
                    {
                        "name": "Flagged Mules",
                        "value": str(len(threat_data.get("flagged_accounts") or [])) + " account(s)",
                        "inline": True,
                    },
                ],
                "footer": {
                    "text": "PhishGuard-AI Multi-Modal Defense System • Autonomous SOC Alert"
                },
            }
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(target_url, json=payload)
            return resp.status_code in (200, 204)
    except Exception as err:
        logger.warning("Failed to dispatch SOC webhook alert: %s", err)
        return False
