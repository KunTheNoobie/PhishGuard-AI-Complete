"""
PhishGuard-AI — SOC Multi-Channel Webhook Notifier.
==================================================

Dispatches structured security alerts to Discord, Slack, Telegram, and generic SOC Webhook
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

# Configurable in-memory / env webhook settings
SOC_WEBHOOK_SETTINGS: dict[str, Any] = {
    "discord_webhook": os.getenv("PHISHGUARD_DISCORD_WEBHOOK", ""),
    "slack_webhook": os.getenv("PHISHGUARD_SLACK_WEBHOOK", ""),
    "telegram_bot_token": os.getenv("PHISHGUARD_TELEGRAM_TOKEN", ""),
    "telegram_chat_id": os.getenv("PHISHGUARD_TELEGRAM_CHAT_ID", ""),
    "enabled": True,
}


async def test_webhook_ping(
    channel: str,
    target_url: str,
    chat_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch a test ping message to verify webhook connectivity."""
    if not target_url.strip():
        return {"success": False, "error": "Webhook URL / Token is empty"}

    channel_lower = channel.lower().strip()
    test_msg = "🚨 **[TEST PING] PhishGuard-AI Alert Pipeline Active**\nYour SOC notification endpoint is successfully connected to the live telemetry stream."

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            if "discord" in channel_lower or "discord.com" in target_url:
                payload = {
                    "username": "PhishGuard-AI SOC Bot",
                    "content": test_msg,
                    "embeds": [{
                        "title": "✅ Webhook Connectivity Verified",
                        "description": "Real-time threat telemetry and quarantined domain alerts will arrive here.",
                        "color": 3066993, # Emerald green #2ecc71
                    }]
                }
                resp = await client.post(target_url, json=payload)
                return {"success": resp.status_code in (200, 204), "status_code": resp.status_code}

            elif "slack" in channel_lower or "slack.com" in target_url:
                payload = {"text": test_msg}
                resp = await client.post(target_url, json=payload)
                return {"success": resp.status_code == 200, "status_code": resp.status_code}

            elif "telegram" in channel_lower:
                # Telegram bot API
                t_chat_id = chat_id or SOC_WEBHOOK_SETTINGS.get("telegram_chat_id", "")
                t_url = f"https://api.telegram.org/bot{target_url}/sendMessage"
                resp = await client.post(t_url, json={"chat_id": t_chat_id, "text": test_msg, "parse_mode": "Markdown"})
                return {"success": resp.status_code == 200, "status_code": resp.status_code}

            else:
                # Generic JSON webhook
                resp = await client.post(target_url, json={"event": "TEST_PING", "message": test_msg})
                return {"success": resp.status_code in (200, 201, 202, 204), "status_code": resp.status_code}

    except Exception as err:
        return {"success": False, "error": str(err)}


async def dispatch_threat_webhook(
    event_type: str,
    threat_data: dict[str, Any],
    webhook_url: str | None = None,
) -> bool:
    """Send an asynchronous incident notification payload to configured webhooks."""
    target_url = webhook_url or SOC_WEBHOOK_SETTINGS.get("discord_webhook") or os.getenv("PHISHGUARD_SOC_WEBHOOK")
    if not target_url:
        return False

    url_str = threat_data.get("malicious_url") or threat_data.get("url") or "N/A"
    score_val = float(threat_data.get("bert_score") or threat_data.get("score") or 0)

    payload = {
        "username": "PhishGuard-AI Security Bot",
        "avatar_url": "https://raw.githubusercontent.com/KunTheNoobie/PhishGuard-AI-Complete/main/chrome_extension/icons/icon128.png",
        "content": f"🚨 **CRITICAL SECURITY ALERT: {event_type.upper()} Intercepted**",
        "embeds": [
            {
                "title": "PhishGuard-AI Threat Interception Report",
                "color": 15682628,  # Red hex #ef4444
                "fields": [
                    {"name": "Targeted URL", "value": f"`{url_str}`", "inline": False},
                    {"name": "BERT Threat Score", "value": f"{score_val*100:.1f}%", "inline": True},
                    {"name": "Target Institution", "value": threat_data.get("targeted_institution") or "Malaysian Banking Sector", "inline": True},
                    {"name": "Flagged Mules", "value": str(len(threat_data.get("flagged_accounts") or [])) + " account(s)", "inline": True},
                ],
                "footer": {"text": "PhishGuard-AI Multi-Modal Defense System • Autonomous SOC Alert"},
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

