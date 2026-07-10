"""
PhishGuard-AI — Locust Load / Stress Test.
============================================

Simulates concurrent browser extension clients sending analysis requests
to the ``/api/v1/analyze/semantics`` endpoint.

Usage
-----
    locust -f tests/locustfile.py --host http://localhost:8000

Then open http://localhost:8089 to configure users and spawn rate.

Recommended test parameters for thesis validation:
    - Users: 50
    - Spawn rate: 5/s
    - Duration: 60s
    - Target: p95 latency < 300ms

Architecture Layer : Testing / Performance
Thesis Reference   : §5.4 — API Stress Testing & Latency Validation
"""

from __future__ import annotations

import os
from typing import Final

from locust import HttpUser, between, task

# Read the API key from the environment or use the default test key.
API_KEY: Final[str] = os.getenv("PHISHGUARD_API_KEY", "phishguard_secret_key_2026")

# ── Realistic DOM payloads ──

LEGITIMATE_PAYLOAD: Final[dict] = {
    "url": "https://www.maybank2u.com.my/home",
    "dom_content": """
    <html>
    <head><title>Maybank2u - Online Banking</title></head>
    <body>
        <header><h1>Welcome to Maybank2u</h1></header>
        <nav>
            <a href="/accounts">My Accounts</a>
            <a href="/transfer">Fund Transfer</a>
            <a href="/bills">Bill Payment</a>
        </nav>
        <main>
            <p>Access your accounts securely with Maybank2u online banking.</p>
            <p>Your trusted partner for all financial needs since 1960.</p>
        </main>
        <footer><p>© 2026 Malayan Banking Berhad. All rights reserved.</p></footer>
    </body>
    </html>
    """,
}

PHISHING_PAYLOAD: Final[dict] = {
    "url": "https://rnaybank-secure.com/verify",
    "dom_content": """
    <html>
    <head><title>Maybank Security Verification</title></head>
    <body>
        <script>document.cookie='session=stolen'</script>
        <style>.urgent{color:red;font-size:24px;font-weight:bold}</style>
        <div class="urgent">
            <h1>⚠ CRITICAL SECURITY ALERT ⚠</h1>
            <h2>Your Maybank Account Has Been Compromised!</h2>
            <p>Unauthorized login detected from IP 192.168.1.100.</p>
            <p>To prevent permanent suspension, you MUST verify your identity NOW.</p>
            <p>Transfer RM500 security deposit to account 112233445566 within 30 minutes.</p>
            <p>Failure to act will result in permanent account closure and legal action.</p>
            <div id="countdown">Time remaining: 29:45</div>
        </div>
    </body>
    </html>
    """,
}

MULE_PAYLOAD: Final[dict] = {
    "url": "https://facebook.com/marketplace/item/12345",
    "dom_content": """
    <html>
    <body>
        <h1>iPhone 15 Pro Max - RM800 ONLY!</h1>
        <p>Brand new sealed in box. Cash only, no COD.</p>
        <p>Bank transfer to:</p>
        <ul>
            <li>Account: 76001234567890</li>
            <li>Bank: CIMB</li>
            <li>Name: Ahmad bin Abu</li>
        </ul>
        <p>WhatsApp: 0123456789</p>
    </body>
    </html>
    """,
}


class PhishGuardUser(HttpUser):
    """Simulated browser extension client for load testing."""

    # Wait 1–3 seconds between requests (realistic browsing pattern).
    wait_time = between(1, 3)

    headers: dict[str, str] = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    @task(3)
    def analyse_legitimate_page(self) -> None:
        """Simulate analysing a legitimate banking page (most common)."""
        self.client.post(
            "/api/v1/analyze/semantics",
            json=LEGITIMATE_PAYLOAD,
            headers=self.headers,
            name="/analyze/semantics [LEGITIMATE]",
        )

    @task(1)
    def analyse_phishing_page(self) -> None:
        """Simulate analysing a phishing page."""
        self.client.post(
            "/api/v1/analyze/semantics",
            json=PHISHING_PAYLOAD,
            headers=self.headers,
            name="/analyze/semantics [PHISHING]",
        )

    @task(1)
    def analyse_mule_page(self) -> None:
        """Simulate analysing a page with a mule account."""
        self.client.post(
            "/api/v1/analyze/semantics",
            json=MULE_PAYLOAD,
            headers=self.headers,
            name="/analyze/semantics [MULE]",
        )

    @task(2)
    def check_health(self) -> None:
        """Periodic health checks (mimics K8s liveness probes)."""
        self.client.get("/health", name="/health")

    @task(1)
    def view_dashboard_stats(self) -> None:
        """Simulate admin checking dashboard stats."""
        self.client.get(
            "/api/v1/dashboard/stats",
            name="/dashboard/stats",
        )
