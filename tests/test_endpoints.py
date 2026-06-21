"""
PhishGuard-AI — API Endpoint Integration Tests.
=================================================

Full integration tests exercising the ``/api/v1/analyse/semantics``
endpoint through the FastAPI test client.  Uses mocked BERT engine
and in-memory database from ``conftest.py``.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import AUTH_HEADERS


# ==============================================================================
# Health Check
# ==============================================================================

class TestHealthEndpoint:

    @pytest.mark.asyncio
    async def test_health_returns_200(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "PhishGuard" in data["service"]


# ==============================================================================
# Authentication
# ==============================================================================

class TestAuthentication:

    @pytest.mark.asyncio
    async def test_missing_auth_returns_401(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://example.com",
                "dom_content": "<html><body>Hello</body></html>",
            },
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://example.com",
                "dom_content": "<html><body>Hello</body></html>",
            },
            headers={"Authorization": "Bearer wrong_token_here"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_passes(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://example.com",
                "dom_content": "<html><body>Hello</body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200


# ==============================================================================
# Payload Validation
# ==============================================================================

class TestPayloadValidation:

    @pytest.mark.asyncio
    async def test_missing_url_returns_422(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={"dom_content": "<html><body>Hello</body></html>"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_dom_content_returns_422(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={"url": "https://example.com"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_url_format_returns_422(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "not-a-valid-url",
                "dom_content": "<html><body>Hello</body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_dom_content_returns_422(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://example.com",
                "dom_content": "",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422


# ==============================================================================
# Semantic Analysis Pipeline (SAFE verdict)
# ==============================================================================

class TestSafeVerdict:

    @pytest.mark.asyncio
    async def test_legitimate_page_returns_safe(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://www.maybank2u.com.my",
                "dom_content": "<html><body><h1>Welcome to Maybank</h1><p>Internet Banking</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        # Check response structure
        assert "meta" in data
        assert "data" in data
        assert "orchestration" in data

        # Check meta block
        assert "transaction_id" in data["meta"]
        assert "processing_time_ms" in data["meta"]
        assert data["meta"]["processing_time_ms"] >= 0

        # Check semantic analysis
        sem = data["data"]["semantic_analysis"]
        assert sem["label"] == "LEGITIMATE"
        assert sem["is_malicious"] is False
        assert 0.0 <= sem["confidence"] <= 1.0
        assert len(sem["sanitized_text_preview"]) > 0

        # Check orchestration verdict
        assert data["orchestration"] == "SAFE"

    @pytest.mark.asyncio
    async def test_response_includes_mule_scan(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://example.com",
                "dom_content": "<html><body>No accounts here</body></html>",
            },
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        mule = data["data"]["mule_scan"]
        assert "accounts_extracted" in mule
        assert "flagged_accounts" in mule
        assert "mule_detected" in mule
        assert mule["mule_detected"] is False


# ==============================================================================
# Phishing Detection (BLOCK_RENDER verdict)
# ==============================================================================

class TestBlockVerdict:

    @pytest.mark.asyncio
    async def test_phishing_page_returns_block(self, phishing_client: AsyncClient) -> None:
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://rnaybank.com/login",
                "dom_content": "<html><body><h1>URGENT: Account suspended!</h1><p>Transfer RM500 now</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["data"]["semantic_analysis"]["label"] == "PHISHING"
        assert data["data"]["semantic_analysis"]["is_malicious"] is True
        assert data["orchestration"] == "BLOCK_RENDER"


# ==============================================================================
# Trusted Domain Whitelist (False Positive Prevention)
# ==============================================================================

class TestWhitelistedDomains:
    """Verify that known-legitimate bank domains bypass BERT and return SAFE.

    Uses the ``phishing_client`` fixture (which forces PHISHING verdict)
    to prove that the whitelist override takes priority over the model.
    """

    @pytest.mark.asyncio
    async def test_whitelisted_maybank_returns_safe(self, phishing_client: AsyncClient) -> None:
        """maybank2u.com.my should return SAFE even when BERT would say PHISHING."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://www.maybank2u.com.my/login",
                "dom_content": "<html><body><h1>Welcome to Maybank</h1><p>Internet Banking Login</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["data"]["semantic_analysis"]["label"] == "LEGITIMATE"
        assert data["data"]["semantic_analysis"]["is_malicious"] is False
        assert data["orchestration"] == "SAFE"

    @pytest.mark.asyncio
    async def test_whitelisted_pbebank_returns_safe(self, phishing_client: AsyncClient) -> None:
        """pbebank.com (Public Bank) should return SAFE."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://www.pbebank.com/personal-banking",
                "dom_content": "<html><body><h1>Public Bank</h1><p>Login to your account</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["data"]["semantic_analysis"]["label"] == "LEGITIMATE"
        assert data["data"]["semantic_analysis"]["is_malicious"] is False
        assert data["orchestration"] == "SAFE"

    @pytest.mark.asyncio
    async def test_whitelisted_cimb_returns_safe(self, phishing_client: AsyncClient) -> None:
        """cimbclicks.com.my should return SAFE."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://www.cimbclicks.com.my/",
                "dom_content": "<html><body><h1>CIMB Clicks</h1><p>Secure Online Banking</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["data"]["semantic_analysis"]["label"] == "LEGITIMATE"
        assert data["orchestration"] == "SAFE"

    @pytest.mark.asyncio
    async def test_subdomain_of_whitelisted_returns_safe(self, phishing_client: AsyncClient) -> None:
        """Subdomains like online.maybank.com.my should also be whitelisted."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://online.maybank.com.my/banking",
                "dom_content": "<html><body><h1>Maybank Online</h1><p>Transfer funds securely</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["data"]["semantic_analysis"]["label"] == "LEGITIMATE"
        assert data["orchestration"] == "SAFE"

    @pytest.mark.asyncio
    async def test_phishing_clone_still_blocked(self, phishing_client: AsyncClient) -> None:
        """A phishing clone (rnaybank.com) must NOT be whitelisted."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://rnaybank.com/login",
                "dom_content": "<html><body><h1>Maybank Login</h1><p>Enter your password</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["data"]["semantic_analysis"]["label"] == "PHISHING"
        assert data["data"]["semantic_analysis"]["is_malicious"] is True
        assert data["orchestration"] == "BLOCK_RENDER"

    @pytest.mark.asyncio
    async def test_non_whitelisted_domain_uses_bert(self, phishing_client: AsyncClient) -> None:
        """An unknown domain should go through normal BERT inference."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://suspicious-site.com/login",
                "dom_content": "<html><body><h1>Login</h1><p>Enter credentials</p></body></html>",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()

        # phishing_client uses mock that returns PHISHING
        assert data["data"]["semantic_analysis"]["label"] == "PHISHING"
        assert data["orchestration"] == "BLOCK_RENDER"


# ==============================================================================
# Mule Account Detection in DOM
# ==============================================================================

class TestMuleDetectionInEndpoint:

    @pytest.mark.asyncio
    async def test_mule_account_in_dom_triggers_block(self, phishing_client: AsyncClient) -> None:
        """When DOM contains a known mule account number, it should be flagged."""
        resp = await phishing_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://suspicious-shop.com/pay",
                "dom_content": (
                    "<html><body>"
                    "<p>Please transfer RM1000 to account 112233445566</p>"
                    "</body></html>"
                ),
            },
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        mule = data["data"]["mule_scan"]

        assert mule["mule_detected"] is True
        assert len(mule["flagged_accounts"]) >= 1
        assert mule["flagged_accounts"][0]["bank_name"] == "Maybank"

    @pytest.mark.asyncio
    async def test_mule_account_alone_triggers_block(self, test_client: AsyncClient) -> None:
        """Even with a LEGITIMATE BERT verdict, a mule account should trigger BLOCK."""
        resp = await test_client.post(
            "/api/v1/analyse/semantics",
            json={
                "url": "https://normal-looking-site.com",
                "dom_content": (
                    "<html><body>"
                    "<p>Pay to 112233445566 for your order</p>"
                    "</body></html>"
                ),
            },
            headers=AUTH_HEADERS,
        )
        data = resp.json()

        # BERT says LEGITIMATE, but mule detected
        assert data["data"]["semantic_analysis"]["is_malicious"] is False
        assert data["data"]["mule_scan"]["mule_detected"] is True
        # Orchestration should still be BLOCK_RENDER
        assert data["orchestration"] == "BLOCK_RENDER"


# ==============================================================================
# Dashboard Endpoints
# ==============================================================================

class TestDashboardEndpoints:

    @pytest.mark.asyncio
    async def test_stats_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_threats" in data
        assert "avg_confidence" in data
        assert "total_mule_accounts" in data
        assert "total_reports" in data
        assert data["total_mule_accounts"] == 15  # From expanded seed data

    @pytest.mark.asyncio
    async def test_telemetry_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/telemetry")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "entries" in data
        assert isinstance(data["entries"], list)

    @pytest.mark.asyncio
    async def test_mule_registry_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/mule-registry")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "accounts" in data
        assert data["count"] == 15  # Expanded seed data
        # Verify structure of first account
        acct = data["accounts"][0]
        assert "account_number" in acct
        assert "bank_name" in acct
        assert "report_count" in acct
