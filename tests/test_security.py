"""
PhishGuard-AI — Security Control Tests.
========================================

Covers the controls added in v3.2.0:

- Administrative authentication on every ``/api/v1/dashboard`` route
  (bearer token or server-side session cookie).
- CORS policy (explicit origins, no credentialed wildcard).
- Baseline security response headers.
- Single SSE broadcast per logged threat.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from core.config import ADMIN_API_TOKEN, APP_VERSION

PROTECTED_GET_ROUTES = [
    "/api/v1/dashboard/stats",
    "/api/v1/dashboard/telemetry",
    "/api/v1/dashboard/mule-registry",
    "/api/v1/dashboard/db/backup",
    "/api/v1/dashboard/export/cef",
]


class TestDashboardAuthentication:

    @pytest.mark.asyncio
    @pytest.mark.parametrize("route", PROTECTED_GET_ROUTES)
    async def test_dashboard_routes_reject_anonymous(self, anon_client: AsyncClient, route: str) -> None:
        resp = await anon_client.get(route)
        assert resp.status_code == 401
        assert resp.json()["detail"]["error"] == "DASHBOARD_AUTH_REQUIRED"

    @pytest.mark.asyncio
    async def test_anonymous_cannot_delete_mule_record(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.delete("/api/v1/dashboard/mule-registry/1")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_bearer_token_rejected(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get(
            "/api/v1/dashboard/stats", headers={"Authorization": "Bearer not-the-admin-key"}
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_bearer_token_grants_access(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get(
            "/api/v1/dashboard/stats", headers={"Authorization": f"Bearer {ADMIN_API_TOKEN}"}
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_login_with_wrong_key_rejected(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.post("/api/v1/dashboard/auth/login", json={"api_key": "wrong"})
        assert resp.status_code == 401
        assert "set-cookie" not in resp.headers

    @pytest.mark.asyncio
    async def test_session_cookie_login_flow(self, anon_client: AsyncClient) -> None:
        probe = await anon_client.get("/api/v1/dashboard/auth/session")
        assert probe.status_code == 200 and probe.json()["authenticated"] is False

        login = await anon_client.post("/api/v1/dashboard/auth/login", json={"api_key": ADMIN_API_TOKEN})
        assert login.status_code == 200
        cookie = login.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie

        # The cookie alone (no Authorization header) now authorises requests.
        stats = await anon_client.get("/api/v1/dashboard/stats")
        assert stats.status_code == 200
        assert (await anon_client.get("/api/v1/dashboard/auth/session")).json()["authenticated"] is True

        logout = await anon_client.post("/api/v1/dashboard/auth/logout")
        assert logout.status_code == 200
        anon_client.cookies.clear()
        assert (await anon_client.get("/api/v1/dashboard/stats")).status_code == 401

    @pytest.mark.asyncio
    async def test_login_is_rate_limited_against_guessing(self, anon_client: AsyncClient) -> None:
        statuses = []
        for attempt in range(7):
            resp = await anon_client.post("/api/v1/dashboard/auth/login", json={"api_key": f"guess-{attempt}"})
            statuses.append(resp.status_code)
        assert statuses[:5] == [401] * 5
        assert statuses[5:] == [429, 429]

    @pytest.mark.asyncio
    async def test_forged_session_cookie_rejected(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get(
            "/api/v1/dashboard/stats", headers={"Cookie": "phishguard_session=forged-value"}
        )
        assert resp.status_code == 401


class TestCorsAndHeaders:

    @pytest.mark.asyncio
    async def test_unknown_origin_gets_no_cors_grant(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get("/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in resp.headers
        assert "access-control-allow-credentials" not in resp.headers

    @pytest.mark.asyncio
    async def test_local_dashboard_origin_allowed_without_credentials(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get("/health", headers={"Origin": "http://127.0.0.1:8000"})
        assert resp.headers["access-control-allow-origin"] == "http://127.0.0.1:8000"
        assert "access-control-allow-credentials" not in resp.headers

    @pytest.mark.asyncio
    async def test_extension_origin_allowed(self, anon_client: AsyncClient) -> None:
        origin = "chrome-extension://" + "abcdefghijklmnop" * 2
        resp = await anon_client.get("/health", headers={"Origin": origin})
        assert resp.headers["access-control-allow-origin"] == origin

    @pytest.mark.asyncio
    async def test_security_headers_present(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get("/health")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "SAMEORIGIN"
        assert "referrer-policy" in resp.headers

    @pytest.mark.asyncio
    async def test_api_responses_are_not_cacheable(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/stats")
        assert resp.headers["cache-control"] == "no-store"

    @pytest.mark.asyncio
    async def test_health_reports_unified_version(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.get("/health")
        assert resp.json()["version"] == APP_VERSION == "3.2.0"


class TestTelemetryBroadcast:

    @pytest.mark.asyncio
    async def test_threat_is_broadcast_exactly_once(self, test_db) -> None:
        import asyncio

        from api.dashboard_endpoints import _SSE_CLIENTS
        from database.repository import log_threat_telemetry

        queue: asyncio.Queue = asyncio.Queue()
        _SSE_CLIENTS.add(queue)
        try:
            log_id = await log_threat_telemetry("http://maybank2u-verify.top/login", 0.97, test_db)
        finally:
            _SSE_CLIENTS.discard(queue)
        assert log_id > 0
        assert queue.qsize() == 1

    @pytest.mark.asyncio
    async def test_blocked_page_does_not_poison_mule_registry(self, phishing_client: AsyncClient, test_db) -> None:
        """Accounts merely displayed on a blocked page must not be auto-registered as mules."""
        from tests.conftest import AUTH_HEADERS

        innocent_account = "562179504126"
        resp = await phishing_client.post(
            "/api/v1/analyze/semantics",
            json={
                "url": "http://maybank2u-secure-login.top/m2u/login",
                "dom_content": (
                    "<html><body><p>Maybank2u login. Refunds are paid to account "
                    f"{innocent_account}.</p><input type='password' name='password'></body></html>"
                ),
            },
            headers=AUTH_HEADERS,
        )
        assert resp.json()["orchestration"] == "BLOCK_RENDER"
        cursor = await test_db.execute(
            "SELECT COUNT(*) FROM mule_registry WHERE account_number = ?;", (innocent_account,)
        )
        assert (await cursor.fetchone())[0] == 0
