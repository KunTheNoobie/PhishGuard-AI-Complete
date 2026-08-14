"""
PhishGuard-AI — Enhancements Unit & Integration Tests.
======================================================

Tests for:
1. Semantic Result Cache (DOM hash, TTL expiration, eviction).
2. Dynamic Mule Registry CRUD Endpoints (POST / DELETE).
3. Telemetry CSV Export Endpoint.
"""

from __future__ import annotations

import time
import pytest
from httpx import AsyncClient

from services.cache_service import SemanticResultCache


# ==============================================================================
# 1. Semantic Result Cache Tests
# ==============================================================================

class TestSemanticResultCache:

    def test_cache_set_and_get(self) -> None:
        cache = SemanticResultCache(ttl_seconds=60)
        key = cache.hash_key("URL: https://scam-site.test | login to your bank")
        payload = {"label": "PHISHING", "confidence": 0.98, "is_malicious": True}

        assert cache.get(key) is None
        cache.set(key, payload)
        cached = cache.get(key)
        assert cached is not None
        assert cached["label"] == "PHISHING"
        assert cached["confidence"] == 0.98

    def test_cache_ttl_expiration(self) -> None:
        cache = SemanticResultCache(ttl_seconds=1)
        key = cache.hash_key("test payload")
        cache.set(key, {"label": "LEGITIMATE", "confidence": 0.95, "is_malicious": False})

        assert cache.get(key) is not None
        time.sleep(1.1)
        assert cache.get(key) is None

    def test_cache_clear(self) -> None:
        cache = SemanticResultCache(ttl_seconds=60)
        key = cache.hash_key("test")
        cache.set(key, {"label": "SAFE"})
        cache.clear()
        assert cache.get(key) is None


# ==============================================================================
# 2. Dashboard Mule Registry & Export Integration Tests
# ==============================================================================

class TestDashboardEnhancements:

    @pytest.mark.asyncio
    async def test_add_and_delete_mule_account(self, test_client: AsyncClient) -> None:
        # 1. Add Mule Account
        add_resp = await test_client.post(
            "/api/v1/dashboard/mule-registry",
            json={
                "account_number": "998877665544",
                "bank_name": "Maybank",
                "platform_flagged": "Telegram Test",
                "report_count": 3,
            },
        )
        assert add_resp.status_code == 200
        data = add_resp.json()
        assert data["success"] is True
        record = data["record"]
        assert record["account_number"] == "998877665544"
        assert record["bank_name"] == "Maybank"
        mule_id = record["id"]

        # 2. Verify account is in registry
        list_resp = await test_client.get("/api/v1/dashboard/mule-registry")
        assert list_resp.status_code == 200
        accounts = list_resp.json()["accounts"]
        assert any(a["account_number"] == "998877665544" for a in accounts)

        # 3. Delete Mule Account
        del_resp = await test_client.delete(f"/api/v1/dashboard/mule-registry/{mule_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["success"] is True

        # 4. Delete non-existent returns 404
        del_404 = await test_client.delete("/api/v1/dashboard/mule-registry/999999")
        assert del_404.status_code == 404

    @pytest.mark.asyncio
    async def test_telemetry_csv_export(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/telemetry/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "Log ID,Malicious URL,BERT Score,Timestamp" in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_distributions(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/distributions")
        assert resp.status_code == 200
        data = resp.json()
        assert "banks" in data
        assert "platforms" in data
        assert "timeline" in data

    @pytest.mark.asyncio
    async def test_duitnow_scanner_integration(self, test_client: AsyncClient) -> None:
        from services.mule_scanner import MuleScanner
        import aiosqlite
        from database.init_db import initialize_database

        scanner = MuleScanner()
        db = await initialize_database()
        try:
            # Test mobile DuitNow format
            result = await scanner.scan_and_verify(
                "Please pay deposit to DuitNow 012-3456789 immediately.", db
            )
            assert "012-3456789" in result["accounts_extracted"] or "0123456789" in result["accounts_extracted"]
            assert result["mule_detected"] is True
            assert any("DuitNow" in acc["bank_name"] for acc in result["flagged_accounts"])
        finally:
            await db.close()

