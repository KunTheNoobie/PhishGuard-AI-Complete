"""
PhishGuard-AI — Mule Report Review Queue Tests.
================================================

``POST /api/v1/mule-reports`` (extension, API key) queues a report;
``/api/v1/dashboard/mule-reports`` (admin) lists and reviews it.  A report
must never reach the blocking registry without analyst approval.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

NEW_ACCOUNT = "514098765432"


async def _registry_count(db, account: str) -> int:
    cursor = await db.execute("SELECT COUNT(*) FROM mule_registry WHERE account_number = ?;", (account,))
    return (await cursor.fetchone())[0]


class TestMuleReportSubmission:

    @pytest.mark.asyncio
    async def test_report_requires_api_key(self, anon_client: AsyncClient) -> None:
        resp = await anon_client.post("/api/v1/mule-reports", json={"account_number": NEW_ACCOUNT})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_is_queued_not_registered(self, test_client: AsyncClient, test_db) -> None:
        resp = await test_client.post(
            "/api/v1/mule-reports",
            json={"account_number": NEW_ACCOUNT, "bank_name": "Maybank", "page_url": "http://murah-gadget-store.com/x"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "PENDING" and body["already_registered"] is False
        assert await _registry_count(test_db, NEW_ACCOUNT) == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["12", "abc123456789", "1234567890'; DROP TABLE mule_registry;--", "x" * 40])
    async def test_invalid_account_numbers_rejected(self, test_client: AsyncClient, bad: str) -> None:
        resp = await test_client.post("/api/v1/mule-reports", json={"account_number": bad})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_report_on_registered_account_links_and_increments(self, test_client: AsyncClient, test_db) -> None:
        cursor = await test_db.execute("SELECT id, report_count FROM mule_registry WHERE account_number = '112233445566';")
        registry_id, before = await cursor.fetchone()
        resp = await test_client.post("/api/v1/mule-reports", json={"account_number": "1122-3344-5566"})
        assert resp.status_code == 201 and resp.json()["already_registered"] is True
        cursor = await test_db.execute("SELECT report_count FROM mule_registry WHERE id = ?;", (registry_id,))
        assert (await cursor.fetchone())[0] == before + 1
        cursor = await test_db.execute("SELECT registry_id FROM mule_reports ORDER BY report_id DESC LIMIT 1;")
        assert (await cursor.fetchone())[0] == registry_id


class TestMuleReportReview:

    @pytest.mark.asyncio
    async def test_review_queue_requires_admin(self, anon_client: AsyncClient) -> None:
        assert (await anon_client.get("/api/v1/dashboard/mule-reports")).status_code == 401
        resp = await anon_client.post("/api/v1/dashboard/mule-reports/1/review", json={"decision": "APPROVE"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_approve_promotes_to_registry(self, test_client: AsyncClient, test_db) -> None:
        report_id = (await test_client.post("/api/v1/mule-reports", json={"account_number": NEW_ACCOUNT})).json()["report_id"]
        listing = (await test_client.get("/api/v1/dashboard/mule-reports")).json()
        assert any(r["report_id"] == report_id and r["status"] == "PENDING" for r in listing["reports"])

        review = await test_client.post(f"/api/v1/dashboard/mule-reports/{report_id}/review", json={"decision": "APPROVE"})
        assert review.status_code == 200 and review.json()["status"] == "APPROVED"
        assert await _registry_count(test_db, NEW_ACCOUNT) == 1

        again = await test_client.post(f"/api/v1/dashboard/mule-reports/{report_id}/review", json={"decision": "REJECT"})
        assert again.status_code == 409

    @pytest.mark.asyncio
    async def test_reject_leaves_registry_untouched(self, test_client: AsyncClient, test_db) -> None:
        report_id = (await test_client.post("/api/v1/mule-reports", json={"account_number": NEW_ACCOUNT})).json()["report_id"]
        review = await test_client.post(f"/api/v1/dashboard/mule-reports/{report_id}/review", json={"decision": "REJECT"})
        assert review.json()["status"] == "REJECTED"
        assert await _registry_count(test_db, NEW_ACCOUNT) == 0

    @pytest.mark.asyncio
    async def test_review_validation_and_missing_report(self, test_client: AsyncClient) -> None:
        assert (await test_client.post("/api/v1/dashboard/mule-reports/999999/review", json={"decision": "APPROVE"})).status_code == 404
        assert (await test_client.post("/api/v1/dashboard/mule-reports/1/review", json={"decision": "MAYBE"})).status_code == 422

    @pytest.mark.asyncio
    async def test_foreign_key_set_null_on_registry_delete(self, test_client: AsyncClient, test_db) -> None:
        report_id = (await test_client.post("/api/v1/mule-reports", json={"account_number": NEW_ACCOUNT})).json()["report_id"]
        registry_id = (await test_client.post(
            f"/api/v1/dashboard/mule-reports/{report_id}/review", json={"decision": "APPROVE"}
        )).json()["registry_id"]
        await test_db.execute("DELETE FROM mule_registry WHERE id = ?;", (registry_id,))
        await test_db.commit()
        cursor = await test_db.execute("SELECT registry_id, status FROM mule_reports WHERE report_id = ?;", (report_id,))
        assert await cursor.fetchone() == (None, "APPROVED")
