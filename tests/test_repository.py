"""
PhishGuard-AI — Repository Unit Tests.
========================================

Tests the async data-access methods in ``database.repository``.
Uses the in-memory ``test_db`` fixture from ``conftest.py``.
"""

from __future__ import annotations

import pytest

from database.repository import check_mule_accounts, log_threat_telemetry


class TestCheckMuleAccounts:
    """Tests for the ``check_mule_accounts()`` repository function."""

    @pytest.mark.asyncio
    async def test_returns_match_for_known_account(self, test_db) -> None:
        result = await check_mule_accounts(["112233445566"], test_db)
        assert len(result) == 1
        assert result[0]["account_number"] == "112233445566"
        assert result[0]["bank_name"] == "Maybank"
        assert result[0]["report_count"] == 14

    @pytest.mark.asyncio
    async def test_returns_empty_for_unknown_account(self, test_db) -> None:
        result = await check_mule_accounts(["9999999999"], test_db)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_for_empty_list(self, test_db) -> None:
        result = await check_mule_accounts([], test_db)
        assert result == []

    @pytest.mark.asyncio
    async def test_multiple_accounts_partial_match(self, test_db) -> None:
        result = await check_mule_accounts(
            ["112233445566", "0000000000", "76001234567890"], test_db
        )
        # Two of three should match (Maybank and CIMB)
        assert len(result) == 2
        matched_accounts = {r["account_number"] for r in result}
        assert "112233445566" in matched_accounts
        assert "76001234567890" in matched_accounts

    @pytest.mark.asyncio
    async def test_returns_all_fields(self, test_db) -> None:
        result = await check_mule_accounts(["3112233445"], test_db)
        assert len(result) == 1
        entry = result[0]
        assert "account_number" in entry
        assert "bank_name" in entry
        assert "report_count" in entry
        assert entry["bank_name"] == "Public Bank"


class TestLogThreatTelemetry:
    """Tests for the ``log_threat_telemetry()`` repository function."""

    @pytest.mark.asyncio
    async def test_log_persists_entry(self, test_db) -> None:
        await log_threat_telemetry(
            url="https://evil-phishing.com/login",
            score=0.98,
            db=test_db,
        )

        cursor = await test_db.execute(
            "SELECT malicious_url, bert_score FROM threat_telemetry;"
        )
        rows = await cursor.fetchall()

        assert len(rows) == 1
        assert rows[0][0] == "https://evil-phishing.com/login"
        assert abs(rows[0][1] - 0.98) < 0.001

    @pytest.mark.asyncio
    async def test_log_multiple_entries(self, test_db) -> None:
        for i in range(5):
            await log_threat_telemetry(
                url=f"https://phish-{i}.com",
                score=0.80 + i * 0.03,
                db=test_db,
            )

        cursor = await test_db.execute(
            "SELECT COUNT(*) FROM threat_telemetry;"
        )
        row = await cursor.fetchone()
        assert row[0] == 5

    @pytest.mark.asyncio
    async def test_log_entry_has_timestamp(self, test_db) -> None:
        await log_threat_telemetry(
            url="https://timestamped.com",
            score=0.85,
            db=test_db,
        )

        cursor = await test_db.execute(
            "SELECT timestamp FROM threat_telemetry WHERE malicious_url = ?;",
            ("https://timestamped.com",),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is not None  # Timestamp should be auto-populated
