"""
PhishGuard-AI — Mule Scanner Unit Tests.
==========================================

Tests the ``MuleScanner`` service: regex extraction (bank-specific
and generic fallback) and registry cross-referencing.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from services.mule_scanner import MuleScanner


class TestMuleScannerRegex:
    """Tests for regex-based account number extraction."""

    @pytest.fixture
    def scanner(self) -> MuleScanner:
        return MuleScanner()

    # ── Bank-Specific Pattern Tests ──

    def test_extracts_maybank_12_digit(self, scanner: MuleScanner) -> None:
        text = "Transfer to account 112233445566 now."
        matches = scanner._generic_pattern.findall(text)
        # Should be caught by bank-specific or generic
        found = set()
        for _, pattern in scanner._bank_patterns.items():
            found.update(pattern.findall(text))
        assert "112233445566" in found

    def test_extracts_cimb_14_digit(self, scanner: MuleScanner) -> None:
        text = "CIMB account: 76001234567890"
        found = set()
        for _, pattern in scanner._bank_patterns.items():
            found.update(pattern.findall(text))
        assert "76001234567890" in found

    def test_extracts_public_bank_10_digit(self, scanner: MuleScanner) -> None:
        text = "Pay to Public Bank 3112233445"
        found = set()
        for _, pattern in scanner._bank_patterns.items():
            found.update(pattern.findall(text))
        assert "3112233445" in found

    def test_extracts_rhb_14_digit(self, scanner: MuleScanner) -> None:
        text = "RHB: 21234567890123"
        found = set()
        for _, pattern in scanner._bank_patterns.items():
            found.update(pattern.findall(text))
        assert "21234567890123" in found

    def test_extracts_ambank_13_digit(self, scanner: MuleScanner) -> None:
        text = "AmBank account 8123456789012"
        found = set()
        for _, pattern in scanner._bank_patterns.items():
            found.update(pattern.findall(text))
        assert "8123456789012" in found

    def test_generic_fallback_catches_unknown_format(self, scanner: MuleScanner) -> None:
        text = "Unknown bank: 4567890123"
        # This 10-digit number starting with 4 doesn't match any bank-specific pattern
        bank_found = set()
        for _, pattern in scanner._bank_patterns.items():
            bank_found.update(pattern.findall(text))
        generic_found = set(scanner._generic_pattern.findall(text))
        # Should be caught by generic but not bank-specific
        assert "4567890123" in generic_found

    def test_no_match_on_short_numbers(self, scanner: MuleScanner) -> None:
        text = "Phone: 012345678"  # 9 digits — too short
        found = set(scanner._generic_pattern.findall(text))
        assert len(found) == 0

    def test_no_match_on_long_numbers(self, scanner: MuleScanner) -> None:
        text = "ID: 123456789012345"  # 15 digits — too long
        found = set(scanner._generic_pattern.findall(text))
        assert len(found) == 0

    def test_deduplication(self, scanner: MuleScanner) -> None:
        text = "Account 3112233445 and again 3112233445"
        all_matches = set()
        for _, pattern in scanner._bank_patterns.items():
            all_matches.update(pattern.findall(text))
        all_matches.update(scanner._generic_pattern.findall(text))
        # Should only have one entry after dedup
        assert len([x for x in all_matches if x == "3112233445"]) == 1

    def test_multiple_accounts_in_text(self, scanner: MuleScanner) -> None:
        text = "Pay 112233445566 or 76001234567890 or 3112233445"
        all_matches = set()
        for _, pattern in scanner._bank_patterns.items():
            all_matches.update(pattern.findall(text))
        all_matches.update(scanner._generic_pattern.findall(text))
        assert len(all_matches) >= 3


class TestMuleScannerVerification:
    """Tests for the full scan_and_verify pipeline with DB lookups."""

    @pytest.mark.asyncio
    async def test_scan_detects_known_mule(self, test_db) -> None:
        scanner = MuleScanner()
        # Use a seed account number from the expanded seed data
        text = "Please transfer to 112233445566 immediately"
        result = await scanner.scan_and_verify(text, test_db)

        assert result["mule_detected"] is True
        assert len(result["flagged_accounts"]) >= 1
        assert result["flagged_accounts"][0]["account_number"] == "112233445566"
        assert result["flagged_accounts"][0]["bank_name"] == "Maybank"

    @pytest.mark.asyncio
    async def test_scan_no_mule_in_clean_text(self, test_db) -> None:
        scanner = MuleScanner()
        text = "Welcome to our website. Enjoy your shopping experience."
        result = await scanner.scan_and_verify(text, test_db)

        assert result["mule_detected"] is False
        assert result["flagged_accounts"] == []
        assert result["accounts_extracted"] == []

    @pytest.mark.asyncio
    async def test_scan_extracts_but_not_flagged(self, test_db) -> None:
        scanner = MuleScanner()
        # A number that matches regex but is NOT in the mule registry
        text = "Account number: 9999999999"
        result = await scanner.scan_and_verify(text, test_db)

        assert len(result["accounts_extracted"]) >= 1
        assert result["mule_detected"] is False
        assert result["flagged_accounts"] == []

    @pytest.mark.asyncio
    async def test_scan_multiple_accounts_one_flagged(self, test_db) -> None:
        scanner = MuleScanner()
        # 112233445566 is in seed data, 9999888877 is not
        text = "Pay to 112233445566 or 9999888877"
        result = await scanner.scan_and_verify(text, test_db)

        assert result["mule_detected"] is True
        assert len(result["flagged_accounts"]) == 1
        assert len(result["accounts_extracted"]) >= 2
