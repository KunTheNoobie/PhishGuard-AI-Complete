"""Mule-account extraction, registry lookup and QR payload handling."""

from __future__ import annotations

import pytest

from services.mule_scanner import MuleScanner, extract_accounts, normalise_account
from services.qr_payload import classify_payload, decode_qr_image, extract_duitnow_accounts, parse_emvco_tlv


def numbers(text: str) -> set[str]:
    return {a["account_number"] for a in extract_accounts(text)}


class TestExtraction:
    @pytest.mark.parametrize("written", ["514276103388", "5142 7610 3388", "5142-7610-3388", "5142.7610.3388"])
    def test_maybank_formats(self, written):
        found = extract_accounts(f"Transfer RM10 to {written} now")
        assert found[0]["account_number"] == "514276103388"
        assert found[0]["account_type"] == "Maybank"

    @pytest.mark.parametrize("written", ["+60 12-345 6789", "012-3456789", "6012 345 6789", "0123456789"])
    def test_duitnow_phone_formats(self, written):
        assert numbers(f"DuitNow to {written}") == {"0123456789"}

    def test_nric_proxy(self):
        found = extract_accounts("DuitNow ID 980102-14-5678")
        assert found[0]["account_number"] == "980102145678"
        assert found[0]["account_type"] == "DuitNow ID (NRIC)"

    @pytest.mark.parametrize("text", [
        "Price RM1,234.56 only", "Order 12 34 56", "Card 4111 1111 1111 1111", "Version 1.2.3.4.5",
        "Call 03-2178 8888",
    ])
    def test_ignores_amounts_short_numbers_cards_and_landlines(self, text):
        assert not numbers(text)

    def test_normalise(self):
        assert normalise_account("+60 12-345 6789") == "0123456789"
        assert normalise_account("7600 1234 5678 90") == "76001234567890"


class TestRegistryScan:
    async def test_spaced_account_matches_registry(self, test_db):
        result = await MuleScanner().scan_and_verify("Pay to Maybank 1122 3344 5566 today", test_db)
        assert result["mule_detected"]
        assert result["flagged_accounts"][0]["account_number"] == "112233445566"

    async def test_hyphenated_nric_matches_registry(self, test_db):
        result = await MuleScanner().scan_and_verify("DuitNow ID 980102-14-5678", test_db)
        assert result["mule_detected"]

    async def test_unknown_account_is_not_flagged(self, test_db):
        result = await MuleScanner().scan_and_verify("Account 5555 6666 7777", test_db)
        assert result["accounts_extracted"] == ["555566667777"] and not result["mule_detected"]


def _tlv(tag: str, value: str) -> str:
    return f"{tag}{len(value):02d}{value}"


# A DuitNow merchant QR (EMVCo TLV) that pays account 112233445566.
EMV = (_tlv("00", "01") + _tlv("01", "12")
       + _tlv("26", _tlv("00", "A0000006150001") + _tlv("02", "112233445566"))
       + _tlv("52", "0000") + _tlv("53", "458") + _tlv("58", "MY") + _tlv("59", "SHOP") + _tlv("63", "ABCD"))


class TestQrPayload:
    def test_tlv_parse(self):
        tlv = parse_emvco_tlv(EMV)
        assert tlv["00"] == "01" and tlv["58"] == "MY"

    def test_duitnow_account_extracted(self):
        assert {a["account_number"] for a in extract_duitnow_accounts(EMV)} == {"112233445566"}

    def test_deeplink(self):
        found = extract_duitnow_accounts("https://duitnow.my/pay?acc=1122-3344-5566")
        assert found[0]["account_number"] == "112233445566"

    @pytest.mark.parametrize("payload, kind", [
        ("https://example.com/path", "url"), ("example.com", "url"), (EMV, "payment"), ("hello world", "text"),
    ])
    def test_classify(self, payload, kind):
        assert classify_payload(payload)["payload_type"] == kind

    def test_decode_real_image(self, qr_png):
        result = decode_qr_image(qr_png("https://example.com/qr-test"))
        assert result["decoded"] and result["urls"] == ["https://example.com/qr-test"]

    def test_decode_rejects_non_image(self):
        assert not decode_qr_image("bm90IGFuIGltYWdl")["decoded"]
