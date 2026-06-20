"""
PhishGuard-AI — NLP Engine Unit Tests.
========================================

Tests the ``SemanticEngine`` service interface.  Uses the mock engine
from conftest to avoid loading the 438 MB BERT model during CI/CD.
"""

from __future__ import annotations

import pytest

from tests.conftest import MockSemanticEngine


class TestMockSemanticEngine:
    """Tests using the lightweight MockSemanticEngine stand-in."""

    @pytest.mark.asyncio
    async def test_predict_returns_correct_schema(self) -> None:
        engine = MockSemanticEngine()
        result = await engine.predict("This is a test page.")

        assert "label" in result
        assert "confidence" in result
        assert "is_malicious" in result

    @pytest.mark.asyncio
    async def test_predict_legitimate_defaults(self) -> None:
        engine = MockSemanticEngine()
        result = await engine.predict("Normal banking page content.")

        assert result["label"] == "LEGITIMATE"
        assert result["confidence"] == 0.95
        assert result["is_malicious"] is False

    @pytest.mark.asyncio
    async def test_predict_phishing_override(self) -> None:
        engine = MockSemanticEngine(
            label="PHISHING", confidence=0.97, is_malicious=True
        )
        result = await engine.predict("URGENT: Transfer RM500 now!")

        assert result["label"] == "PHISHING"
        assert result["confidence"] == 0.97
        assert result["is_malicious"] is True

    @pytest.mark.asyncio
    async def test_predict_threshold_boundary(self) -> None:
        """Test with confidence exactly at the threshold (0.75)."""
        engine = MockSemanticEngine(
            label="PHISHING", confidence=0.75, is_malicious=True
        )
        result = await engine.predict("Suspicious content")

        assert result["is_malicious"] is True
        assert result["confidence"] == 0.75

    @pytest.mark.asyncio
    async def test_predict_below_threshold(self) -> None:
        """Test with confidence below threshold — should not be malicious."""
        engine = MockSemanticEngine(
            label="PHISHING", confidence=0.74, is_malicious=False
        )
        result = await engine.predict("Borderline content")

        assert result["is_malicious"] is False

    def test_warm_up_does_not_raise(self) -> None:
        engine = MockSemanticEngine()
        engine.warm_up()  # Should not raise

    def test_shutdown_does_not_raise(self) -> None:
        engine = MockSemanticEngine()
        engine.shutdown()  # Should not raise

    @pytest.mark.asyncio
    async def test_predict_with_empty_text(self) -> None:
        engine = MockSemanticEngine()
        result = await engine.predict("")
        assert result["label"] == "LEGITIMATE"

    @pytest.mark.asyncio
    async def test_predict_with_very_long_text(self) -> None:
        engine = MockSemanticEngine()
        long_text = "word " * 10_000
        result = await engine.predict(long_text)
        assert result["label"] == "LEGITIMATE"
