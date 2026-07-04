from __future__ import annotations

import pytest
from httpx import AsyncClient

from api import visual as visual_api
from schemas.visual import BoundingBox, DetectedLogo
from services.visual_detector import evaluate_logo_domain
from tests.conftest import AUTH_HEADERS


def logo(brand: str, confidence: float) -> DetectedLogo:
    return DetectedLogo(
        brand=brand,
        confidence=confidence,
        bbox=BoundingBox(x1=10, y1=20, x2=110, y2=70),
    )


class TestLogoDomainEvaluation:
    def test_matching_official_domain_is_safe(self) -> None:
        result = evaluate_logo_domain(
            "https://www.cimbclicks.com.my/login",
            [logo("CIMB", 0.91)],
        )

        assert result.risk_level == "safe"
        assert result.detected_logos[0].brand == "CIMB"

    def test_lookalike_domain_is_dangerous(self) -> None:
        result = evaluate_logo_domain(
            "https://cimb.com.my.evil.example/login",
            [logo("CIMB", 0.91)],
        )

        assert result.risk_level == "dangerous"

    def test_lower_confidence_mismatch_is_suspicious(self) -> None:
        result = evaluate_logo_domain(
            "https://example.com/login",
            [logo("Maybank", 0.80)],
        )

        assert result.risk_level == "suspicious"

    def test_no_supported_logo_is_safe(self) -> None:
        result = evaluate_logo_domain("https://example.com", [])

        assert result.risk_level == "safe"
        assert result.detected_logos == []

    def test_detector_warning_never_becomes_safe(self) -> None:
        with pytest.raises(RuntimeError, match="model missing"):
            evaluate_logo_domain(
                "https://example.com",
                [],
                detector_warning="model missing",
            )


class TestVisualEndpoint:
    @pytest.mark.asyncio
    async def test_authentication_is_required(self, test_client: AsyncClient) -> None:
        response = await test_client.post(
            "/api/visual/analyze",
            json={
                "current_url": "https://example.com",
                "page_title": "Example",
                "visible_text": "Example page",
                "screenshot": "ignored-by-mock",
            },
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_model_warning_returns_503(
        self,
        test_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            visual_api._detector,
            "detect",
            lambda _screenshot: ([], "Visual model is unavailable."),
        )

        response = await test_client.post(
            "/api/visual/analyze",
            headers=AUTH_HEADERS,
            json={
                "current_url": "https://example.com",
                "page_title": "Example",
                "visible_text": "Example page",
                "screenshot": "ignored-by-mock",
            },
        )

        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "VISUAL_MODEL_UNAVAILABLE"

    @pytest.mark.asyncio
    async def test_fake_domain_logo_mismatch_returns_dangerous(
        self,
        test_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            visual_api._detector,
            "detect",
            lambda _screenshot: ([logo("Public Bank", 0.90)], None),
        )

        response = await test_client.post(
            "/api/visual/analyze",
            headers=AUTH_HEADERS,
            json={
                "current_url": "https://fake-pbebank-login.example",
                "page_title": "Public Bank Login",
                "visible_text": "Sign in",
                "screenshot": "ignored-by-mock",
            },
        )

        assert response.status_code == 200
        assert response.json()["risk_level"] == "dangerous"

