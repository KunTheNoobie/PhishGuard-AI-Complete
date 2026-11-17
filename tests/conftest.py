"""
PhishGuard-AI — Shared Test Fixtures.
======================================

* ``test_db``          in-memory SQLite with the production schema and seed.
* ``test_client``      the real FastAPI app with a mock BERT engine (LEGITIMATE),
                       sending the API key by default.
* ``phishing_client``  the same app with a mock engine that says PHISHING.
* ``anon_client``      no credentials, to prove routes are protected.
* ``dashboard``        a client signed in to the dashboard with a session cookie.
* ``qr_png``           builds a PNG QR code for any payload (OpenCV encoder).

The real 438 MB BERT model and the YOLO weights are never loaded in tests.
"""

from __future__ import annotations

import base64
import os
os.environ.setdefault("PHISHGUARD_SEED_DEMO", "false")  # tests count rows: keep the demonstration dataset out
import sys
from typing import Any, AsyncGenerator, Callable, Final

import aiosqlite
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.config import API_SECRET_TOKEN  # noqa: E402
from database.init_db import apply_schema  # noqa: E402

AUTH_HEADERS: Final[dict[str, str]] = {"Authorization": f"Bearer {API_SECRET_TOKEN}"}


class MockSemanticEngine:
    """Stand-in for ``SemanticEngine`` returning a fixed classification."""

    def __init__(self, phishing_probability: float = 0.05) -> None:
        self.p = phishing_probability
        self.calls: list[str] = []

    async def predict(self, text: str) -> dict[str, Any]:
        self.calls.append(text)
        label = "PHISHING" if self.p >= 0.5 else "LEGITIMATE"
        return {
            "label": label,
            "confidence": self.p if label == "PHISHING" else 1 - self.p,
            "phishing_probability": self.p,
            "is_malicious": self.p >= 0.75,
        }


@pytest_asyncio.fixture
async def test_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    db = await aiosqlite.connect(":memory:")
    await apply_schema(db)
    yield db
    await db.close()


def _wire(app: Any, db: aiosqlite.Connection, engine: MockSemanticEngine) -> None:
    from core.rate_limit import limiter
    from services.mule_scanner import MuleScanner

    app.state.db = db
    app.state.semantic_engine = engine
    app.state.mule_scanner = MuleScanner()
    app.state.cache = None
    app.state.visual_detector = None
    limiter._storage.reset()  # noqa: SLF001 — isolate rate limits between tests


async def _client(engine: MockSemanticEngine, db: aiosqlite.Connection, headers: dict[str, str]):
    from main import app

    _wire(app, db, engine)
    return AsyncClient(transport=ASGITransport(app=app), base_url="https://test", headers=headers)


@pytest_asyncio.fixture
async def test_client(test_db: aiosqlite.Connection) -> AsyncGenerator[AsyncClient, None]:
    async with await _client(MockSemanticEngine(0.05), test_db, AUTH_HEADERS) as client:
        yield client


@pytest_asyncio.fixture
async def phishing_client(test_db: aiosqlite.Connection) -> AsyncGenerator[AsyncClient, None]:
    async with await _client(MockSemanticEngine(0.97), test_db, AUTH_HEADERS) as client:
        yield client


@pytest_asyncio.fixture
async def anon_client(test_db: aiosqlite.Connection) -> AsyncGenerator[AsyncClient, None]:
    async with await _client(MockSemanticEngine(0.05), test_db, {}) as client:
        yield client


@pytest_asyncio.fixture
async def dashboard(test_db: aiosqlite.Connection) -> AsyncGenerator[AsyncClient, None]:
    async with await _client(MockSemanticEngine(0.05), test_db, {}) as client:
        response = await client.post("/api/v1/dashboard/auth/login", json={"api_key": API_SECRET_TOKEN})
        assert response.status_code == 200
        yield client


@pytest.fixture
def qr_png() -> Callable[[str], str]:
    """Return a function that encodes ``payload`` as a base64 PNG QR code."""
    import cv2

    def make(payload: str) -> str:
        image = cv2.QRCodeEncoder.create().encode(payload)
        image = cv2.resize(image, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
        image = cv2.copyMakeBorder(image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
        ok, buffer = cv2.imencode(".png", image)
        assert ok
        return base64.b64encode(buffer.tobytes()).decode("ascii")

    return make


@pytest.fixture(autouse=True)
def _no_live_certificate_checks(monkeypatch):
    """Tests never open real TLS connections; the certificate check has its own tests."""
    async def none(host, port=443):
        return None
    monkeypatch.setattr("services.analysis_pipeline.check_certificate", none)
