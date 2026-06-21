"""
PhishGuard-AI — Shared Pytest Fixtures.
=========================================

Provides reusable fixtures for all test modules:

- ``test_client``: An ``httpx.AsyncClient`` wired to the FastAPI app.
- ``mock_semantic_engine``: A lightweight mock of ``SemanticEngine``.
- ``test_db``: An in-memory aiosqlite database with schema + seed data.
- ``auth_headers``: Pre-built Authorization headers with the test API key.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator, Final
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ── Ensure the project root is importable ──
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.config import API_SECRET_TOKEN
from database.init_db import (
    _DDL_MULE_REGISTRY,
    _DDL_THREAT_TELEMETRY,
    _IDX_MULE_ACCOUNT,
    _IDX_TELEMETRY_URL,
    _INSERT_SEED,
    _SEED_MULE_ACCOUNTS,
)


# ==============================================================================
# Auth Headers
# ==============================================================================

AUTH_HEADERS: Final[dict[str, str]] = {
    "Authorization": f"Bearer {API_SECRET_TOKEN}",
    "Content-Type": "application/json",
}


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Return pre-built Authorization headers."""
    return dict(AUTH_HEADERS)


# ==============================================================================
# In-Memory Database
# ==============================================================================

@pytest_asyncio.fixture
async def test_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Create a fresh in-memory SQLite database with schema + seed data."""
    db = await aiosqlite.connect(":memory:")
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA foreign_keys=ON;")
    await db.execute(_DDL_MULE_REGISTRY)
    await db.execute(_DDL_THREAT_TELEMETRY)
    await db.execute(_IDX_MULE_ACCOUNT)
    await db.execute(_IDX_TELEMETRY_URL)

    for account in _SEED_MULE_ACCOUNTS:
        await db.execute(_INSERT_SEED, account)
    await db.commit()

    yield db

    await db.close()


# ==============================================================================
# Mock Semantic Engine
# ==============================================================================

class MockSemanticEngine:
    """Lightweight stand-in for ``SemanticEngine`` that avoids loading BERT."""

    def __init__(self, label: str = "LEGITIMATE", confidence: float = 0.95,
                 is_malicious: bool = False) -> None:
        self._result: dict[str, Any] = {
            "label": label,
            "confidence": confidence,
            "is_malicious": is_malicious,
        }

    async def predict(self, text: str) -> dict[str, Any]:
        return dict(self._result)

    def warm_up(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


@pytest.fixture
def mock_semantic_engine() -> MockSemanticEngine:
    """Return a safe mock engine (LEGITIMATE, 0.95, not malicious)."""
    return MockSemanticEngine()


@pytest.fixture
def mock_phishing_engine() -> MockSemanticEngine:
    """Return a mock engine that always flags content as PHISHING."""
    return MockSemanticEngine(
        label="PHISHING", confidence=0.97, is_malicious=True
    )


# ==============================================================================
# Full Test Client (wired to the FastAPI app with mocked singletons)
# ==============================================================================

@pytest_asyncio.fixture
async def test_client(
    test_db: aiosqlite.Connection,
    mock_semantic_engine: MockSemanticEngine,
) -> AsyncGenerator[AsyncClient, None]:
    """Provide an ``httpx.AsyncClient`` backed by the real FastAPI app
    but with mocked ML engine and in-memory database."""
    from main import app
    from services.mule_scanner import MuleScanner
    from api.endpoints import limiter as endpoint_limiter

    # Inject test singletons into app.state
    app.state.db = test_db
    app.state.semantic_engine = mock_semantic_engine
    app.state.mule_scanner = MuleScanner()

    # Reset both rate limiters to prevent 429 collisions across test classes
    app.state.limiter._storage.reset()
    endpoint_limiter._storage.reset()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def phishing_client(
    test_db: aiosqlite.Connection,
    mock_phishing_engine: MockSemanticEngine,
) -> AsyncGenerator[AsyncClient, None]:
    """Test client where the engine always returns PHISHING."""
    from main import app
    from services.mule_scanner import MuleScanner
    from api.endpoints import limiter as endpoint_limiter

    app.state.db = test_db
    app.state.semantic_engine = mock_phishing_engine
    app.state.mule_scanner = MuleScanner()

    # Reset both rate limiters to prevent 429 collisions across test classes
    app.state.limiter._storage.reset()
    endpoint_limiter._storage.reset()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
