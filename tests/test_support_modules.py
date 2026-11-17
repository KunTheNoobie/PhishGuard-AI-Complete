"""Result cache, BERT input preparation and the YOLOv8n logo-to-domain decision."""

from __future__ import annotations

import time

from schemas.visual import BoundingBox, DetectedLogo
from services.cache_service import SemanticResultCache
from services.nlp_engine import build_model_input
from services.visual_detector import evaluate_logo_domain

BOX = BoundingBox(x1=0, y1=0, x2=10, y2=10)


def logo(brand: str, confidence: float = 0.93) -> DetectedLogo:
    return DetectedLogo(brand=brand, confidence=confidence, bbox=BOX)


class TestCache:
    def test_hit_miss_and_expiry(self):
        cache = SemanticResultCache(ttl_seconds=1, max_entries=10)
        key = cache.hash_key("maybank2u.com.my/login")
        assert cache.get(key) is None
        cache.set(key, {"label": "LEGITIMATE"})
        assert cache.get(key) == {"label": "LEGITIMATE"}
        cache._store[key] = (cache._store[key][0], time.monotonic() - 5)  # noqa: SLF001 — age the entry
        assert cache.get(key) is None

    def test_evicts_oldest_when_full(self):
        cache = SemanticResultCache(ttl_seconds=60, max_entries=2)
        for name in ("a", "b", "c"):
            cache.set(name, {"v": name})
        assert cache.get("a") is None and cache.get("c") == {"v": "c"}
        cache.clear()
        assert cache.get("c") is None


class TestBertInput:
    def test_scheme_and_www_removed(self):
        assert build_model_input("https://www.maybank2u.com.my/home") == "maybank2u.com.my/home"

    def test_tricks_kept_for_the_model(self):
        assert build_model_input("https://maybank2u.com.my@evil.top/x") == "maybank2u.com.my@evil.top/x"


class TestLogoDomain:
    def test_no_logo_is_safe(self):
        assert evaluate_logo_domain("https://example.com/", []).risk_level == "safe"

    def test_logo_on_official_domain_is_safe(self):
        assert evaluate_logo_domain("https://www.maybank2u.com.my/", [logo("Maybank")]).risk_level == "safe"

    def test_logo_on_foreign_domain_is_dangerous(self):
        result = evaluate_logo_domain("https://rewards-portal.example/", [logo("Maybank")])
        assert result.risk_level == "dangerous" and "maybank2u.com.my" in result.reason

    def test_low_confidence_mismatch_is_only_suspicious(self):
        assert evaluate_logo_domain("https://rewards.example/", [logo("CIMB", 0.6)]).risk_level == "suspicious"

    def test_cross_brand_logo_on_official_domain(self):
        noisy = evaluate_logo_domain("https://www.cimbclicks.com.my/", [logo("Maybank", 0.7)])
        strong = evaluate_logo_domain("https://www.cimbclicks.com.my/", [logo("Maybank", 0.97)])
        assert noisy.risk_level == "safe"
        assert strong.risk_level == "safe"  # trusted domains are never flagged by the logo check
