"""Analysis API, dashboard API, authentication, SSRF protection and security headers."""

from __future__ import annotations

import pytest

from services.page_fetcher import fetch_page

PHISH_HTML = ("<html><body><h1>Maybank2u</h1><p>Your account access has been limited. Verify immediately.</p>"
              "<form><input name='u'><input type='password' name='p'></form></body></html>")


class TestAnalysisApi:
    async def test_requires_api_key(self, anon_client):
        assert (await anon_client.post("/api/v1/analyze", json={"url": "https://example.com"})).status_code in (401, 403)

    async def test_rejects_wrong_key(self, anon_client):
        r = await anon_client.post("/api/v1/analyze", json={"url": "https://example.com"},
                                   headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    @pytest.mark.parametrize("url", ["javascript:alert(1)", "ftp://example.com/x", "x"])
    async def test_rejects_non_web_urls(self, test_client, url):
        assert (await test_client.post("/api/v1/analyze", json={"url": url})).status_code == 422

    async def test_safe_page_full_response(self, test_client):
        r = await test_client.post("/api/v1/analyze", json={"url": "https://example.com/", "dom_content": "<p>Example</p>"})
        d = r.json()
        assert r.status_code == 200 and d["verdict"] == "SAFE" and d["risk_level"] == "safe"
        assert [s["name"] for s in d["steps"]][:4] == ["URL canonicalisation", "Trusted-domain check",
                                                       "Connection security", "Page structure (DOM)"]
        assert d["explanation"] and d["reasons"]

    async def test_http_page_warns_and_http_login_blocks(self, test_client):
        warn = (await test_client.post("/api/v1/analyze", json={"url": "http://neverssl.com/", "dom_content": "<p>x</p>"})).json()
        block = (await test_client.post("/api/v1/analyze", json={"url": "http://testphp.vulnweb.com/login.php",
                                                                 "dom_content": "<input type='password'>"})).json()
        assert warn["verdict"] == "WARNING" and block["rule"] == "H1_HTTP_SENSITIVE_FORM"

    async def test_phishing_clone_blocked(self, phishing_client):
        d = (await phishing_client.post("/api/v1/analyze", json={"url": "http://maybank2u-secure-login.top/m2u",
                                                                 "dom_content": PHISH_HTML})).json()
        assert d["verdict"] == "BLOCK_RENDER" and d["rule"] == "R2_BRAND_IN_HOSTNAME"

    async def test_spaced_mule_account_blocked(self, test_client):
        d = (await test_client.post("/api/v1/analyze", json={"url": "https://deals.example/pay",
                                                             "dom_content": "<p>Bank in to 1122 3344 5566</p>"})).json()
        assert d["rule"] == "R1_MULE_REGISTRY"

    async def test_userinfo_spoof_blocked(self, test_client):
        d = (await test_client.post("/api/v1/analyze", json={"url": "https://maybank2u.com.my@evil-login.top/",
                                                             "dom_content": "<p>hi</p>"})).json()
        assert d["rule"] == "R7_USERINFO_SPOOF" and d["hostname"] == "evil-login.top"

    async def test_trusted_domain_skips_bert(self, test_client):
        d = (await test_client.post("/api/v1/analyze", json={"url": "https://www.cimbclicks.com.my/",
                                                             "dom_content": "<p>CIMB</p>"})).json()
        assert d["is_whitelisted"] and d["bert"]["skipped"] and d["headline"] == "Official CIMB Bank website"

    async def test_mule_report_queued_normalised(self, test_client, test_db):
        r = await test_client.post("/api/v1/mule-reports", json={"account_number": "5142 7610 3388", "bank_name": "Maybank"})
        assert r.status_code == 201 and r.json()["status"] == "PENDING"
        row = await (await test_db.execute("SELECT account_number FROM mule_reports")).fetchone()
        assert row[0] == "514276103388"

    async def test_qr_endpoint(self, test_client, qr_png):
        d = (await test_client.post("/api/v1/analyze/qr", json={"image_base64": qr_png("just some text")})).json()
        assert d["decoded"] and d["payload_type"] == "text" and d["verdict"] == "SAFE"


class TestDashboardApi:
    async def test_routes_need_sign_in(self, anon_client):
        for path in ("/api/v1/dashboard/overview", "/api/v1/dashboard/mules", "/api/v1/dashboard/scans/export"):
            assert (await anon_client.get(path)).status_code == 401

    async def test_wrong_key_rejected(self, anon_client):
        r = await anon_client.post("/api/v1/dashboard/auth/login", json={"api_key": "nope"})
        assert r.status_code == 401

    async def test_session_cookie_flags(self, anon_client):
        r = await anon_client.post("/api/v1/dashboard/auth/login", json={"api_key": "12345678"})
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie

    async def test_logout(self, dashboard):
        await dashboard.post("/api/v1/dashboard/auth/logout")
        assert (await dashboard.get("/api/v1/dashboard/overview")).status_code == 401

    async def test_overview_counts_real_scans(self, dashboard):
        for url in ("https://example.com/", "http://neverssl.com/"):
            await dashboard.post("/api/v1/dashboard/analyze", json={"url": url, "page_text": "hello", "fetch_page": False})
        stats = (await dashboard.get("/api/v1/dashboard/overview")).json()["stats"]
        assert stats["total_scans"] == 2 and stats["safe"] == 1 and stats["http_warnings"] == 1
        assert stats["registry_accounts"] == 18

    async def test_scan_filter_and_exports(self, dashboard):
        await dashboard.post("/api/v1/dashboard/analyze", json={"url": "https://=cmd.example.com/", "page_text": "x"})
        rows = (await dashboard.get("/api/v1/dashboard/scans?verdict=SAFE")).json()["items"]
        assert rows and all(r["verdict"] == "SAFE" for r in rows)
        csv_text = (await dashboard.get("/api/v1/dashboard/scans/export?format=csv")).text
        assert csv_text.startswith("scan_id,created_at,source,url")
        js = (await dashboard.get("/api/v1/dashboard/scans/export?format=json")).json()
        assert js["count"] == len(js["scans"]) >= 1

    async def test_analyzer_account_number_is_checked(self, dashboard):
        d = (await dashboard.post("/api/v1/dashboard/analyze", json={
            "url": "https://example.com/", "account_number": "1122-3344-5566", "fetch_page": False})).json()
        assert d["rule"] == "R1_MULE_REGISTRY" and d["source"] == "dashboard"

    async def test_registry_add_search_delete(self, dashboard):
        rec = (await dashboard.post("/api/v1/dashboard/mules", json={
            "account_number": "7600-9999-8888-77", "bank_name": "CIMB Bank"})).json()
        assert rec["account_number"] == "76009999888877"
        found = (await dashboard.get("/api/v1/dashboard/mules?search=7600 9999")).json()
        assert found["total"] == 1
        assert (await dashboard.delete(f"/api/v1/dashboard/mules/{rec['id']}")).status_code == 200
        assert (await dashboard.delete(f"/api/v1/dashboard/mules/{rec['id']}")).status_code == 404

    async def test_report_review_promotes_to_registry(self, dashboard, test_client):
        await test_client.post("/api/v1/mule-reports", json={"account_number": "5555 6666 7777", "bank_name": "RHB Bank"})
        reports = (await dashboard.get("/api/v1/dashboard/mule-reports")).json()["reports"]
        rid = reports[0]["report_id"]
        r = (await dashboard.post(f"/api/v1/dashboard/mule-reports/{rid}/review", json={"decision": "APPROVE"})).json()
        assert r["status"] == "APPROVED" and r["changed"]
        again = (await dashboard.post(f"/api/v1/dashboard/mule-reports/{rid}/review", json={"decision": "REJECT"})).json()
        assert not again["changed"]
        d = (await test_client.post("/api/v1/analyze", json={"url": "https://x.example/", "dom_content": "<p>555566667777</p>"})).json()
        assert d["rule"] == "R1_MULE_REGISTRY"

    async def test_qr_scan_payment_code_to_mule(self, dashboard, qr_png):
        from tests.test_mule_and_qr import EMV

        d = (await dashboard.post("/api/v1/dashboard/qr-scan", json={"image_base64": qr_png(EMV)})).json()
        assert d["payload_type"] == "payment" and d["verdict"] == "BLOCK_RENDER"


class TestSsrfProtection:
    @pytest.mark.parametrize("url", ["http://127.0.0.1:8000/health", "http://localhost/", "http://169.254.169.254/latest",
                                     "http://10.0.0.5/", "http://[::1]/", "http://example.com:22/"])
    async def test_internal_targets_refused(self, url):
        result = await fetch_page(url)
        assert result.error and not result.html


class TestHardening:
    async def test_security_headers(self, test_client):
        r = await test_client.get("/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors" in r.headers["content-security-policy"]
        assert "strict-transport-security" in r.headers

    async def test_api_responses_not_cached(self, test_client):
        r = await test_client.post("/api/v1/analyze", json={"url": "https://example.com/"})
        assert r.headers["cache-control"] == "no-store"

    async def test_cors_allows_extension_not_random_origin(self, test_client):
        ok = await test_client.options("/api/v1/analyze", headers={
            "Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop", "Access-Control-Request-Method": "POST"})
        bad = await test_client.options("/api/v1/analyze", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        assert ok.headers.get("access-control-allow-origin") and not bad.headers.get("access-control-allow-origin")

    async def test_docs_and_dashboard_served(self, test_client):
        assert "swagger-ui" in (await test_client.get("/docs")).text
        assert (await test_client.get("/openapi.json")).json()["info"]["version"] == "4.1.0"
        assert (await test_client.get("/dashboard/")).status_code == 200
        assert (await test_client.get("/dashboard/sandbox.html")).status_code == 404


class TestBrowserReportedTlsError:
    async def test_certificate_error_from_the_browser_gives_a_warning(self, test_client):
        r = await test_client.post("/api/v1/analyze", json={"url": "https://expired.example-test.org/", "tls_error": "net::ERR_CERT_DATE_INVALID"})
        body = r.json()
        assert r.status_code == 200 and body["verdict"] == "WARNING" and body["rule"] == "W1_TLS_CERTIFICATE"

    async def test_malformed_tls_error_is_rejected(self, test_client):
        r = await test_client.post("/api/v1/analyze", json={"url": "https://example.org/", "tls_error": "<script>"})
        assert r.status_code == 422


class TestAnalyzerScreenshot:
    async def test_uploaded_screenshot_reaches_the_logo_detector(self, dashboard):
        from schemas.visual import BoundingBox, DetectedLogo

        class FakeDetector:
            def detect(self, screenshot):
                assert screenshot.startswith("data:image/png;base64,")
                return [DetectedLogo(brand="Maybank", confidence=0.96, bbox=BoundingBox(x1=1, y1=1, x2=50, y2=50))], None

        dashboard._transport.app.state.visual_detector = FakeDetector()
        shot = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        r = await dashboard.post("/api/v1/dashboard/analyze", json={
            "url": "https://rewards-portal.example/login", "page_text": "Enter your password to continue", "screenshot_b64": shot})
        body = r.json()
        visual = body["visual"]
        assert r.status_code == 200 and visual["status"] == "ok" and visual["detected_logos"][0]["brand"] == "Maybank"
        assert body["verdict"] == "BLOCK_RENDER"

    async def test_no_screenshot_means_the_logo_check_is_skipped(self, dashboard):
        body = (await dashboard.post("/api/v1/dashboard/analyze", json={"url": "https://example.org/", "page_text": "hello"})).json()
        assert body["visual"] is None
