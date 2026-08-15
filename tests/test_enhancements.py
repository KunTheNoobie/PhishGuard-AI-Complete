"""
PhishGuard-AI — Enhancements Unit & Integration Tests.
======================================================

Tests for:
1. Semantic Result Cache (DOM hash, TTL expiration, eviction).
2. Dynamic Mule Registry CRUD Endpoints (POST / DELETE).
3. Telemetry CSV Export Endpoint.
"""

from __future__ import annotations

import time
import pytest
from httpx import AsyncClient

from services.cache_service import SemanticResultCache


# ==============================================================================
# 1. Semantic Result Cache Tests
# ==============================================================================

class TestSemanticResultCache:

    def test_cache_set_and_get(self) -> None:
        cache = SemanticResultCache(ttl_seconds=60)
        key = cache.hash_key("URL: https://scam-site.test | login to your bank")
        payload = {"label": "PHISHING", "confidence": 0.98, "is_malicious": True}

        assert cache.get(key) is None
        cache.set(key, payload)
        cached = cache.get(key)
        assert cached is not None
        assert cached["label"] == "PHISHING"
        assert cached["confidence"] == 0.98

    def test_cache_ttl_expiration(self) -> None:
        cache = SemanticResultCache(ttl_seconds=1)
        key = cache.hash_key("test payload")
        cache.set(key, {"label": "LEGITIMATE", "confidence": 0.95, "is_malicious": False})

        assert cache.get(key) is not None
        time.sleep(1.1)
        assert cache.get(key) is None

    def test_cache_clear(self) -> None:
        cache = SemanticResultCache(ttl_seconds=60)
        key = cache.hash_key("test")
        cache.set(key, {"label": "SAFE"})
        cache.clear()
        assert cache.get(key) is None


# ==============================================================================
# 2. Dashboard Mule Registry & Export Integration Tests
# ==============================================================================

class TestDashboardEnhancements:

    @pytest.mark.asyncio
    async def test_add_and_delete_mule_account(self, test_client: AsyncClient) -> None:
        # 1. Add Mule Account
        add_resp = await test_client.post(
            "/api/v1/dashboard/mule-registry",
            json={
                "account_number": "998877665544",
                "bank_name": "Maybank",
                "platform_flagged": "Telegram Test",
                "report_count": 3,
            },
        )
        assert add_resp.status_code == 200
        data = add_resp.json()
        assert data["success"] is True
        record = data["record"]
        assert record["account_number"] == "998877665544"
        assert record["bank_name"] == "Maybank"
        mule_id = record["id"]

        # 2. Verify account is in registry
        list_resp = await test_client.get("/api/v1/dashboard/mule-registry")
        assert list_resp.status_code == 200
        accounts = list_resp.json()["accounts"]
        assert any(a["account_number"] == "998877665544" for a in accounts)

        # 3. Delete Mule Account
        del_resp = await test_client.delete(f"/api/v1/dashboard/mule-registry/{mule_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["success"] is True

        # 4. Delete non-existent returns 404
        del_404 = await test_client.delete("/api/v1/dashboard/mule-registry/999999")
        assert del_404.status_code == 404

    @pytest.mark.asyncio
    async def test_telemetry_csv_export(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/telemetry/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "Log ID,Malicious URL,BERT Score,Timestamp" in resp.text

    @pytest.mark.asyncio
    async def test_dashboard_distributions(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/distributions")
        assert resp.status_code == 200
        data = resp.json()
        assert "banks" in data
        assert "platforms" in data
        assert "timeline" in data

    @pytest.mark.asyncio
    async def test_duitnow_scanner_integration(self, test_client: AsyncClient) -> None:
        from services.mule_scanner import MuleScanner
        import aiosqlite
        from database.init_db import initialize_database

        scanner = MuleScanner()
        db = await initialize_database()
        try:
            # Test mobile DuitNow format
            result = await scanner.scan_and_verify(
                "Please pay deposit to DuitNow 012-3456789 immediately.", db
            )
            assert "012-3456789" in result["accounts_extracted"] or "0123456789" in result["accounts_extracted"]
            assert result["mule_detected"] is True
            assert any("DuitNow" in acc["bank_name"] for acc in result["flagged_accounts"])
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_system_health(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/system-health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "cache" in data
        assert "models" in data

    @pytest.mark.asyncio
    async def test_quick_scan_threat(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/dashboard/quick-scan",
            json={"url": "http://scam-bank.test", "text_content": "Urgent pay to DuitNow 012-3456789"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "BLOCK_RENDER"
        assert data["mule_detected"] is True

    @pytest.mark.asyncio
    async def test_quick_scan_local_scam_page(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/dashboard/quick-scan",
            json={"url": "http://127.0.0.1:8000/dashboard/test_scam.html"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "BLOCK_RENDER"
        assert data["mule_detected"] is True
        assert any(acc["account_number"] == "112233445566" for acc in data["flagged_accounts"])

    @pytest.mark.asyncio
    async def test_forensic_incident_report(self, test_client: AsyncClient) -> None:
        # 1. Quick scan a threat to populate telemetry
        await test_client.post(
            "/api/v1/dashboard/quick-scan",
            json={"url": "http://scam-bank.test", "text_content": "Urgent pay to DuitNow 012-3456789"}
        )
        tel_resp = await test_client.get("/api/v1/dashboard/telemetry")
        assert tel_resp.status_code == 200
        entries = tel_resp.json()["entries"]
        assert len(entries) > 0
        first_id = entries[0]["log_id"]

        # 2. Fetch structured forensic report
        rep_resp = await test_client.get(f"/api/v1/dashboard/telemetry/{first_id}/report")
        assert rep_resp.status_code == 200
        rep_data = rep_resp.json()
        assert "incident_id" in rep_data
        assert "url_hash_sha256" in rep_data
        assert "targeted_institution" in rep_data
        assert "recommended_action" in rep_data


    @pytest.mark.asyncio
    async def test_qr_scanner_quishing_detection(self) -> None:
        from services.qr_scanner import extract_duitnow_qr_accounts, scan_and_verify_qr
        from database.init_db import initialize_database

        # Sample EMVCo QR with seeded Maybank mule account 112233445566
        sample_qr = "00020101021126330013my.com.paynet011211223344556652045311"
        extracted = extract_duitnow_qr_accounts(sample_qr)
        assert len(extracted) > 0
        assert any(e["account_number"] == "112233445566" for e in extracted)

        db = await initialize_database()
        try:
            scan_res = await scan_and_verify_qr(sample_qr, db)
            assert scan_res["qr_detected"] is True
            assert scan_res["quishing_threat"] is True
            assert len(scan_res["flagged_accounts"]) > 0
            assert any(f["account_number"] == "112233445566" for f in scan_res["flagged_accounts"])
        finally:
            await db.close()


    def test_domain_heuristic_analyzer(self) -> None:
        from services.heuristic_engine import analyze_url_heuristics

        # Test IP address
        res_ip = analyze_url_heuristics("http://192.168.1.100/login/maybank")
        assert res_ip["is_ip_address"] is True
        assert res_ip["heuristic_score"] >= 0.40

        # Test High-risk TLD
        res_tld = analyze_url_heuristics("http://maybank2u-update.top/auth")
        assert any(".top" in i for i in res_tld["indicators"])

        # Test Punycode
        res_puny = analyze_url_heuristics("http://xn--mybank2u-9ya.com")
        assert res_puny["is_punycode"] is True

    @pytest.mark.asyncio
    async def test_stix_21_cti_bundle_export(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/export/stix")
        assert resp.status_code == 200
        bundle = resp.json()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert "objects" in bundle
        assert any(o["type"] == "identity" for o in bundle["objects"])

    def test_brand_impersonation_profiler(self) -> None:
        from services.brand_profiler import profile_brand_impersonation

        # Test spoofed Maybank site
        res_spoof = profile_brand_impersonation(
            "http://maybank2u-verify.top/login", "Please login with your Maybank username."
        )
        assert res_spoof["is_impersonation"] is True
        assert res_spoof["target_brand"] == "Maybank"
        assert res_spoof["impersonation_index"] >= 0.90

        # Test authentic Maybank site
        res_auth = profile_brand_impersonation(
            "https://www.maybank2u.com.my/home/login", "Official Maybank Login"
        )
        assert res_auth["is_impersonation"] is False
        assert res_auth["is_official_domain"] is True
        assert res_auth["impersonation_index"] == 0.0

    @pytest.mark.asyncio
    async def test_webhook_notifier_dispatch(self) -> None:
        from services.webhook_notifier import dispatch_threat_webhook

        # When no webhook is configured, returns False cleanly without exception
        res = await dispatch_threat_webhook("test_threat", {"url": "http://scam.test", "score": 0.95})
        assert res is False

    @pytest.mark.asyncio
    async def test_domain_quarantine_and_whitelist(self, test_client: AsyncClient) -> None:
        # 1. Quarantine domain
        q_resp = await test_client.post(
            "/api/v1/dashboard/domains/quarantine",
            json={"domain": "scam-maybank-urgent.top", "reason": "Automated Testing Quarantine"}
        )
        assert q_resp.status_code == 200
        assert q_resp.json()["action"] == "QUARANTINED"

        # 2. Whitelist domain
        w_resp = await test_client.post(
            "/api/v1/dashboard/domains/whitelist",
            json={"domain": "partner-portal.com", "reason": "Verified Partner", "ttl_hours": 12}
        )
        assert w_resp.status_code == 200
        assert w_resp.json()["action"] == "WHITELISTED"

        # 3. Check Policy list
        pol_resp = await test_client.get("/api/v1/dashboard/domains/policy")
        assert pol_resp.status_code == 200
        pol = pol_resp.json()
        assert pol["quarantined_count"] >= 1
        assert any(d["domain"] == "scam-maybank-urgent.top" for d in pol["quarantined_domains"])
        assert pol["whitelisted_count"] >= 1
        assert any(d["domain"] == "partner-portal.com" for d in pol["whitelisted_domains"])

    @pytest.mark.asyncio
    async def test_takedown_notice_generator(self, test_client: AsyncClient) -> None:
        # Seed a threat telemetry entry first if needed
        await test_client.post(
            "/api/v1/dashboard/quick-scan",
            json={"url": "http://maybank2u-verify.top/login", "text_content": "login"}
        )
        # Fetch latest telemetry to get log_id
        t_resp = await test_client.get("/api/v1/dashboard/telemetry?limit=1")
        assert t_resp.status_code == 200
        entries = t_resp.json()["entries"]
        assert len(entries) > 0
        log_id = entries[0]["log_id"]

        # Generate takedown notice
        resp = await test_client.get(f"/api/v1/dashboard/telemetry/{log_id}/takedown-notice")
        assert resp.status_code == 200
        notice = resp.json()
        assert "incident_id" in notice
        assert "abuse_email" in notice
        assert "subject" in notice
        assert "body" in notice
        assert "URGENT ABUSE TAKEDOWN" in notice["subject"]

    @pytest.mark.asyncio
    async def test_bulk_mule_import_csv(self, test_client: AsyncClient) -> None:
        csv_payload = (
            "Account, Bank, Platform, Reports\n"
            "991188223344, Maybank, WhatsApp, 5\n"
            "772233445566, CIMB Bank, Telegram, 12\n"
            "334455667788, Public Bank, Facebook, 2\n"
        )
        resp = await test_client.post(
            "/api/v1/dashboard/mule-registry/bulk",
            json={"raw_csv": csv_payload}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["imported_count"] == 3

    @pytest.mark.asyncio
    async def test_distributions_includes_infrastructure(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/distributions")
        assert resp.status_code == 200
        data = resp.json()
        assert "infrastructure" in data
        assert len(data["infrastructure"]) > 0
        assert any("Cloudflare" in item["provider"] or "Namecheap" in item["provider"] for item in data["infrastructure"])

    @pytest.mark.asyncio
    async def test_geo_threats_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/geo-threats")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert len(data["nodes"]) >= 4
        assert any(n["city"] == "Kuala Lumpur" for n in data["nodes"])

    @pytest.mark.asyncio
    async def test_webhook_test_ping_and_save(self, test_client: AsyncClient) -> None:
        # 1. Test ping on empty URL returns error
        p_resp = await test_client.post(
            "/api/v1/dashboard/webhooks/test-ping",
            json={"channel": "discord", "target_url": ""}
        )
        assert p_resp.status_code == 200
        assert p_resp.json()["success"] is False

        # 2. Save settings
        s_resp = await test_client.post(
            "/api/v1/dashboard/webhooks/save",
            json={"discord_webhook": "https://discord.com/api/webhooks/123/abc", "enabled": True}
        )
        assert s_resp.status_code == 200
        assert s_resp.json()["success"] is True

        # 3. Check status
        st_resp = await test_client.get("/api/v1/dashboard/webhooks/status")
        assert st_resp.status_code == 200
        assert st_resp.json()["discord_configured"] is True

    @pytest.mark.asyncio
    async def test_executive_ciso_report_generator(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/export/executive-report")
        assert resp.status_code == 200
        data = resp.json()
        assert "report_id" in data
        assert "executive_summary" in data
        assert "mean_time_to_detect_seconds" in data["executive_summary"]
        assert len(data["strategic_recommendations"]) > 0

    def test_xai_token_attribution_service(self) -> None:
        from services.xai_engine import explain_text_threat
        res = explain_text_threat("http://maybank2u-verify-tac.top/login", base_score=0.92)
        assert "tokens" in res
        assert len(res["tokens"]) > 0
        assert any(t["token"].lower() == "tac" for t in res["tokens"])
        assert any(t["category"] == "credential" for t in res["tokens"])
        assert "top_drivers" in res
        assert res["base_score"] == 0.92

    @pytest.mark.asyncio
    async def test_xai_endpoints(self, test_client: AsyncClient) -> None:
        # Test explain endpoint
        e_resp = await test_client.post(
            "/api/v1/dashboard/telemetry/explain",
            json={"text_or_url": "URGENT: Your CIMB account is frozen. Enter TAC.", "base_score": 0.88}
        )
        assert e_resp.status_code == 200
        e_data = e_resp.json()
        assert len(e_data["tokens"]) > 0
        assert any(t["category"] == "urgency" for t in e_data["tokens"])

        # Test telemetry XAI for log_id 1
        t_resp = await test_client.get("/api/v1/dashboard/telemetry/1/xai")
        assert t_resp.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_siem_cef_syslog_export_endpoints(self, test_client: AsyncClient) -> None:
        from database.repository import log_threat_telemetry
        db = test_client._transport.app.state.db
        await log_threat_telemetry("http://maybank2u-verify.top/auth", 0.95, db)

        # CEF
        cef_resp = await test_client.get("/api/v1/dashboard/export/cef")
        assert cef_resp.status_code == 200
        assert "CEF:0|PhishGuard-AI" in cef_resp.text

        # Syslog
        sys_resp = await test_client.get("/api/v1/dashboard/export/syslog")
        assert sys_resp.status_code == 200
        assert "phishguard-soc" in sys_resp.text

    @pytest.mark.asyncio
    async def test_sinkhole_rules_export(self, test_client: AsyncClient) -> None:
        for fmt in ["pihole", "hosts", "bind", "suricata"]:
            resp = await test_client.get(f"/api/v1/dashboard/export/sinkhole-rules?format={fmt}")
            assert resp.status_code == 200
            assert len(resp.text) > 0

    @pytest.mark.asyncio
    async def test_brand_campaign_matrix_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/brand-campaign-matrix")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tracked_institutions"] == 10
        assert len(data["brands"]) == 10
        assert any(b["brand"] == "Maybank" for b in data["brands"])
        assert any(b["brand"] == "Touch 'n Go eWallet" for b in data["brands"])

    @pytest.mark.asyncio
    async def test_ssl_intel_analyzer_and_endpoint(self, test_client: AsyncClient) -> None:
        from services.ssl_analyzer import analyze_target_ssl
        res = analyze_target_ssl("http://maybank-fake.top/login")
        assert res["protocol"] == "HTTP (Insecure)"
        assert res["spoof_risk_score"] > 80

        ep_resp = await test_client.post(
            "/api/v1/dashboard/ssl-intel",
            json={"url": "https://maybank2u-update.xyz"}
        )
        assert ep_resp.status_code == 200
        data = ep_resp.json()
        assert "certificate_issuer" in data
        assert "trust_tier" in data

    @pytest.mark.asyncio
    async def test_playbook_engine_execution_and_api(self, test_client: AsyncClient) -> None:
        from services.playbook_engine import execute_playbook_action, AVAILABLE_PLAYBOOKS
        assert len(AVAILABLE_PLAYBOOKS) >= 3

        # Test list endpoint
        l_resp = await test_client.get("/api/v1/dashboard/playbooks")
        assert l_resp.status_code == 200
        assert len(l_resp.json()["playbooks"]) >= 3

        # Test manual run endpoint
        r_resp = await test_client.post(
            "/api/v1/dashboard/playbooks/run",
            json={
                "playbook_id": "PLAYBOOK-CRITICAL-INTERCEPT",
                "target_url": "https://cimbclicks-auth.top/login",
                "target_bank": "CIMB Bank",
                "confidence": 0.98
            }
        )
        assert r_resp.status_code == 200
        r_data = r_resp.json()
        assert r_data["status"] == "SUCCESS"
        assert len(r_data["actions_executed"]) > 0

        # Test history endpoint
        h_resp = await test_client.get("/api/v1/dashboard/playbooks/history")
        assert h_resp.status_code == 200
        assert h_resp.json()["total_executions"] > 0

    def test_typosquat_homoglyph_generator(self) -> None:
        from services.typosquat_engine import generate_typosquats_for_domain, get_complete_typosquat_radar
        res = generate_typosquats_for_domain("maybank2u.com.my", limit=10)
        assert len(res) > 0
        assert any("Homoglyph" in v["technique"] or "Hyphenated" in v["technique"] for v in res)

        radar = get_complete_typosquat_radar()
        assert radar["total_tracked_brands"] == 10
        assert radar["total_pre_emptive_variants"] > 30

    @pytest.mark.asyncio
    async def test_typosquat_radar_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.get("/api/v1/dashboard/typosquat-radar")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ACTIVE_RADAR"
        assert len(data["institutions"]) == 10

    def test_multi_vector_risk_scorer(self) -> None:
        from services.multi_vector_scorer import compute_multi_vector_risk
        res = compute_multi_vector_risk(
            url="http://maybank2u-tac-verify.top/auth",
            text_content="URGENT TAC update needed for Maybank account.",
            bert_score=0.95,
            mule_detected=True,
            mule_count=2
        )
        assert res["composite_score"] >= 75.0
        assert res["verdict"] in ["CRITICAL_THREAT", "SUSPICIOUS_PHISH"]
        assert "vectors" in res
        assert res["vectors"]["neural_nlp_score"] > 0
        assert res["vectors"]["mule_syndicate_score"] > 0

    @pytest.mark.asyncio
    async def test_multi_vector_endpoint(self, test_client: AsyncClient) -> None:
        resp = await test_client.post(
            "/api/v1/dashboard/multi-vector-score",
            json={
                "url": "http://cimbclicks-secure.xyz/login",
                "bert_score": 0.88,
                "mule_detected": False
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "composite_score" in data
        assert "vectors" in data

    @pytest.mark.asyncio
    async def test_threat_graph_and_speed_endpoints(self, test_client: AsyncClient) -> None:
        from database.repository import log_threat_telemetry
        db = test_client._transport.app.state.db
        log_id = await log_threat_telemetry("http://pbebank-update.top/auth", 0.94, db)

        # Graph endpoint
        g_resp = await test_client.get(f"/api/v1/dashboard/threat-graph/{log_id}")
        assert g_resp.status_code == 200
        g_data = g_resp.json()
        assert "nodes" in g_data
        assert "links" in g_data
        assert any(n["id"] == "domain" for n in g_data["nodes"])

        # Simulator Speed endpoint
        s_resp = await test_client.post(
            "/api/v1/dashboard/simulator/speed",
            json={"speed": 2.5}
        )
        assert s_resp.status_code == 200
        assert s_resp.json()["simulator_speed"] == 2.5

    # ── Phase 10 Tests ──
    @pytest.mark.asyncio
    async def test_visual_sandbox_service_and_endpoint(self, test_client: AsyncClient) -> None:
        from services.visual_sandbox import generate_visual_sandbox_snapshot
        snap = generate_visual_sandbox_snapshot("http://maybank2u-secure-login.top/auth", log_id=101, bert_score=0.96)
        assert snap["target_brand"] == "Maybank"
        assert len(snap["extracted_fields"]) >= 4
        assert snap["yolo_detection"]["detected"] is True
        assert "<iframe" in snap["safe_html_preview"] or "<html" in snap["safe_html_preview"]

        # API inspection endpoint
        resp = await test_client.post(
            "/api/v1/dashboard/sandbox-inspect",
            json={"url": "http://cimb-clicks-verify.net/tac", "bert_score": 0.92}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_brand"] == "CIMB Bank"
        assert len(data["security_headers"]) >= 4

    @pytest.mark.asyncio
    async def test_nsrc_bridge_and_freeze_endpoint(self, test_client: AsyncClient) -> None:
        # NSRC summary
        s_resp = await test_client.get("/api/v1/dashboard/nsrc/summary")
        assert s_resp.status_code == 200
        s_data = s_resp.json()
        assert "total_losses_prevented_myr" in s_data
        assert "RM" in s_data["total_losses_prevented_formatted"]
        assert len(s_data["recent_intercept_cases"]) > 0

        # NSRC multi-bank freeze escalation
        f_resp = await test_client.post(
            "/api/v1/dashboard/nsrc/escalate-freeze",
            json={"account_number": "998877665544", "bank_name": "Public Bank"}
        )
        assert f_resp.status_code == 200
        f_data = f_resp.json()
        assert f_data["status"] == "FREEZE_DIRECTIVE_BROADCASTED"
        assert "NSRC-2026-EMERGENCY" in f_data["case_reference"]

    @pytest.mark.asyncio
    async def test_quishing_scanner_and_endpoint(self, test_client: AsyncClient) -> None:
        from services.quishing_scanner import scan_quishing_payload
        res = scan_quishing_payload("duitnow://pay?acc=112233445566&bank=Maybank&url=http://maybank-verify.top")
        assert res["quishing_score"] >= 0.70
        assert res["is_duitnow_scheme"] is True
        assert len(res["extracted_mule_accounts"]) > 0

        # API endpoint
        resp = await test_client.post(
            "/api/v1/dashboard/quishing/scan",
            json={"payload": "https://pdrm-saman-bayar.xyz/dbkl?acc=564738291012"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["quishing_score"] > 0.5
        assert len(data["risk_factors"]) > 0

    @pytest.mark.asyncio
    async def test_taxii2_server_endpoints(self, test_client: AsyncClient) -> None:
        # Discovery root
        root_resp = await test_client.get("/api/v1/dashboard/taxii2/root")
        assert root_resp.status_code == 200
        assert "PhishGuard-AI" in root_resp.json()["title"]

        # Collections
        col_resp = await test_client.get("/api/v1/dashboard/taxii2/collections")
        assert col_resp.status_code == 200
        assert len(col_resp.json()["collections"]) == 1

        # Threat objects STIX bundle
        obj_resp = await test_client.get("/api/v1/dashboard/taxii2/collections/phishguard-threats/objects")
        assert obj_resp.status_code == 200
        obj_data = obj_resp.json()
        assert "objects" in obj_data
        assert obj_data["spec_version"] == "2.1"

    # ── Finalization Suite Tests ──
    @pytest.mark.asyncio
    async def test_batch_inspector_service_and_endpoint(self, test_client: AsyncClient) -> None:
        from services.batch_inspector import inspect_batch_urls, parse_raw_email

        # 1. Multi-URL batch test
        urls = [
            "http://maybank2u-auth.top/login",
            "https://cimbclicks-secure.xyz",
            "http://pbebank-tac-verify.net",
        ]
        b_res = inspect_batch_urls(urls)
        assert b_res["total_analyzed"] == 3
        assert b_res["high_risk_count"] >= 1
        assert "execution_time_ms" in b_res

        # 2. Raw Email / EML test
        raw_eml = """From: alerts@maybank2u-security.top
Subject: URGENT: TAC Authentication Required
Authentication-Results: spf=fail dkim=fail

Please confirm your account balance at http://maybank2u-tac.top and send RM 500 to Maybank 112233445566.
"""
        e_res = parse_raw_email(raw_eml)
        assert e_res["spoof_risk"] is True
        assert len(e_res["extracted_urls"]) == 1
        assert len(e_res["mule_matches"]) > 0

        # 3. API endpoint tests
        resp_urls = await test_client.post(
            "/api/v1/dashboard/batch-inspect",
            json={"mode": "urls", "urls": urls}
        )
        assert resp_urls.status_code == 200
        assert resp_urls.json()["total_analyzed"] == 3

        resp_eml = await test_client.post(
            "/api/v1/dashboard/batch-inspect",
            json={"mode": "email", "raw_text": raw_eml}
        )
        assert resp_eml.status_code == 200
        assert resp_eml.json()["spoof_risk"] is True

    @pytest.mark.asyncio
    async def test_threat_feeds_sync_and_check_endpoint(self, test_client: AsyncClient) -> None:
        # Status endpoint
        status_resp = await test_client.get("/api/v1/dashboard/threat-feeds/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["total_active_indicators"] >= 3

        # Sync endpoint
        sync_resp = await test_client.post("/api/v1/dashboard/threat-feeds/sync")
        assert sync_resp.status_code == 200
        assert sync_resp.json()["status"] == "SYNC_SUCCESSFUL"

        # Check endpoint
        check_resp = await test_client.post(
            "/api/v1/dashboard/threat-feeds/check",
            json={"url": "http://maybank2u-tac-auth.top/login"}
        )
        assert check_resp.status_code == 200
        assert check_resp.json()["is_blacklisted"] is True
        assert "URLhaus" in check_resp.json()["feed_source"]

    @pytest.mark.asyncio
    async def test_db_maintenance_stats_optimize_prune_backup(self, test_client: AsyncClient) -> None:
        # Stats endpoint
        stats_resp = await test_client.get("/api/v1/dashboard/db/stats")
        assert stats_resp.status_code == 200
        s_data = stats_resp.json()
        assert s_data["status"] == "HEALTHY"
        assert "table_row_counts" in s_data

        # Optimize endpoint
        opt_resp = await test_client.post("/api/v1/dashboard/db/optimize")
        assert opt_resp.status_code == 200
        assert opt_resp.json()["status"] == "OPTIMIZATION_COMPLETE"

        # Prune endpoint
        prune_resp = await test_client.post(
            "/api/v1/dashboard/db/prune",
            json={"keep_last_n": 500}
        )
        assert prune_resp.status_code == 200
        assert "records_retained" in prune_resp.json()

        # Hot backup endpoint
        backup_resp = await test_client.get("/api/v1/dashboard/db/backup")
        assert backup_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_diagnostics_benchmark_endpoint(self, test_client: AsyncClient) -> None:
        b_resp = await test_client.get("/api/v1/dashboard/diagnostics/benchmark")
        assert b_resp.status_code == 200
        b_data = b_resp.json()
        assert b_data["status"] == "HEALTHY"
        assert b_data["nlp_inference_latency_ms"] >= 0
        assert b_data["sqlite_query_latency_ms"] >= 0
        assert "system_telemetry" in b_data

    @pytest.mark.asyncio
    async def test_mitre_attack_matrix_service_and_endpoint(self, test_client: AsyncClient) -> None:
        from services.mitre_mapper import generate_mitre_attack_matrix
        matrix = generate_mitre_attack_matrix(141)
        assert "MITRE ATT&CK" in matrix["framework"]
        assert matrix["total_tactics"] >= 4
        assert matrix["total_techniques_covered"] >= 5

        resp = await test_client.get("/api/v1/dashboard/mitre-matrix")
        assert resp.status_code == 200
        data = resp.json()
        assert "tactics" in data
        assert len(data["tactics"]) >= 4

    @pytest.mark.asyncio
    async def test_yara_and_suricata_rules_generation_and_endpoints(self, test_client: AsyncClient) -> None:
        from services.yara_generator import generate_phishguard_yara_rules, generate_suricata_snort_rules

        yara_str = generate_phishguard_yara_rules()
        assert "rule PhishGuard_Malaysian_Banking_PhishKit" in yara_str
        assert "$bank1" in yara_str

        suricata_str = generate_suricata_snort_rules()
        assert "alert http" in suricata_str
        assert "PHISHGUARD MALICIOUS HOST" in suricata_str

        # Endpoints
        yara_resp = await test_client.get("/api/v1/dashboard/yara-rules")
        assert yara_resp.status_code == 200
        assert "rules" in yara_resp.json()

        suricata_resp = await test_client.get("/api/v1/dashboard/suricata-rules")
        assert suricata_resp.status_code == 200
        assert "rules" in suricata_resp.json()

    @pytest.mark.asyncio
    async def test_red_team_simulator_service_and_endpoint(self, test_client: AsyncClient) -> None:
        from services.red_team_simulator import get_available_campaign_templates, launch_simulated_red_team_campaign

        templates = get_available_campaign_templates()
        assert len(templates) >= 5

        sim_res = launch_simulated_red_team_campaign("SAT-MY-001", target_count=50)
        assert sim_res["recipients_targeted"] == 50
        assert sim_res["telemetry"]["blocked_by_phishguard_extension"] > 0
        assert sim_res["verdict"] == "CAMPAIGN_EXECUTED_SUCCESSFULLY"

        # Endpoints
        tpl_resp = await test_client.get("/api/v1/dashboard/red-team/campaigns")
        assert tpl_resp.status_code == 200
        assert len(tpl_resp.json()["templates"]) >= 5

        launch_resp = await test_client.post(
            "/api/v1/dashboard/red-team/launch",
            json={"template_id": "SAT-MY-002", "target_count": 80}
        )
        assert launch_resp.status_code == 200
        assert launch_resp.json()["recipients_targeted"] == 80



