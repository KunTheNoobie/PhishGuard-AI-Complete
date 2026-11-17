"""Every verdict rule, the HTTP/HTTPS policy and the explanations."""

from __future__ import annotations

from typing import Any

import pytest

from services.brand_profiler import profile_brand_impersonation
from services.heuristic_engine import analyze_url_heuristics
from services.url_canonicalizer import canonicalize
from services.verdict_engine import decide, detect_sensitive_fields, has_credential_text, scam_phrases

LOGIN_FORM = "<form><input name='user'><input type='password' name='pass'></form>"
CARD_FORM = "<form><input name='cardnumber'><input name='cvv'></form>"


def run(url: str, html: str = "", *, p_bert: float = 0.05, trusted: bool = False,
        flagged: list[dict[str, Any]] | None = None, visual: dict | None = None, tls_error: str | None = None):
    c = canonicalize(url)
    from services.sanitizer import sanitize_dom
    text = sanitize_dom(html) if html else ""
    return decide(
        canon=c, is_trusted=trusted,
        bert_result={"label": "PHISHING" if p_bert >= 0.5 else "LEGITIMATE", "phishing_probability": p_bert,
                     "confidence": max(p_bert, 1 - p_bert), "is_malicious": p_bert >= 0.75},
        mule_result={"flagged_accounts": flagged or [], "accounts_extracted": [f["account_number"] for f in flagged or []]},
        brand_result=profile_brand_impersonation(c, text),
        heuristic_result=analyze_url_heuristics(c),
        sanitized_text=text, raw_content=html, visual_result=visual, tls_error=tls_error,
    )


class TestTransportPolicy:
    def test_https_clean_is_safe(self):
        v = run("https://example.com/", "<h1>Example Domain</h1>")
        assert v.verdict == "SAFE" and v.risk_level == "safe"

    def test_http_without_form_is_warning(self):
        v = run("http://neverssl.com/", "<h1>NeverSSL</h1>")
        assert (v.verdict, v.rule) == ("WARNING", "H2_INSECURE_HTTP")

    @pytest.mark.parametrize("form", [LOGIN_FORM, CARD_FORM, "<input name='otp'>"])
    def test_http_with_sensitive_form_is_blocked(self, form):
        v = run("http://testphp.vulnweb.com/login.php", form)
        assert (v.verdict, v.rule) == ("BLOCK_RENDER", "H1_HTTP_SENSITIVE_FORM")

    def test_http_is_never_safe_even_when_trusted(self):
        assert run("http://www.maybank2u.com.my/", "<p>hi</p>", trusted=True).verdict == "WARNING"
        assert run("http://www.maybank2u.com.my/", LOGIN_FORM, trusted=True).verdict == "BLOCK_RENDER"

    def test_trusted_https_is_safe_with_named_owner(self):
        v = run("https://www.maybank2u.com.my/", LOGIN_FORM, trusted=True)
        assert v.verdict == "SAFE" and v.headline == "Official Maybank website"

    def test_certificate_error_is_warning(self):
        v = run("https://expired.badssl.com/", "<p>x</p>", tls_error="certificate has expired")
        assert (v.verdict, v.rule) == ("WARNING", "W1_TLS_CERTIFICATE")


class TestBlockRules:
    def test_r1_mule_registry(self):
        v = run("https://shop.example/", "<p>pay</p>", flagged=[{"account_number": "112233445566", "bank_name": "Maybank"}])
        assert v.rule == "R1_MULE_REGISTRY" and "112233445566" in v.explanation

    def test_r7_userinfo_spoof_needs_no_form(self):
        v = run("https://maybank2u.com.my@evil-login.top/", "<p>Welcome</p>")
        assert v.rule == "R7_USERINFO_SPOOF" and "evil-login.top" in v.explanation

    def test_plain_user_name_is_not_spoofing(self):
        assert run("https://admin@example.com/", "<p>x</p>").rule != "R7_USERINFO_SPOOF"

    def test_r2_brand_in_hostname(self):
        v = run("https://maybank2u-secure-login.top/", LOGIN_FORM)
        assert v.rule == "R2_BRAND_IN_HOSTNAME" and v.headline == "Fake Maybank website"

    def test_r3_lookalike(self):
        assert run("https://rnaybank2u.com/", LOGIN_FORM).rule == "R3_LOOKALIKE_DOMAIN"

    def test_r8_visual_logo_mismatch(self):
        visual = {"risk_level": "dangerous", "detected_logos": [{"brand": "Maybank", "confidence": 0.93}]}
        v = run("https://rewards-portal.example/", LOGIN_FORM, visual=visual)
        assert v.rule == "R8_VISUAL_BRAND_MISMATCH"

    def test_r4_brand_clone(self):
        assert run("https://secure-portal.example/", "<h1>Maybank2u</h1>" + LOGIN_FORM, p_bert=0.9).rule == "R4_BRAND_CLONE"

    def test_r5_coercive_request(self):
        html = "<p>Account suspended. Verify immediately.</p>" + LOGIN_FORM
        assert run("https://account-help.example/", html, p_bert=0.9).rule == "R5_COERCIVE_CREDENTIAL_REQUEST"

    def test_r6_evasive_infrastructure(self):
        assert run("https://203.0.113.5/", "<p>log in</p>", p_bert=0.95).rule == "R6_EVASIVE_INFRASTRUCTURE"

    def test_r9_free_hosting_form_with_bert(self):
        assert run("https://pay-portal.web.app/", LOGIN_FORM, p_bert=0.9).rule == "R9_FREE_HOSTING_CREDENTIAL_FORM"


class TestWarningsAndSafety:
    def test_w2_uncorroborated_impersonation(self):
        v = run("https://maybank-fans.example/", "<p>A fan page</p>")
        assert (v.verdict, v.rule) == ("WARNING", "W2_UNCORROBORATED_IMPERSONATION")

    def test_w3_form_on_free_hosting(self):
        v = run("https://testsafebrowsing.appspot.com/s/phishing.html", LOGIN_FORM)
        assert (v.verdict, v.rule) == ("WARNING", "W3_FREE_HOSTING_FORM")

    def test_bert_alone_never_blocks(self):
        v = run("https://news.example.com/article", "<p>Maybank reports earnings</p>", p_bert=0.99)
        assert v.verdict == "SAFE" and 0 < v.risk_score < 0.5

    def test_reasons_are_ordered_and_explained(self):
        v = run("https://maybank2u-secure-login.top/", LOGIN_FORM, p_bert=0.99)
        severities = [r["severity"] for r in v.reasons]
        order = ["high", "medium", "low", "info", "ok"]
        assert severities == sorted(severities, key=order.index)
        assert v.explanation.startswith("PhishGuard blocked this page.")


class TestContentDetectors:
    def test_sensitive_fields(self):
        assert detect_sensitive_fields(LOGIN_FORM + CARD_FORM + "<input autocomplete='one-time-code'>") == [
            "password", "payment card", "OTP / TAC / PIN"]
        assert detect_sensitive_fields("<input name='shopping'>") == []

    def test_credential_text_needs_context_for_short_words(self):
        assert has_credential_text("Please enter your TAC code")
        assert not has_credential_text("Pin this recipe for later shopping")

    def test_scam_phrases_multilingual(self):
        assert scam_phrases("Akaun anda dibekukan. Tindakan segera diperlukan.") == ["tindakan segera", "akaun anda dibekukan"]
