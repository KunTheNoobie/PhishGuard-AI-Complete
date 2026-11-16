"""
PhishGuard-AI — Verdict Engine, Brand Profiler and Heuristic Unit Tests.
=========================================================================

Regression tests for the false-positive and scoring defects fixed in v3.2.0.
"""

from __future__ import annotations

import pytest

from services.brand_profiler import profile_brand_impersonation
from services.domain_utils import levenshtein, registrable_domain, strip_scheme, subdomain_labels
from services.heuristic_engine import analyze_url_heuristics
from services.multi_vector_scorer import compute_multi_vector_risk
from services.nlp_engine import build_model_input, predict_phishing_probability
from services.verdict_engine import decide, has_credential_form, has_credential_text, has_scam_language

SAFE_BERT = {"label": "LEGITIMATE", "confidence": 0.97, "is_malicious": False}
PHISH_BERT = {"label": "PHISHING", "confidence": 0.99, "is_malicious": True}
NO_MULE = {"mule_detected": False, "flagged_accounts": [], "accounts_extracted": []}
LOGIN_FORM = "<form><input type='text' name='user'><input type=\"password\" name='pw'></form>"


def _decide(url: str, text: str, html: str = "", bert=None, mule=None, trusted: bool = False):
    return decide(
        is_trusted=trusted,
        bert_result=bert or SAFE_BERT,
        mule_result=mule or NO_MULE,
        brand_result=profile_brand_impersonation(url, text),
        heuristic_result=analyze_url_heuristics(url),
        sanitized_text=text,
        raw_content=html or f"<p>{text}</p>",
    )


class TestCredentialTextMatching:

    @pytest.mark.parametrize("text", [
        "Great shopping deals this weekend",        # contains 'pin'
        "Contact our sales team for a quote",       # contains 'tac'
        "Pin this recipe for later",                # 'pin' as an ordinary word
        "The spinach tacos were photographed",      # 'pin' and 'tac' substrings
        "Hotpot and octopus menu",                  # contains 'otp'
    ])
    def test_benign_substrings_do_not_match(self, text: str) -> None:
        assert has_credential_text(text) is False

    @pytest.mark.parametrize("text", [
        "Enter your password to continue",
        "Sila masukkan kata laluan anda",
        "Key in your TAC code now",
        "Masukkan nombor TAC anda untuk pengesahan",
        "Confirm the OTP number sent to your phone",
        "Enter your 6-digit PIN",
        "请输入密码和验证码",
    ])
    def test_explicit_credential_requests_match(self, text: str) -> None:
        assert has_credential_text(text) is True

    def test_form_detection(self) -> None:
        assert has_credential_form(LOGIN_FORM) is True
        assert has_credential_form("<input type='text' name='otp'>") is True
        assert has_credential_form("<input autocomplete=\"cc-number\">") is True
        assert has_credential_form("<input type='text' name='search'>") is False
        assert has_credential_form("password") is False  # plain text is not a form

    def test_scam_lexicon(self) -> None:
        assert has_scam_language("Akaun anda dibekukan, sila buat pengesahan keselamatan") is True
        assert has_scam_language("Maybank revises fixed deposit rates") is False


class TestBrandProfilerTiers:

    def test_news_article_mention_is_not_impersonation(self) -> None:
        res = profile_brand_impersonation(
            "https://ringgitplus.com/en/blog/maybank-fd-rates.html",
            "Maybank has revised its fixed deposit rates. RHB and PayPal were also mentioned.",
        )
        assert res["is_impersonation"] is False
        assert res["brand_mentioned"] is True
        assert res["impersonation_index"] < 0.5

    def test_brand_in_foreign_hostname(self) -> None:
        res = profile_brand_impersonation("http://maybank2u-secure-login.top/login", "")
        assert res["is_impersonation"] is True and res["brand_in_hostname"] is True
        assert res["target_brand"] == "Maybank"

    @pytest.mark.parametrize("url", ["https://rnaybank2u.com/login", "http://maybznk2u.com.my/auth"])
    def test_lookalike_domains(self, url: str) -> None:
        res = profile_brand_impersonation(url, "")
        assert res["lookalike_domain"] is True and res["target_brand"] == "Maybank"

    @pytest.mark.parametrize("url", [
        "https://www.maybank2u.com.my/home/m2u/common/login.do",
        "https://ambank.amonline.com.my/web",
        "https://www.bankislam.biz/",
        "https://www.mybsn.com.my/mybsn/login/login.do",
    ])
    def test_official_domains_never_impersonation(self, url: str) -> None:
        res = profile_brand_impersonation(url, "Login with your password")
        assert res["is_official_domain"] is True and res["is_impersonation"] is False

    def test_short_brand_tokens_need_whole_token_match(self) -> None:
        # 'rhb' and 'hlb' must not match inside unrelated hostnames.
        assert profile_brand_impersonation("https://www.thrhbooks.com/", "")["is_impersonation"] is False
        assert profile_brand_impersonation("https://rhb-online-verify.net/", "")["brand_in_hostname"] is True


class TestHeuristics:

    def test_cctld_hosts_not_penalised_for_depth(self) -> None:
        res = analyze_url_heuristics("https://www.maybank2u.com.my/home")
        assert res["is_suspicious"] is False

    def test_deep_subdomain_chain_flagged(self) -> None:
        res = analyze_url_heuristics("http://login.maybank2u.com.my.session-verify.info/m2u")
        assert res["is_suspicious"] is True
        assert res["registrable_domain"] == "session-verify.info"

    @pytest.mark.parametrize("url", ["http://185.203.118.44/login.php", "https://xn--mybank2u-n4a.com/", "http://promo-claim.top/"])
    def test_strong_indicators(self, url: str) -> None:
        assert analyze_url_heuristics(url)["is_strong"] is True

    def test_domain_utils(self) -> None:
        assert registrable_domain("secure.kwsp.gov.my") == "kwsp.gov.my"
        assert subdomain_labels("a.b.example.co.uk") == ["a", "b"]
        assert strip_scheme("https://www.pbebank.com/x") == "pbebank.com/x"
        assert build_model_input("http://evil.top/a") == "evil.top/a"
        assert levenshtein("maybznk2u", "maybank2u") == 1
        assert levenshtein("completely", "different", 2) == 3


class TestCorroborationRules:

    def test_bert_alone_never_blocks(self) -> None:
        v = _decide("https://www.popular.com.my/eshop/account/login", "Member login. Email. Password.",
                    LOGIN_FORM, bert=PHISH_BERT)
        assert v.is_threat is False and 0 < v.risk_score < 0.5

    def test_brand_mention_plus_form_without_third_signal_is_safe(self) -> None:
        v = _decide("https://forum.lowyat.net/topic/1", "Cannot log in to Maybank MAE today", LOGIN_FORM)
        assert v.is_threat is False

    def test_mule_match_blocks_alone(self) -> None:
        mule = {"mule_detected": True, "flagged_accounts": [{"account_number": "112233445566", "bank_name": "Maybank"}]}
        v = _decide("http://murah-gadget-store.com/iphone", "Bank in to 112233445566", mule=mule)
        assert v.is_threat is True and v.rule == "R1_MULE_REGISTRY" and v.risk_score == 0.99

    def test_brand_hostname_with_credentials_blocks(self) -> None:
        v = _decide("http://maybank2u-secure-login.top/m2u", "Maybank2u login", LOGIN_FORM)
        assert v.rule == "R2_BRAND_IN_HOSTNAME"

    def test_parked_brand_hostname_without_corroboration_is_safe(self) -> None:
        v = _decide("https://maybankfoundation.org/", "Our community programmes and scholarships")
        assert v.is_threat is False

    def test_lookalike_with_credentials_blocks(self) -> None:
        v = _decide("https://rnaybank2u.com/home/login", "Welcome", LOGIN_FORM)
        assert v.rule == "R3_LOOKALIKE_DOMAIN"

    def test_benign_near_miss_domain_is_safe(self) -> None:
        v = _decide("https://paypay.ne.jp/", "Cashless payments for everyday shopping")
        assert v.is_threat is False

    def test_coercive_credential_request_blocks(self) -> None:
        v = _decide("http://refund-claims-my.com/tuntutan", "Sila kemaskini maklumat untuk elak akaun digantung",
                    LOGIN_FORM, bert=PHISH_BERT)
        assert v.rule == "R5_COERCIVE_CREDENTIAL_REQUEST"

    def test_evasive_infrastructure_blocks(self) -> None:
        v = _decide("http://185.203.118.44/portal/login.php", "Username. Password. Login.", LOGIN_FORM, bert=PHISH_BERT)
        assert v.rule == "R6_EVASIVE_INFRASTRUCTURE"

    def test_trusted_domain_is_never_blocked(self) -> None:
        v = _decide("https://www.maybank2u.com.my/login", "Enter your password and TAC", LOGIN_FORM,
                    bert=PHISH_BERT, trusted=True)
        assert v.is_threat is False and v.risk_score == 0.0


class TestScorers:

    def test_brand_vector_now_contributes_dynamically(self) -> None:
        spoof = compute_multi_vector_risk("http://maybank2u-tac-verify.top/auth", "Maybank TAC", bert_score=0.5)
        clean = compute_multi_vector_risk("http://example-bakery.com/menu", "Fresh bread daily", bert_score=0.5)
        assert spoof["vectors"]["brand_impersonation_score"] > 9.0
        assert clean["vectors"]["brand_impersonation_score"] == 0.0
        assert spoof["target_brand"] == "Maybank"

    def test_fallback_probability_uses_real_heuristic_score(self) -> None:
        risky, risky_label = predict_phishing_probability("http://185.203.118.44/maybank2u/login.php")
        benign, benign_label = predict_phishing_probability("https://www.utar.edu.my/admission.php")
        assert risky > benign
        assert benign_label == "LEGITIMATE"

    def test_fallback_probability_ignores_benign_substrings(self) -> None:
        prob, label = predict_phishing_probability("Great shopping deals, contact our team")
        assert label == "LEGITIMATE" and prob < 0.2

    def test_fallback_probability_flags_scam_text(self) -> None:
        prob, label = predict_phishing_probability("URGENT: akaun digantung. Enter your password to verify immediately")
        assert label == "PHISHING" and prob >= 0.6
