"""URL canonicalisation, structural heuristics and brand-impersonation profiling."""

from __future__ import annotations

import pytest

from core.brands import BRANDS, brand_for_domain
from core.config import ALL_TRUSTED_DOMAINS
from services.brand_profiler import profile_brand_impersonation
from services.heuristic_engine import analyze_url_heuristics
from services.url_canonicalizer import canonicalize


class TestCanonicalize:
    def test_userinfo_reveals_real_host(self):
        c = canonicalize("https://maybank2u.com.my@evil-login.top/login?x=1#frag")
        assert c.hostname == "evil-login.top"
        assert c.userinfo == "maybank2u.com.my"
        assert c.display_url == "https://evil-login.top/login"
        assert c.fetch_url == "https://evil-login.top/login?x=1"
        assert "maybank2u.com.my" not in c.fetch_url

    @pytest.mark.parametrize("host", ["3232235777", "0xC0A80101", "0300.0250.01.01"])
    def test_numeric_ip_forms(self, host):
        c = canonicalize(f"http://{host}/")
        assert c.is_ip and c.hostname == "192.168.1.1"

    def test_cyrillic_homoglyph_skeleton(self):
        c = canonicalize("https://mаybank2u.com/")  # Cyrillic 'а'
        assert c.is_idn and c.hostname.startswith("xn--")
        assert c.skeleton_hostname == "maybank2u.com"
        assert c.mixed_script

    def test_backslash_and_case_and_port(self):
        c = canonicalize("HTTPS://WWW.Example.COM.:443\\path")
        assert c.hostname == "www.example.com" and c.port is None and c.path == "/path"

    def test_missing_scheme_defaults_to_http(self):
        assert canonicalize("example.com").scheme == "http"

    def test_bert_input_keeps_url_as_written(self):
        assert canonicalize("https://www.maybank2u.com.my/home").model_url == "maybank2u.com.my/home"


class TestHeuristics:
    def test_clean_https_url(self):
        assert not analyze_url_heuristics("https://example.com/")["is_suspicious"]

    @pytest.mark.parametrize("url, needle", [
        ("http://203.0.113.9/login", "raw IP"),
        ("https://bank.com@evil.top/", "hides its real destination"),
        ("https://secure-update.xyz/", ".xyz"),
    ])
    def test_strong_indicators(self, url, needle):
        h = analyze_url_heuristics(url)
        assert h["is_strong"] and any(needle in i for i in h["indicators"])

    def test_free_hosting_is_weak(self):
        h = analyze_url_heuristics("https://maybank2u-login.web.app/")
        assert h["free_hosting"] and not h["is_strong"]

    def test_deceptive_subdomain_and_port(self):
        h = analyze_url_heuristics("https://login.verify.secure.example.com:4444/")
        text = " ".join(h["indicators"])
        assert "nesting" in text and "Deceptive keyword" in text and "4444" in text


class TestBrandRegistry:
    REQUIRED = ["Maybank", "CIMB Bank", "Public Bank", "RHB Bank", "Hong Leong Bank", "AmBank", "Bank Islam",
                "Bank Rakyat", "BSN", "Alliance Bank", "Affin Bank", "UOB Malaysia", "OCBC Malaysia",
                "HSBC Malaysia", "Standard Chartered Malaysia", "Citibank Malaysia", "Agrobank", "Bank Muamalat",
                "MBSB Bank", "GXBank", "AEON Bank", "Boost Bank", "KAF Digital Bank", "Touch 'n Go eWallet",
                "DuitNow / PayNet", "Chase", "Bank of America", "Wells Fargo", "Barclays", "DBS / POSB", "PayPal"]

    def test_every_required_brand_has_official_domains(self):
        for name in self.REQUIRED:
            assert BRANDS[name]["domains"], name

    def test_official_domains_are_trusted(self):
        for host in ("www.maybank2u.com.my", "www.cimbclicks.com.my", "www.pbebank.com", "www.gxbank.my",
                     "www.aeonbank.com.my", "www.i-muamalat.com.my", "www.dbs.com.sg", "www.paypal.com"):
            assert any(host == d or host.endswith("." + d) for d in ALL_TRUSTED_DOMAINS), host

    def test_no_public_hosting_suffix_is_trusted(self):
        for suffix in ("web.app", "vercel.app", "netlify.app", "github.io", "hf.space", "appspot.com"):
            assert suffix not in ALL_TRUSTED_DOMAINS

    def test_brand_for_domain(self):
        assert brand_for_domain("s.hongleongconnect.my") == "Hong Leong Bank"
        assert brand_for_domain("evil.com") is None


class TestBrandProfiler:
    def test_official_domain(self):
        r = profile_brand_impersonation("https://www.maybank2u.com.my/")
        assert r["is_official_domain"] and r["target_brand"] == "Maybank"

    @pytest.mark.parametrize("url, brand", [
        ("http://maybank2u-secure-login.top/", "Maybank"),
        ("https://cimb-verify.com/", "CIMB Bank"),
        ("https://gxbank-rewards.click/", "GXBank"),
        ("https://paypal-billing-help.com/", "PayPal"),
        ("https://poslaju-redelivery.top/", "Pos Malaysia"),
    ])
    def test_brand_in_hostname(self, url, brand):
        r = profile_brand_impersonation(url)
        assert r["brand_in_hostname"] and r["target_brand"] == brand

    @pytest.mark.parametrize("url", ["https://rnaybank2u.com/", "https://maybznk2u.com.my/", "https://mаybank2u.com/"])
    def test_lookalikes(self, url):
        r = profile_brand_impersonation(url)
        assert r["lookalike_domain"] and r["target_brand"] == "Maybank"

    def test_text_mention_is_weak(self):
        r = profile_brand_impersonation("https://news.example.org/", "Maybank announced new rates")
        assert r["brand_mentioned"] and not r["is_impersonation"]

    def test_unrelated_words_do_not_match(self):
        r = profile_brand_impersonation("https://purchase-orders.example.com/")  # contains "chase"
        assert not r["is_impersonation"]
