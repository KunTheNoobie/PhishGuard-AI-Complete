"""
PhishGuard-AI — DOM Sanitization Service (ETL Layer).
======================================================

Implements the **Extract-Transform-Load** cleansing stage that converts
raw browser DOM content into pure semantic text suitable for BERT
tokenization.  The sanitization pipeline:

    1. Strips ``<script>``, ``<style>``, ``<noscript>``, and ``<meta>``
       elements (including their children) to remove executable and
       presentational noise.
    2. Extracts visible text using BeautifulSoup's ``get_text()`` with a
       space separator to preserve word boundaries.
    3. Collapses excessive whitespace via a compiled regex.

Architecture Layer : Service / ETL
Thesis Reference   : §4.1 — Pre-Inference Data Sanitization Pipeline
"""

from __future__ import annotations

import re
from typing import Final

from bs4 import BeautifulSoup, FeatureNotFound

# Pre-compiled regex — collapses runs of whitespace (including newlines)
# into a single space.  Compiled once at module import time for O(1)
# reuse across requests.
_WHITESPACE_RE: Final[re.Pattern[str]] = re.compile(r"\s+")

# ── Select the best available HTML parser at import time ──
# ``lxml`` is the fastest C-backed parser but requires a compiled
# extension.  If unavailable (e.g., on minimal Docker images), we
# fall back to Python's built-in ``html.parser`` which is always present.
try:
    BeautifulSoup("", "lxml")
    _PARSER: Final[str] = "lxml"
except FeatureNotFound:
    _PARSER: Final[str] = "html.parser"  # type: ignore[misc]

# Tags whose **entire subtree** should be removed before text extraction.
_TAGS_TO_DECOMPOSE: Final[tuple[str, ...]] = (
    "script",
    "style",
    "noscript",
    "meta",
    "link",
    "svg",
    "iframe",
)


def sanitize_dom(raw_html: str) -> str:
    """Transform raw DOM HTML into clean, NLP-ready plaintext.

    Parameters
    ----------
    raw_html : str
        The unprocessed ``outerHTML`` captured by the browser extension.

    Returns
    -------
    str
        Whitespace-normalised plaintext with all markup, scripts, CSS,
        and non-visible elements removed.

    Examples
    --------
    >>> sanitize_dom("<html><script>alert(1)</script><p>Hello World</p></html>")
    'Hello World'
    """
    # ── 1. Parse with the best available parser ──
    soup: BeautifulSoup = BeautifulSoup(raw_html, _PARSER)

    # ── 2. Decompose (remove entirely) noisy/dangerous tags ──
    for tag_name in _TAGS_TO_DECOMPOSE:
        for element in soup.find_all(tag_name):
            element.decompose()

    # ── 3. Extract visible text with space-separated tokens ──
    raw_text: str = soup.get_text(separator=" ", strip=True)

    # ── 4. Collapse multi-whitespace sequences into single spaces ──
    clean_text: str = _WHITESPACE_RE.sub(" ", raw_text).strip()

    return clean_text
