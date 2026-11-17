"""
PhishGuard-AI — Request Schemas.
=================================

Pydantic v2 models for every request body.  Validation happens before any
handler runs, so malformed input is rejected with HTTP 422 and never reaches
the models or the database.

Architecture Layer : DTO / Validation
"""

from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

_URL_FIELD = Field(..., min_length=4, max_length=2048, description="Page address (http or https).")


_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(?!\d)")


def _check_web_url(value: str) -> str:
    """Accept http(s) URLs or bare host names; reject javascript:, data:, ftp:// and the like."""
    text = value.strip()
    match = _SCHEME_RE.match(text)
    if match and match.group(1).lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// addresses can be analysed.")
    if not match:
        # Typed without a scheme: insist on a real domain name, then assume http.
        if "." not in text.split("/", 1)[0] and "[" not in text:
            raise ValueError("The address needs a domain name such as example.com.")
        text = "http://" + text
    return text


class AnalyzeRequest(BaseModel):
    """Body of ``POST /api/v1/analyze`` (sent by the browser extension)."""

    url: str = _URL_FIELD
    dom_content: Optional[str] = Field(None, max_length=3_000_000, description="Page HTML (document.documentElement.outerHTML).")
    text_content: Optional[str] = Field(None, max_length=100_000, description="Visible page text.")
    screenshot: Optional[str] = Field(
        None, max_length=8_000_000,
        description="Base64 or data-URL screenshot of the visible tab for the YOLOv8n logo check.",
    )

    tls_error: Optional[str] = Field(None, max_length=80, pattern=r"^net::ERR_[A-Z_]+$", description="Certificate error reported by the browser, e.g. net::ERR_CERT_DATE_INVALID.")

    _url = field_validator("url")(_check_web_url)

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "url": "http://maybank2u-secure-login.top/m2u/login",
                "dom_content": "<html><body><h1>Maybank2u</h1><form><input type='password' name='pass'></form>"
                               "<p>Your account access has been limited. Verify immediately.</p></body></html>",
            }]
        }
    }


class MuleReportRequest(BaseModel):
    """Body of ``POST /api/v1/mule-reports`` (extension "Report account" action)."""

    account_number: str = Field(
        ..., min_length=6, max_length=34, pattern=r"^\+?[0-9][0-9\- ]{4,32}[0-9]$",
        description="Bank account, DuitNow phone or NRIC (digits, spaces and dashes only).",
        examples=["5142 7610 3388"],
    )
    bank_name: str = Field("Unknown", max_length=60)
    page_url: Optional[str] = Field(None, max_length=2048, description="Page on which the account was shown.")


class MuleReportReview(BaseModel):
    """Body of ``POST /api/v1/dashboard/mule-reports/{report_id}/review``."""

    decision: str = Field(..., pattern=r"^(APPROVE|REJECT)$", description="'APPROVE' or 'REJECT'.")


class MuleAccountCreate(BaseModel):
    """Body of ``POST /api/v1/dashboard/mules`` (analyst adds a verified account)."""

    account_number: str = Field(..., min_length=6, max_length=34, pattern=r"^\+?[0-9][0-9\- ]{4,32}[0-9]$")
    bank_name: str = Field(..., min_length=2, max_length=60)
    platform_flagged: str = Field("PDRM Semakmule", max_length=80, description="Where the account was reported.")


class DashboardAnalyzeRequest(BaseModel):
    """Body of ``POST /api/v1/dashboard/analyze`` (Live URL & Page Analyzer tab)."""

    url: str = _URL_FIELD
    page_text: Optional[str] = Field(None, max_length=100_000, description="Optional page text to analyse instead of fetching.")
    account_number: Optional[str] = Field(None, max_length=40, description="Optional account number to check.")
    fetch_page: bool = Field(True, description="Download the live page when no text is given.")
    screenshot_b64: Optional[str] = Field(None, max_length=8_000_000, description="Optional page screenshot (base64 or data URL) for the YOLOv8n logo check; used when the logo detector is enabled.")

    _url = field_validator("url")(_check_web_url)


class QRScanRequest(BaseModel):
    """Body of ``POST /api/v1/dashboard/qr-scan`` and ``POST /api/v1/analyze/qr``."""

    image_base64: str = Field(..., min_length=20, max_length=12_000_000, description="QR image as base64 or data URL.")


class DashboardLoginRequest(BaseModel):
    """Body of ``POST /api/v1/dashboard/auth/login``."""

    api_key: str = Field(..., min_length=1, max_length=256)
