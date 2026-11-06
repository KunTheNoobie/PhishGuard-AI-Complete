"""
PhishGuard-AI — Request Payload Schemas.
=========================================

Pydantic v2 models defining the shape of incoming request bodies. Every
field carries explicit type annotations (PEP 484) and validator metadata
so that FastAPI can auto-generate OpenAPI documentation and perform
server-side validation *before* any business logic executes.

Architecture Layer: DTO / Anti-Corruption Layer
Thesis Reference : §3.4 — Inbound Data Contracts
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field, HttpUrl, model_validator


class WebPayload(BaseModel):
    """Canonical inbound payload for the ``/analyze/semantics`` endpoint.

    Attributes
    ----------
    url : HttpUrl
        The fully-qualified URL of the page currently rendered in the
        user's browser. Validated to reject malformed URIs at the edge.
    dom_content : Optional[str]
        The raw ``document.documentElement.outerHTML`` captured by the
        browser extension. Will be ETL-sanitised before NLP inference.
    text_content : Optional[str]
        Sanitised innerText / plaintext extracted from the webpage DOM.
    origin : Optional[str]
        Optional HTTP origin or referrer header.
    extract_mules : bool
        Flag to enable deterministic Regex mule account scanning.
    """

    url: HttpUrl = Field(
        ...,
        title="Page URL",
        description="Fully-qualified URL of the inspected page.",
        examples=["https://secure-banking.example.com/login"],
    )
    dom_content: Optional[str] = Field(
        None,
        title="Raw DOM Content",
        description=(
            "Complete outerHTML of the page. Must contain at least one "
            "non-whitespace character after sanitization."
        ),
        max_length=5_000_000,  # 5 MB hard cap to prevent DoS.
    )
    text_content: Optional[str] = Field(
        None,
        title="Sanitised innerText / DOM text",
        description="Sanitised plaintext extracted from the webpage DOM.",
        max_length=5_000_000,
    )
    origin: Optional[str] = Field(
        None,
        title="Origin Header",
        description="Optional HTTP origin or referrer header.",
    )
    extract_mules: bool = Field(
        True,
        title="Extract Mules Flag",
        description="Flag to enable deterministic Regex mule account scanning.",
    )

    @model_validator(mode="before")
    @classmethod
    def validate_content_presence(cls, data: Any) -> Any:
        if isinstance(data, dict):
            dom = data.get("dom_content")
            txt = data.get("text_content")
            if not dom and txt:
                data["dom_content"] = txt
            elif not txt and dom:
                data["text_content"] = dom

            content = data.get("dom_content") or data.get("text_content")
            if content is None or not str(content).strip():
                raise ValueError("Payload must contain non-empty 'dom_content' or 'text_content'.")
        return data

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "url": "https://maybank2u.com.my/login",
                    "dom_content": (
                        "<html><body><h1>Login</h1>"
                        "<p>Please transfer RM500 to account 1234567890</p>"
                        "</body></html>"
                    ),
                    "text_content": "Login Please transfer RM500 to account 1234567890",
                    "extract_mules": True,
                }
            ]
        }
    }
