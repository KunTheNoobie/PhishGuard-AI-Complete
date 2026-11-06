"""
PhishGuard-AI — Response Envelope Schemas.
===========================================

Defines the unified JSON response structure returned by all analysis
endpoints. The envelope follows the **JSend** convention extended with
an ``orchestration`` directive consumed by the browser extension's
content-script to decide whether to block page rendering, and provides
top-level convenience fields for direct threat intelligence consumption.

Architecture Layer : DTO / Presentation
Thesis Reference   : §3.5 — Outbound Data Contracts & Orchestration Signals
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


# ==============================================================================
# Sub-Models
# ==============================================================================

class MetaBlock(BaseModel):
    """Operational metadata attached to every API response."""

    transaction_id: str = Field(
        ...,
        description="UUID v4 uniquely identifying this analysis transaction.",
    )
    processing_time_ms: float = Field(
        ...,
        description="Wall-clock latency of the full analysis pipeline in ms.",
    )


class SemanticResult(BaseModel):
    """Output of the BERT-based semantic analysis stage."""

    label: str = Field(
        ...,
        description=(
            "Classification label emitted by the NLP model "
            "(e.g., 'PHISHING', 'LEGITIMATE')."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Softmax confidence score in [0, 1].",
    )
    is_malicious: bool = Field(
        ...,
        description="True if confidence exceeds the malicious threshold.",
    )
    sanitized_text_preview: str = Field(
        ...,
        description="Truncated preview of the sanitized text fed to BERT.",
    )


class MuleScanResult(BaseModel):
    """Output of the mule-account scanning stage."""

    accounts_extracted: list[str] = Field(
        default_factory=list,
        description="Account numbers extracted from the page via regex.",
    )
    flagged_accounts: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Subset of extracted accounts that matched known mule records "
            "in the registry, including bank name and report count."
        ),
    )
    mule_detected: bool = Field(
        ...,
        description="True if at least one flagged mule account was found.",
    )


class DataBlock(BaseModel):
    """Aggregated analysis results from all pipeline stages."""

    semantic_analysis: SemanticResult
    mule_scan: MuleScanResult


# ==============================================================================
# Top-Level Envelopes
# ==============================================================================

class AnalysisResponse(BaseModel):
    """Unified response envelope for the ``/analyze/semantics`` endpoint.

    The ``orchestration`` field carries a directive that the browser
    extension's content-script interprets:

    - ``BLOCK_RENDER`` — inject a warning interstitial and prevent the
      page from rendering.
    - ``SAFE`` — allow normal rendering; no action required.
    """

    meta: MetaBlock
    data: DataBlock
    orchestration: str = Field(
        ...,
        description="Orchestration directive: 'BLOCK_RENDER' or 'SAFE'.",
        examples=["BLOCK_RENDER", "SAFE"],
    )

    # Top-level unified fields for thesis and OpenAPI compatibility (§4.3.2)
    status: str = Field(default="success", description="API execution status.")
    verdict: Optional[str] = Field(default=None, description="Final orchestration directive ('BLOCK_RENDER' or 'SAFE').")
    risk_score: Optional[float] = Field(default=None, description="Calibrated multi-vector risk probability.")
    bert_score: Optional[float] = Field(default=None, description="Raw semantic threat probability from BERT.")
    is_whitelisted: Optional[bool] = Field(default=None, description="True if domain matched 28-Bank Trusted Whitelist.")
    brand_impersonation: Optional[dict[str, Any]] = Field(default=None, description="Brand impersonation profile.")
    mule_accounts_flagged: Optional[list[dict[str, Any]]] = Field(default=None, description="List of matched mule accounts.")
    execution_time_ms: Optional[float] = Field(default=None, description="Total server-side processing latency in ms.")
    timestamp: Optional[str] = Field(default=None, description="ISO-8601 evaluation timestamp.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "meta": {
                        "transaction_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                        "processing_time_ms": 142.7,
                    },
                    "data": {
                        "semantic_analysis": {
                            "label": "PHISHING",
                            "confidence": 0.97,
                            "is_malicious": True,
                            "sanitized_text_preview": "Please transfer RM500 to ...",
                        },
                        "mule_scan": {
                            "accounts_extracted": ["1234567890"],
                            "flagged_accounts": [
                                {
                                    "account_number": "1234567890",
                                    "bank_name": "Maybank",
                                    "report_count": 14,
                                }
                            ],
                            "mule_detected": True,
                        },
                    },
                    "orchestration": "BLOCK_RENDER",
                    "status": "success",
                    "verdict": "BLOCK_RENDER",
                    "risk_score": 0.985,
                    "bert_score": 0.972418,
                    "is_whitelisted": False,
                    "mule_accounts_flagged": [
                        {
                            "account_number": "1234567890",
                            "bank_name": "Maybank",
                            "report_count": 14,
                        }
                    ],
                    "execution_time_ms": 142.7,
                }
            ]
        }
    }


class QuishingAnalysisRequest(BaseModel):
    """Payload schema for optical QR and Quishing forensic inspection (§4.3.3)."""

    image_base64: str = Field(
        ...,
        title="Base64 Encoded QR Code Image",
        description="Base64-encoded image bytes of the suspicious QR code.",
    )
    page_url: Optional[str] = Field(
        None,
        title="Page URL",
        description="URL of the page where the QR code was rendered.",
    )


class QuishingAnalysisResponse(BaseModel):
    """Forensic evaluation response for Quishing inspection."""

    quishing_threat: bool = Field(..., description="True if payload is flagged as malicious.")
    quishing_score: float = Field(..., description="Calibrated quishing forensic probability.")
    decoded_payload: str = Field(..., description="Decoded URL or PayNet EMVCo string.")
    verdict: str = Field(..., description="Defensive action: 'BLOCK_RENDER' or 'SAFE'.")
    risk_factors: list[str] = Field(default_factory=list, description="Forensic risk flags.")
    raw_payload: Optional[str] = Field(default=None, description="Exact raw decoded payload.")
    is_duitnow_scheme: Optional[bool] = Field(default=None, description="True if DuitNow EMVCo QR code.")
    extracted_destination_urls: Optional[list[str]] = Field(default_factory=list, description="Extracted URLs.")
    extracted_mule_accounts: Optional[list[str]] = Field(default_factory=list, description="Extracted mule accounts.")
