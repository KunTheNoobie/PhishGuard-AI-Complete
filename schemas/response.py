"""
PhishGuard-AI — Response Schemas.
==================================

The shape of an analysis result.  Declaring it here makes FastAPI validate
every response and publish the exact contract in ``/docs``.

Architecture Layer : DTO / Contract
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Reason(BaseModel):
    severity: Literal["high", "medium", "low", "info", "ok"]
    text: str


class PipelineStep(BaseModel):
    name: str
    status: Literal["pass", "warn", "fail", "skip", "info"]
    detail: str
    ms: Optional[float] = None


class BertResult(BaseModel):
    label: Optional[str] = None
    confidence: Optional[float] = None
    phishing_probability: Optional[float] = None
    is_malicious: Optional[bool] = None
    skipped: Optional[bool] = None


class MuleResult(BaseModel):
    accounts_extracted: list[str] = Field(default_factory=list)
    flagged_accounts: list[dict[str, Any]] = Field(default_factory=list)
    details: list[dict[str, Any]] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Explained verdict for one page."""

    transaction_id: str
    timestamp: str
    source: str
    url: str = Field(..., description="Requested URL (user name, query and fragment removed).")
    final_url: str = Field(..., description="URL actually analysed (after redirects).")
    hostname: str
    scheme: str
    is_whitelisted: bool
    verdict: Literal["SAFE", "WARNING", "BLOCK_RENDER"]
    risk_level: Literal["safe", "warning", "dangerous"]
    risk_score: float = Field(..., ge=0.0, le=1.0)
    rule: Optional[str] = Field(None, description="Rule that produced the verdict (R1–R9, H1–H2, W1–W3).")
    headline: str
    explanation: str = Field(..., description="One-paragraph plain-language explanation.")
    reasons: list[Reason]
    signals: dict[str, bool]
    steps: list[PipelineStep]
    bert: BertResult
    mule: MuleResult
    brand: dict[str, Any]
    heuristics: dict[str, Any]
    visual: Optional[dict[str, Any]] = None
    page: dict[str, Any]
    processing_time_ms: float


class QRScanResponse(BaseModel):
    """Decoded QR code plus the analysis of the URL it points to."""

    decoded: bool
    payload: Optional[str] = None
    payload_type: Optional[Literal["url", "payment", "text"]] = None
    error: Optional[str] = None
    accounts: list[dict[str, Any]] = Field(default_factory=list)
    flagged_accounts: list[dict[str, Any]] = Field(default_factory=list)
    verdict: Literal["SAFE", "WARNING", "BLOCK_RENDER", "UNKNOWN"]
    headline: str
    analysis: Optional[AnalysisResponse] = None
