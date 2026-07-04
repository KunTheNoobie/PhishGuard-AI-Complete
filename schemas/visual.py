from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class BoundingBox(BaseModel):
    x1: float
    y1: float
    x2: float
    y2: float


class DetectedLogo(BaseModel):
    brand: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    bbox: BoundingBox


class VisualAnalyzeRequest(BaseModel):
    current_url: str = Field(..., description="Current webpage URL from the Chrome extension.")
    page_title: str = Field(default="", description="Document title from the inspected page.")
    visible_text: str = Field(
        default="",
        max_length=500_000,
        description="Visible page text extracted by the content script.",
    )
    screenshot: str = Field(
        ...,
        max_length=15_000_000,
        description="Visible-tab screenshot as a data URL or raw base64 string.",
    )


class VisualAnalyzeResponse(BaseModel):
    detected_logos: list[DetectedLogo] = Field(default_factory=list)
    risk_level: Literal["safe", "suspicious", "dangerous"]
    reason: str
