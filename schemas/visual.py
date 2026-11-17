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


class VisualAnalyzeResponse(BaseModel):
    detected_logos: list[DetectedLogo] = Field(default_factory=list)
    risk_level: Literal["safe", "suspicious", "dangerous"]
    reason: str
