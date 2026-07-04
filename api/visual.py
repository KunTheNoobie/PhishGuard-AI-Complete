from __future__ import annotations

import asyncio
import logging
from typing import Final

from fastapi import APIRouter, Depends, HTTPException, status

from core.security import verify_api_key
from schemas.visual import VisualAnalyzeRequest, VisualAnalyzeResponse
from services.visual_detector import VisualLogoDetector, evaluate_logo_domain

logger: Final[logging.Logger] = logging.getLogger("phishguard.visual_api")

router: Final[APIRouter] = APIRouter(
    prefix="/api/visual",
    tags=["Visual Identity Analysis"],
    dependencies=[Depends(verify_api_key)],
)

_detector: Final[VisualLogoDetector] = VisualLogoDetector()


@router.post(
    "/analyze",
    response_model=VisualAnalyzeResponse,
    summary="Analyse screenshot for financial-logo/domain mismatch",
    status_code=200,
)
async def analyze_visual(payload: VisualAnalyzeRequest) -> VisualAnalyzeResponse:
    """Detect supported Malaysian bank logos and compare them with the URL domain."""
    try:
        detections, warning = await asyncio.to_thread(_detector.detect, payload.screenshot)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_SCREENSHOT", "message": str(exc)},
        ) from exc
    except RuntimeError as exc:
        logger.warning("Visual analysis unavailable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "VISUAL_MODEL_UNAVAILABLE", "message": str(exc)},
        ) from exc

    if warning:
        logger.warning("Visual analysis unavailable: %s", warning)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "VISUAL_MODEL_UNAVAILABLE", "message": warning},
        )

    return evaluate_logo_domain(
        current_url=payload.current_url,
        detections=detections,
    )
