from __future__ import annotations

import base64
import io
import logging
import os
import threading
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

from core.config import VISUAL_CONFIDENCE_THRESHOLD, VISUAL_MODEL_PATH, GLOBAL_SAFE_DOMAINS
from schemas.visual import BoundingBox, DetectedLogo, VisualAnalyzeResponse

logger: Final[logging.Logger] = logging.getLogger("phishguard.visual_detector")

SUPPORTED_BRANDS: Final[set[str]] = {
    "Maybank",
    "CIMB",
    "Public Bank",
    "RHB",
    "Hong Leong Bank",
}

AUTHORIZED_DOMAINS: Final[dict[str, list[str]]] = {
    "Maybank": ["maybank2u.com.my", "maybank.com", "maybank.com.my"],
    "CIMB": ["cimbclicks.com.my", "cimb.com.my", "cimbbank.com.my"],
    "Public Bank": ["pbebank.com", "pbebank.com.my", "publicbank.com.my"],
    "RHB": ["rhbgroup.com", "rhbnow.com", "rhbbank.com.my"],
    "Hong Leong Bank": ["hlb.com.my"],
}

BRAND_ALIASES: Final[dict[str, str]] = {
    "maybank": "Maybank",
    "cimb": "CIMB",
    "publicbank": "Public Bank",
    "public bank": "Public Bank",
    "public_bank": "Public Bank",
    "rhb": "RHB",
    "hongleongbank": "Hong Leong Bank",
    "hong leong bank": "Hong Leong Bank",
    "hong_leong_bank": "Hong Leong Bank",
}

_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
_YOLO_CONFIG_DIR: Final[Path] = _PROJECT_ROOT / "visual_identity" / ".ultralytics"
_OFFICIAL_DOMAIN_MISMATCH_THRESHOLD: Final[float] = 0.95
_MAX_SCREENSHOT_PIXELS: Final[int] = 25_000_000


def _decode_screenshot(screenshot: str):
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:
        raise RuntimeError("Pillow is required for screenshot decoding.") from exc

    if "," in screenshot and screenshot.lower().startswith("data:"):
        screenshot = screenshot.split(",", 1)[1]

    try:
        image_bytes = base64.b64decode(screenshot, validate=True)
    except ValueError as exc:
        raise ValueError("Screenshot must be a valid base64 image or data URL.") from exc

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            if image.width * image.height > _MAX_SCREENSHOT_PIXELS:
                raise ValueError(
                    f"Screenshot is too large; maximum decoded size is {_MAX_SCREENSHOT_PIXELS:,} pixels."
                )
            image.load()
            return image.convert("RGB")
    except ValueError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Screenshot data is not a supported image.") from exc


def _normalize_brand(label: str) -> str | None:
    normalized = label.strip().lower().replace("-", " ").replace("_", " ")
    compact = normalized.replace(" ", "")

    if label in SUPPORTED_BRANDS:
        return label

    for alias, brand in BRAND_ALIASES.items():
        alias_normalized = alias.lower().replace("_", " ")
        if normalized == alias_normalized or compact == alias_normalized.replace(" ", ""):
            return brand

    return None


def _hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def _domain_matches(host: str, allowed_domains: list[str]) -> bool:
    for domain in allowed_domains:
        domain = domain.lower()
        if host == domain or host.endswith(f".{domain}"):
            return True
    return False


def _official_brand_for_host(host: str) -> str | None:
    for brand, domains in AUTHORIZED_DOMAINS.items():
        if _domain_matches(host, domains):
            return brand
    return None


class VisualLogoDetector:
    """Thin YOLOv8 wrapper for Cheon's visual identity module."""

    def __init__(
        self,
        model_path: str = VISUAL_MODEL_PATH,
        confidence_threshold: float = VISUAL_CONFIDENCE_THRESHOLD,
    ) -> None:
        self._model_path = model_path
        self._confidence_threshold = confidence_threshold
        self._model: Any | None = None
        self._load_error: str | None = None
        self._load_lock = threading.Lock()
        self._inference_lock = threading.Lock()

    def _load_model(self):
        if self._model is not None:
            return self._model

        with self._load_lock:
            if self._model is not None:
                return self._model

            model_file = Path(self._model_path).expanduser()
            if not model_file.is_absolute():
                model_file = _PROJECT_ROOT / model_file
            model_file = model_file.resolve()

            if not model_file.exists():
                self._load_error = (
                    f"Visual model not found at {model_file}. "
                    "Train YOLOv8 and copy best.pt to visual_identity/models/best.pt."
                )
                logger.warning(self._load_error)
                return None

            try:
                os.environ.setdefault("YOLO_CONFIG_DIR", str(_YOLO_CONFIG_DIR))
                from ultralytics import YOLO
            except ImportError:
                self._load_error = "ultralytics is not installed. Run pip install -r requirements.txt."
                logger.warning(self._load_error)
                return None

            self._model = YOLO(str(model_file))
            self._load_error = None
            logger.info("Loaded visual YOLO model from %s", model_file)
            return self._model

    def detect(self, screenshot: str) -> tuple[list[DetectedLogo], str | None]:
        model = self._load_model()
        if model is None:
            return [], self._load_error

        image = _decode_screenshot(screenshot)
        with self._inference_lock:
            results = model.predict(
                source=image,
                conf=self._confidence_threshold,
                verbose=False,
            )

        detections: list[DetectedLogo] = []
        for result in results:
            names = result.names
            boxes = result.boxes
            if boxes is None:
                continue

            for box in boxes:
                class_id = int(box.cls[0].item())
                raw_label = str(names.get(class_id, class_id))
                brand = _normalize_brand(raw_label)
                if not brand:
                    continue

                confidence = round(float(box.conf[0].item()), 4)
                x1, y1, x2, y2 = [round(float(value), 2) for value in box.xyxy[0].tolist()]
                detections.append(
                    DetectedLogo(
                        brand=brand,
                        confidence=confidence,
                        bbox=BoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
                    )
                )

        return detections, None


def evaluate_logo_domain(
    current_url: str,
    detections: list[DetectedLogo],
    detector_warning: str | None = None,
) -> VisualAnalyzeResponse:
    if detector_warning:
        raise RuntimeError(detector_warning)

    if not detections:
        return VisualAnalyzeResponse(
            detected_logos=[],
            risk_level="safe",
            reason="No supported Malaysian financial logo was detected in the screenshot.",
        )

    host = _hostname(current_url)
    
    # ── Global Safe Domain Check ──
    # If the user is on a massively popular platform (e.g. WhatsApp, Instagram, Google),
    # bypass the visual checks. YOLOv8 can hallucinate logos in random user content,
    # and these major platforms are definitively not phishing hosting sites.
    for safe_domain in GLOBAL_SAFE_DOMAINS:
        if host == safe_domain or host.endswith(f".{safe_domain}"):
            return VisualAnalyzeResponse(
                detected_logos=detections,
                risk_level="safe",
                reason=f"Platform '{safe_domain}' is a globally trusted domain. Any logo detections are treated as user-generated content or model noise.",
            )

    official_brand = _official_brand_for_host(host)

    if official_brand:
        matching_detections = [
            detection for detection in detections if detection.brand == official_brand
        ]
        cross_brand_detections = [
            detection for detection in detections if detection.brand != official_brand
        ]

        if matching_detections:
            return VisualAnalyzeResponse(
                detected_logos=matching_detections,
                risk_level="safe",
                reason=(
                    f"Detected {official_brand} logo and the current domain "
                    f"'{host}' is an authorised {official_brand} domain."
                ),
            )

        strongest_cross_brand = max(
            cross_brand_detections,
            key=lambda item: item.confidence,
            default=None,
        )
        if (
            strongest_cross_brand is None
            or strongest_cross_brand.confidence < _OFFICIAL_DOMAIN_MISMATCH_THRESHOLD
        ):
            return VisualAnalyzeResponse(
                detected_logos=[],
                risk_level="safe",
                reason=(
                    f"The current domain '{host}' is an authorised {official_brand} "
                    "domain. Cross-brand logo detections below the manual-review "
                    "threshold were treated as visual-model noise."
                ),
            )

        return VisualAnalyzeResponse(
            detected_logos=cross_brand_detections,
            risk_level="suspicious",
            reason=(
                f"The current domain '{host}' is an authorised {official_brand} "
                f"domain, but a high-confidence {strongest_cross_brand.brand} logo "
                "was detected. Please manually review this screenshot."
            ),
        )

    mismatches: list[DetectedLogo] = []

    for detection in detections:
        allowed_domains = AUTHORIZED_DOMAINS.get(detection.brand, [])
        if not _domain_matches(host, allowed_domains):
            mismatches.append(detection)

    if not mismatches:
        brands = ", ".join(sorted({detection.brand for detection in detections}))
        return VisualAnalyzeResponse(
            detected_logos=detections,
            risk_level="safe",
            reason=f"Detected {brands} logo and the current domain matches an authorised domain.",
        )

    strongest = max(mismatches, key=lambda item: item.confidence)
    allowed = ", ".join(AUTHORIZED_DOMAINS.get(strongest.brand, []))
    risk_level = "dangerous" if strongest.confidence >= 0.85 else "suspicious"
    return VisualAnalyzeResponse(
        detected_logos=detections,
        risk_level=risk_level,
        reason=(
            f"{strongest.brand} logo detected but the URL domain '{host or current_url}' "
            f"does not match an authorised {strongest.brand} domain ({allowed})."
        ),
    )
