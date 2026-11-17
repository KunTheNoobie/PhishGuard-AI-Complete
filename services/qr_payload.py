"""
PhishGuard-AI — QR Code Decoding and DuitNow Payload Parsing.
==============================================================

* ``decode_qr_image``      — reads a QR code from an uploaded image with
                             OpenCV (three passes: colour, grey, adaptive
                             threshold) and classifies the payload.
* ``classify_payload``     — URL, DuitNow / EMVCo payment code, or plain text.
* ``extract_duitnow_accounts`` — pulls account / phone / ID proxies out of
                             EMVCo payment strings and DuitNow deep links, so
                             a QR sticker that pays a registered mule account
                             is caught even when it carries no URL.

The decoded URL itself is analysed by the full pipeline
(``services.analysis_pipeline``), exactly like a page visited in the browser.

Architecture Layer : Service / Detection
"""

from __future__ import annotations

import base64
import binascii
import io
import re
from typing import Any, Final

_EMV_RE: Final[re.Pattern[str]] = re.compile(r"000201[0-9A-Za-z.\-_:/?=&]{10,500}")
_DEEPLINK_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:duitnow|paynet)[^\"'\s]*[?&](?:acc|account|proxy|id)=([0-9\-+ ]{10,20})", re.IGNORECASE
)
_URL_RE: Final[re.Pattern[str]] = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_BARE_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:[/?#][^\s]*)?$", re.IGNORECASE
)
_MAX_IMAGE_BYTES: Final[int] = 8 * 1024 * 1024


def parse_emvco_tlv(payload: str) -> dict[str, str]:
    """Parse an EMVCo merchant-presented QR string into ``{tag: value}``."""
    tlv: dict[str, str] = {}
    idx, text = 0, payload.strip()
    while idx <= len(text) - 4:
        tag, length = text[idx:idx + 2], text[idx + 2:idx + 4]
        if not (tag.isdigit() and length.isdigit()):
            break
        end = idx + 4 + int(length)
        if end > len(text):
            break
        tlv[tag] = text[idx + 4:end]
        idx = end
    return tlv


def extract_duitnow_accounts(text: str) -> list[dict[str, str]]:
    """Return account proxies found in EMVCo payloads or DuitNow deep links."""
    found: dict[str, dict[str, str]] = {}
    for match in _EMV_RE.findall(text or ""):
        tlv = parse_emvco_tlv(match)
        for tag in range(26, 52):  # merchant account information templates
            for sub_tag, value in parse_emvco_tlv(tlv.get(f"{tag:02d}", "")).items():
                if sub_tag == "00":  # globally unique identifier of the scheme, not an account
                    continue
                digits = re.sub(r"\D", "", value)
                if 10 <= len(digits) <= 16:
                    found.setdefault(digits, {"account_number": digits, "source": "DuitNow / EMVCo QR payload"})
    for raw in _DEEPLINK_RE.findall(text or ""):
        digits = re.sub(r"\D", "", raw)
        if 10 <= len(digits) <= 16:
            found.setdefault(digits, {"account_number": digits, "source": "DuitNow deep link"})
    return list(found.values())


def classify_payload(payload: str) -> dict[str, Any]:
    """Describe what a decoded QR payload contains."""
    text = (payload or "").strip()
    urls = _URL_RE.findall(text)
    if not urls and _BARE_DOMAIN_RE.match(text):
        urls = ["http://" + text]
    accounts = extract_duitnow_accounts(text)
    is_payment = text.startswith("000201") or bool(accounts) or text.lower().startswith("duitnow")
    kind = "url" if urls else "payment" if is_payment else "text"
    return {"payload": text, "payload_type": kind, "urls": urls, "accounts": accounts}


def decode_qr_image(image_data: str | bytes) -> dict[str, Any]:
    """Decode the first QR code in an image (raw bytes or base64 / data URL)."""
    import cv2
    import numpy as np
    from PIL import Image, UnidentifiedImageError

    try:
        if isinstance(image_data, str):
            if image_data.startswith("data:") and "," in image_data:
                image_data = image_data.split(",", 1)[1]
            raw = base64.b64decode(image_data, validate=False)
        else:
            raw = image_data
    except (binascii.Error, ValueError):
        return {"decoded": False, "error": "The upload is not valid base64 image data."}
    if len(raw) > _MAX_IMAGE_BYTES:
        return {"decoded": False, "error": "Image is larger than 8 MB."}
    try:
        image = Image.open(io.BytesIO(raw)).convert("RGB")
    except (UnidentifiedImageError, OSError):
        return {"decoded": False, "error": "The file is not a readable image."}

    bgr = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
    grey = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    detector = cv2.QRCodeDetector()
    for candidate in (bgr, grey, cv2.adaptiveThreshold(grey, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                                         cv2.THRESH_BINARY, 11, 2)):
        text, _, _ = detector.detectAndDecode(candidate)
        if text:
            return {"decoded": True, **classify_payload(text)}
    return {"decoded": False, "error": "No QR code could be read in this image."}
