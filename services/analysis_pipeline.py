"""
PhishGuard-AI — Analysis Pipeline.
===================================

The single code path behind every verdict.  The browser extension
(``POST /api/v1/analyze``), the dashboard's Live URL Analyzer and the QR
scanner all call ``analyze_page`` so the three can never disagree.

    URL ──► 1 canonicalise ──► 2 (optional) fetch live page ──► 3 trusted list
        ──► 4 transport (HTTPS / HTTP) ──► 5 page structure (DOM)
        ──► 6 BERT URL model ║ mule-registry scan ║ YOLOv8n logo check   (parallel)
        ──► 7 URL heuristics + brand impersonation
        ──► 8 corroborated verdict + plain-language explanation
        ──► 9 scan_log row

Every stage is reported in ``steps`` so the dashboard can show exactly why
a verdict was reached.

Architecture Layer : Service / Orchestration
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

from core.config import ALL_TRUSTED_DOMAINS
from database.repository import increment_report_counts, log_scan
from services.brand_profiler import profile_brand_impersonation
from services.heuristic_engine import analyze_url_heuristics
from services.page_fetcher import fetch_page
from services.sanitizer import sanitize_dom
from services.url_canonicalizer import CanonicalURL, canonicalize
from services.verdict_engine import decide, detect_sensitive_fields

logger: Final[logging.Logger] = logging.getLogger("phishguard.pipeline")

_PREVIEW_CHARS: Final[int] = 200


@dataclass
class PageInput:
    """What a client knows about the page to analyse."""

    url: str
    html: str = ""
    text: str = ""
    screenshot: str | None = None
    source: str = "api"                   # extension | dashboard | qr | api
    fetch: bool = False                   # download the page server-side if no HTML was sent
    extra_accounts: list[str] = field(default_factory=list)


def is_trusted_host(hostname: str) -> bool:
    """True if ``hostname`` is, or is a subdomain of, a whitelisted domain."""
    host = hostname.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in ALL_TRUSTED_DOMAINS)


def _step(name: str, status: str, detail: str, started: float | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name, "status": status, "detail": detail}
    if started is not None:
        entry["ms"] = round((time.perf_counter() - started) * 1000, 1)
    return entry


async def _run_bert(state: Any, canon: CanonicalURL, trusted: bool) -> dict[str, Any]:
    if trusted:
        return {"label": "LEGITIMATE", "confidence": 1.0, "phishing_probability": 0.0,
                "is_malicious": False, "skipped": True, "reason": "trusted domain"}
    engine = getattr(state, "semantic_engine", None)
    if engine is None:
        return {"label": "UNAVAILABLE", "confidence": 0.0, "phishing_probability": 0.0,
                "is_malicious": False, "skipped": True, "reason": "model not loaded"}
    cache = getattr(state, "cache", None)
    key = cache.hash_key(canon.model_url) if cache else None
    cached = cache.get(key) if cache and key else None
    if cached is not None:
        return {**cached, "cached": True}
    result = await engine.predict(canon.model_url)
    result.setdefault("phishing_probability",
                      result["confidence"] if result.get("label") == "PHISHING" else 1 - result.get("confidence", 0))
    if cache and key:
        cache.set(key, result)
    return result


async def _run_visual(state: Any, canon: CanonicalURL, screenshot: str | None, trusted: bool) -> dict[str, Any] | None:
    detector = getattr(state, "visual_detector", None)
    if not screenshot:
        return None
    if trusted:
        return {"status": "skipped", "reason": "trusted domain", "detected_logos": [], "risk_level": "safe"}
    if detector is None:
        return {"status": "unavailable", "reason": "logo model not loaded", "detected_logos": [], "risk_level": "safe"}
    from services.visual_detector import evaluate_logo_domain

    try:
        detections, warning = await asyncio.to_thread(detector.detect, screenshot)
    except ValueError as exc:
        return {"status": "error", "reason": str(exc), "detected_logos": [], "risk_level": "safe"}
    if warning:
        return {"status": "unavailable", "reason": warning, "detected_logos": [], "risk_level": "safe"}
    verdict = evaluate_logo_domain(current_url=canon.display_url, detections=detections)
    return {"status": "ok", **verdict.model_dump()}


async def analyze_page(inp: PageInput, state: Any) -> dict[str, Any]:
    """Run the full pipeline on one page and return the explained verdict."""
    started = time.perf_counter()
    steps: list[dict[str, Any]] = []
    requested = canonicalize(inp.url)
    canon = requested

    # 1. Canonicalise ----------------------------------------------------------
    steps.append(_step(
        "URL canonicalisation", "warn" if requested.notes else "pass",
        " ".join(requested.notes) if requested.notes else f"The browser opens {requested.hostname}.",
    ))

    # 2. Live fetch (dashboard / QR only) --------------------------------------
    html, text, tls_error, page_meta = inp.html or "", inp.text or "", None, {"fetched": False}
    if inp.fetch and not html and not text:
        t = time.perf_counter()
        fetched = await fetch_page(requested.fetch_url)
        page_meta = {"fetched": fetched.ok or bool(fetched.html), "status_code": fetched.status_code,
                     "redirects": fetched.redirects, "error": fetched.error}
        tls_error = fetched.tls_error
        if fetched.redirects:
            canon = canonicalize(fetched.final_url)
        html = fetched.html
        if fetched.html:
            chain = " → ".join([requested.display_url, *fetched.redirects]) if fetched.redirects else "no redirects"
            steps.append(_step("Live page fetch", "pass",
                               f"HTTP {fetched.status_code}, {len(fetched.html):,} characters ({chain}).", t))
        elif tls_error:
            steps.append(_step("Live page fetch", "warn", f"Certificate check failed: {tls_error}.", t))
        else:
            steps.append(_step("Live page fetch", "warn",
                               f"{fetched.error or 'No content'} The URL is analysed without page content.", t))

    # 3. Trusted list ----------------------------------------------------------
    trusted = is_trusted_host(canon.hostname)
    steps.append(_step("Trusted-domain check", "pass" if trusted else "info",
                       f"{canon.hostname} is on the trusted list; AI URL check skipped." if trusted
                       else f"{canon.hostname} is not on the trusted list; every check runs."))

    # 4. Transport -------------------------------------------------------------
    steps.append(_step("Connection security", "pass" if canon.is_https else "warn",
                       "HTTPS: the connection is encrypted." if canon.is_https
                       else "HTTP: the connection is not encrypted."))

    # 5. Page structure --------------------------------------------------------
    t = time.perf_counter()
    if html:
        text = sanitize_dom(html) or text
    if inp.extra_accounts:
        text = (text + " " + " ".join(inp.extra_accounts)).strip()
    fields = detect_sensitive_fields(html)
    if html or text:
        steps.append(_step("Page structure (DOM)", "warn" if fields else "pass",
                           f"{len(text):,} characters of visible text; "
                           + (f"sensitive input fields: {', '.join(fields)}." if fields else "no password, card or OTP field."),
                           t))
    else:
        steps.append(_step("Page structure (DOM)", "skip", "No page content available; URL-only analysis."))

    # 6. Models in parallel ----------------------------------------------------
    t = time.perf_counter()
    bert, mule, visual = await asyncio.gather(
        _run_bert(state, canon, trusted),
        state.mule_scanner.scan_and_verify(text, state.db),
        _run_visual(state, canon, inp.screenshot, trusted),
    )
    parallel_ms = round((time.perf_counter() - t) * 1000, 1)
    if bert.get("skipped"):
        steps.append(_step("BERT URL model", "skip", f"Not run ({bert.get('reason')})."))
    else:
        p = float(bert["phishing_probability"])
        steps.append({**_step("BERT URL model", "fail" if bert["is_malicious"] else "pass",
                              f"P(phishing) = {p:.3f}" + (" (cached)" if bert.get("cached") else "")),
                      "ms": parallel_ms})
    flagged = mule["flagged_accounts"]
    steps.append(_step("Mule-account registry", "fail" if flagged else "pass",
                       f"{len(mule['accounts_extracted'])} account number(s) found; "
                       + (f"registry match: {', '.join(a['account_number'] for a in flagged)}." if flagged
                          else "no registry match.")))
    if visual is None:
        steps.append(_step("YOLOv8n logo check", "skip", "No screenshot supplied."))
    elif visual["status"] != "ok":
        steps.append(_step("YOLOv8n logo check", "skip", f"Not run ({visual['reason']})."))
    else:
        steps.append(_step("YOLOv8n logo check",
                           "fail" if visual["risk_level"] in ("dangerous", "suspicious") else "pass",
                           visual.get("reason", "")))

    # 7. Structure and brand ---------------------------------------------------
    heuristics = analyze_url_heuristics(canon)
    brand = profile_brand_impersonation(canon, text)
    steps.append(_step("URL structure", "warn" if heuristics["is_suspicious"] else "pass",
                       "; ".join(heuristics["indicators"]) or "No structural anomaly."))
    if brand["is_official_domain"]:
        brand_detail, brand_status = f"Official domain of {brand['target_brand']}.", "pass"
    elif brand["is_impersonation"]:
        brand_detail = f"Imitates {brand['target_brand']} ({', '.join(brand['matched_brand_cues'])})."
        brand_status = "fail"
    elif brand["brand_mentioned"]:
        brand_detail, brand_status = f"Mentions {brand['target_brand']} in the text (weak cue).", "info"
    else:
        brand_detail, brand_status = "No protected brand involved.", "pass"
    steps.append(_step("Brand impersonation", brand_status, brand_detail))

    # 8. Verdict ---------------------------------------------------------------
    verdict = decide(
        canon=canon, is_trusted=trusted, bert_result=bert, mule_result=mule, brand_result=brand,
        heuristic_result=heuristics, sanitized_text=text, raw_content=html or text,
        visual_result=visual if visual and visual.get("status") == "ok" else None, tls_error=tls_error,
    )
    if inp.fetch and not html and not text and not tls_error:
        note = "The page itself could not be downloaded, so only the address was checked."
        verdict.reasons.append({"severity": "info", "text": note})
        verdict.explanation = f"{verdict.explanation} {note}"
    steps.append(_step("Corroborated verdict", {"SAFE": "pass", "WARNING": "warn"}.get(verdict.verdict, "fail"),
                       f"{verdict.verdict}" + (f" by rule {verdict.rule}" if verdict.rule else "") + f": {verdict.headline}."))
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

    # 9. Log -------------------------------------------------------------------
    try:
        await log_scan({
            "source": inp.source if inp.source in ("extension", "dashboard", "qr", "api") else "api",
            "url": canon.display_url, "hostname": canon.hostname, "scheme": canon.scheme,
            "verdict": verdict.verdict, "rule": verdict.rule, "risk_score": verdict.risk_score,
            "bert_score": None if bert.get("skipped") else float(bert["phishing_probability"]),
            "headline": verdict.headline, "latency_ms": elapsed_ms,
        }, state.db)
        if verdict.is_threat and flagged:
            await increment_report_counts([a["account_number"] for a in flagged], state.db)
    except Exception:  # logging must never break a verdict
        logger.exception("Could not write the scan log.")

    logger.info("%s %s -> %s (%s) in %.0f ms", inp.source, canon.hostname, verdict.verdict, verdict.rule, elapsed_ms)
    return {
        "transaction_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": inp.source,
        "url": requested.display_url,
        "final_url": canon.display_url,
        "hostname": canon.hostname,
        "scheme": canon.scheme,
        "is_whitelisted": trusted,
        **verdict.as_dict(),
        "steps": steps,
        "bert": {k: bert.get(k) for k in ("label", "confidence", "phishing_probability", "is_malicious", "skipped")},
        "mule": {"accounts_extracted": mule["accounts_extracted"], "flagged_accounts": flagged,
                 "details": mule.get("extracted_details", [])},
        "brand": brand,
        "heuristics": {k: heuristics[k] for k in ("indicators", "is_strong", "registrable_domain")},
        "visual": visual,
        "page": {**page_meta, "sensitive_fields": fields, "text_preview": text[:_PREVIEW_CHARS]},
        "processing_time_ms": elapsed_ms,
    }


async def scan_qr_code(image_base64: str, state: Any, source: str = "qr") -> dict[str, Any]:
    """Decode a QR image and analyse what it points to.

    * URL payload      → the full pipeline on the live page (fetched server-side).
    * DuitNow payload  → the paid account is checked against the mule registry.
    * Plain text       → reported as such.
    """
    from database.repository import check_mule_accounts
    from services.mule_scanner import normalise_account
    from services.qr_payload import decode_qr_image

    decoded = await asyncio.to_thread(decode_qr_image, image_base64)
    if not decoded.get("decoded"):
        return {"decoded": False, "error": decoded.get("error"), "verdict": "UNKNOWN",
                "headline": "No QR code could be read", "accounts": [], "flagged_accounts": []}

    accounts = decoded["accounts"]
    flagged = await check_mule_accounts([normalise_account(a["account_number"]) for a in accounts], state.db)
    analysis = None
    if decoded["urls"]:
        analysis = await analyze_page(PageInput(url=decoded["urls"][0], source=source, fetch=True), state)
        verdict, headline = analysis["verdict"], analysis["headline"]
    elif decoded["payload_type"] == "payment":
        verdict = "SAFE"
        headline = "Payment QR code; the receiving account is not in the mule registry"
    else:
        verdict, headline = "SAFE", "QR code contains plain text, not a link"
    if flagged:
        verdict = "BLOCK_RENDER"
        headline = "QR code pays a registered mule account"
    return {"decoded": True, "payload": decoded["payload"], "payload_type": decoded["payload_type"],
            "accounts": accounts, "flagged_accounts": flagged, "verdict": verdict, "headline": headline,
            "analysis": analysis}
