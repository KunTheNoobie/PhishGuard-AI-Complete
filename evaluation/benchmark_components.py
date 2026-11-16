"""
PhishGuard-AI — Per-Component Measurements for the Architecture Trade-off Analysis.
====================================================================================

Measures detection quality and latency of individual detector families on the
120-page Malaysian benchmark so that they can be compared with the complete
pipeline (``evaluate_pipeline.py``):

* URL heuristics alone (``services.heuristic_engine``): block if any structural
  anomaly is present.
* YOLOv8n visual logo detector: CPU latency per screenshot only. Page-level
  detection quality cannot be measured on this benchmark because its samples
  are HTML documents, not screenshots.

Writes ``evaluation/results/components/metrics.json``.

Run from the repository root:
    python -m evaluation.benchmark_components
"""

from __future__ import annotations

import base64
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.evaluate_pipeline import confusion, metrics_from_confusion  # noqa: E402

DATASET = ROOT / "evaluation" / "datasets" / "malaysia_eval_v1.jsonl"
SCREENSHOTS = ROOT / "visual_identity" / "data" / "reports" / "official_site_scans"
OUT = ROOT / "evaluation" / "results" / "components" / "metrics.json"


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))], 3)


def heuristics_only() -> dict:
    from services.heuristic_engine import analyze_url_heuristics

    samples = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    y_true, y_pred, timings = [], [], []
    for sample in samples:
        start = time.perf_counter()
        result = analyze_url_heuristics(sample["url"])
        timings.append((time.perf_counter() - start) * 1000)
        y_true.append(sample["label"])
        y_pred.append(1 if result["is_suspicious"] else 0)
    return {
        "rule": "block if any URL heuristic indicator is present",
        **metrics_from_confusion(confusion(y_true, y_pred)),
        "latency_ms": {"mean": round(statistics.mean(timings), 4), "p95": _percentile(timings, 95)},
    }


def visual_latency(runs: int = 10) -> dict:
    from services.visual_detector import VisualLogoDetector

    detector = VisualLogoDetector()
    images = sorted(SCREENSHOTS.glob("*.jpg"))
    if not images:
        return {"available": False, "reason": "no screenshots found"}
    payloads = ["data:image/jpeg;base64," + base64.b64encode(p.read_bytes()).decode() for p in images]
    detections, warning = detector.detect(payloads[0])  # warm-up and model load
    if warning:
        return {"available": False, "reason": warning}
    timings = []
    for _ in range(runs):
        for payload in payloads:
            start = time.perf_counter()
            detector.detect(payload)
            timings.append((time.perf_counter() - start) * 1000)
    return {
        "available": True,
        "screenshots": [p.name for p in images],
        "resolution": "1600x900",
        "calls": len(timings),
        "latency_ms": {"mean": round(statistics.mean(timings), 2), "p50": _percentile(timings, 50),
                       "p95": _percentile(timings, 95)},
        "note": "CPU inference including base64 decoding; page-level F1 not measurable on the HTML benchmark.",
        "logo_detection_validation": {"precision": 0.979, "recall": 0.996, "map50": 0.991,
                                      "source": "visual_identity/runs/phishguard_logo_yolov8n/results.csv, epoch 46"},
    }


def main() -> None:
    result = {"heuristics_only": heuristics_only(), "visual_yolov8n": visual_latency()}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
