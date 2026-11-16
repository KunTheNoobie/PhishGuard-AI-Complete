"""
PhishGuard-AI — End-to-End Pipeline Evaluation on the Malaysian Benchmark.
===========================================================================

Runs every sample of ``evaluation/datasets/malaysia_eval_v1.jsonl`` through
the **real** analysis endpoint (``POST /api/v1/analyze/semantics``) with the
**real** fine-tuned BERT model loaded, and reports:

* Pipeline verdict metrics (BLOCK_RENDER vs SAFE): confusion matrix,
  accuracy, precision, recall, F1-score, false-positive rate — overall,
  per split (dev / holdout) and per category.
* BERT-only metrics for three input formulations, plus ROC-AUC:
    - ``composite``     : ``"URL: <url> | <page text>"``
    - ``url_raw``       : the URL exactly as received
    - ``url_stripped``  : the URL without scheme / ``www.`` (the form used
                          in the Kaggle training corpus)
* In-process latency statistics for the endpoint (CPU inference).

Artefacts are written to ``evaluation/results/<tag>/``.

Run from the repository root:
    python -m evaluation.evaluate_pipeline --tag final
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any

# The benchmark issues >100 requests in a few seconds from one client, so the
# per-IP rate limit must be lifted for the evaluation run only.
os.environ.setdefault("PHISHGUARD_RATE_LIMIT", "100000/minute")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import aiosqlite  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

DATASET = ROOT / "evaluation" / "datasets" / "malaysia_eval_v1.jsonl"


# ----------------------------------------------------------------------
# Metric helpers (implemented directly so the script has no sklearn dependency)
# ----------------------------------------------------------------------

def confusion(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def metrics_from_confusion(cm: dict[str, int]) -> dict[str, Any]:
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        **cm,
        "n": total,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else 0.0,
    }


def roc_points(y_true: list[int], scores: list[float]) -> list[tuple[float, float]]:
    """Return (FPR, TPR) points for every distinct score threshold."""
    pos = sum(y_true)
    neg = len(y_true) - pos
    points = [(0.0, 0.0)]
    for threshold in sorted(set(scores), reverse=True):
        tp = sum(1 for t, s in zip(y_true, scores) if s >= threshold and t == 1)
        fp = sum(1 for t, s in zip(y_true, scores) if s >= threshold and t == 0)
        points.append((fp / neg if neg else 0.0, tp / pos if pos else 0.0))
    points.append((1.0, 1.0))
    return points


def auc(points: list[tuple[float, float]]) -> float:
    """Trapezoidal area under a list of (x, y) points sorted by x."""
    ordered = sorted(points)
    area = 0.0
    for (x0, y0), (x1, y1) in zip(ordered, ordered[1:]):
        area += (x1 - x0) * (y0 + y1) / 2.0
    return round(area, 4)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round(pct / 100.0 * (len(ordered) - 1))))
    return round(ordered[rank], 2)


def strip_scheme(url: str) -> str:
    out = url.split("://", 1)[-1]
    return out[4:] if out.startswith("www.") else out


# ----------------------------------------------------------------------
# Evaluation run
# ----------------------------------------------------------------------

async def run(tag: str, no_bert: bool = False) -> dict[str, Any]:
    from core.config import API_SECRET_TOKEN, MALICIOUS_THRESHOLD, APP_VERSION
    from database.init_db import SCHEMA_STATEMENTS, _INSERT_SEED, _SEED_MULE_ACCOUNTS
    from main import app
    from services.mule_scanner import MuleScanner
    from services.nlp_engine import SemanticEngine

    samples = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    out_dir = ROOT / "evaluation" / "results" / tag
    out_dir.mkdir(parents=True, exist_ok=True)

    # Fresh in-memory registry seeded exactly like production start-up.
    db = await aiosqlite.connect(":memory:")
    await db.execute("PRAGMA foreign_keys=ON;")
    for ddl in SCHEMA_STATEMENTS:
        await db.execute(ddl)
    for account in _SEED_MULE_ACCOUNTS:
        await db.execute(_INSERT_SEED, account)
    await db.commit()

    print("Loading the fine-tuned BERT model (real weights) ...")
    engine = SemanticEngine()
    engine.warm_up()

    app.state.db = db
    # Ablation: with ``--no-bert`` the endpoint runs without the BERT signal
    # (the engine is still used below to compute the BERT-only columns).
    app.state.semantic_engine = None if no_bert else engine
    app.state.mule_scanner = MuleScanner()
    app.state.cache = None
    app.state.simulator_running = False

    headers = {"Authorization": f"Bearer {API_SECRET_TOKEN}"}
    rows: list[dict[str, Any]] = []

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://eval") as client:
        for sample in samples:
            body = {
                "url": sample["url"],
                "dom_content": sample["html"],
            }
            started = time.perf_counter()
            resp = await client.post("/api/v1/analyze/semantics", json=body, headers=headers)
            wall_ms = (time.perf_counter() - started) * 1000.0
            if resp.status_code != 200:
                raise RuntimeError(f"{sample['id']} returned HTTP {resp.status_code}: {resp.text[:200]}")
            data = resp.json()
            sem = data["data"]["semantic_analysis"]
            mule = data["data"]["mule_scan"]

            def p_phish(text: str) -> float:
                res = engine._run_inference(text)  # noqa: SLF001 — evaluation only
                return res["confidence"] if res["label"] == "PHISHING" else round(1.0 - res["confidence"], 6)

            rows.append({
                "id": sample["id"],
                "split": sample["split"],
                "category": sample["category"],
                "label": sample["label"],
                "url": sample["url"],
                "form": sample["form"],
                "pipeline_verdict": data["orchestration"],
                "pipeline_pred": 1 if data["orchestration"] == "BLOCK_RENDER" else 0,
                "is_whitelisted": bool(data.get("is_whitelisted")),
                "endpoint_bert_label": sem["label"],
                "endpoint_bert_confidence": sem["confidence"],
                "mule_detected": bool(mule["mule_detected"]),
                "decision_rule": data.get("decision_rule") or "",
                "indicators": "; ".join(data.get("threat_indicators") or []),
                "p_composite": p_phish(f"URL: {sample['url']} | {sample['text']}"),
                "p_url_raw": p_phish(sample["url"]),
                "p_url_stripped": p_phish(strip_scheme(sample["url"])),
                "server_ms": data["meta"]["processing_time_ms"],
                "wall_ms": round(wall_ms, 2),
            })

    await db.close()
    engine.shutdown()

    y_true = [r["label"] for r in rows]

    def subset(pred_key: str, predicate) -> dict[str, Any]:
        sel = [r for r in rows if predicate(r)]
        return metrics_from_confusion(confusion([r["label"] for r in sel], [r[pred_key] for r in sel]))

    pipeline = {
        "overall": subset("pipeline_pred", lambda r: True),
        "dev": subset("pipeline_pred", lambda r: r["split"] == "dev"),
        "holdout": subset("pipeline_pred", lambda r: r["split"] == "holdout"),
        "per_category": {},
    }
    for category in sorted({r["category"] for r in rows}):
        sel = [r for r in rows if r["category"] == category]
        correct = sum(1 for r in sel if r["pipeline_pred"] == r["label"])
        pipeline["per_category"][category] = {
            "n": len(sel),
            "correct": correct,
            "blocked": sum(r["pipeline_pred"] for r in sel),
            "accuracy": round(correct / len(sel), 4),
        }

    bert_only: dict[str, Any] = {}
    roc_curves: dict[str, list[tuple[float, float]]] = {}
    for variant in ("composite", "url_raw", "url_stripped"):
        scores = [r[f"p_{variant}"] for r in rows]
        preds = [1 if s >= MALICIOUS_THRESHOLD else 0 for s in scores]
        curve = roc_points(y_true, scores)
        roc_curves[variant] = curve
        bert_only[variant] = {
            **metrics_from_confusion(confusion(y_true, preds)),
            "threshold": MALICIOUS_THRESHOLD,
            "roc_auc": auc(curve),
        }

    server_ms = [r["server_ms"] for r in rows]
    bert_path_ms = [r["server_ms"] for r in rows if not r["is_whitelisted"]]
    whitelist_ms = [r["server_ms"] for r in rows if r["is_whitelisted"]]
    latency = {
        "note": "In-process ASGI call, single client, CPU inference; excludes network.",
        "all_requests": {"n": len(server_ms), "mean": round(statistics.mean(server_ms), 2),
                         "p50": percentile(server_ms, 50), "p95": percentile(server_ms, 95),
                         "max": round(max(server_ms), 2)},
        "bert_path": {"n": len(bert_path_ms),
                      "mean": round(statistics.mean(bert_path_ms), 2) if bert_path_ms else 0.0,
                      "p50": percentile(bert_path_ms, 50), "p95": percentile(bert_path_ms, 95)},
        "whitelist_bypass": {"n": len(whitelist_ms),
                             "mean": round(statistics.mean(whitelist_ms), 2) if whitelist_ms else 0.0,
                             "p50": percentile(whitelist_ms, 50)},
    }

    import torch
    result = {
        "tag": tag,
        "app_version": APP_VERSION,
        "dataset": DATASET.name,
        "n_samples": len(rows),
        "n_malicious": sum(y_true),
        "n_legitimate": len(rows) - sum(y_true),
        "malicious_threshold": MALICIOUS_THRESHOLD,
        "device": "cuda" if torch.cuda.is_available() else "cpu",
        "bert_signal_enabled": not no_bert,
        "pipeline": pipeline,
        "rule_histogram": {
            rule: sum(1 for r in rows if r["decision_rule"] == rule)
            for rule in sorted({r["decision_rule"] for r in rows if r["decision_rule"]})
        },
        "bert_only": bert_only,
        "latency_ms": latency,
        "misclassified": [
            {"id": r["id"], "category": r["category"], "label": r["label"],
             "verdict": r["pipeline_verdict"], "url": r["url"]}
            for r in rows if r["pipeline_pred"] != r["label"]
        ],
    }

    (out_dir / "metrics.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out_dir / "per_sample.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    _plot(out_dir, result, roc_curves)
    _write_summary(out_dir, result)
    return result


def _plot(out_dir: Path, result: dict[str, Any], roc_curves: dict[str, list[tuple[float, float]]]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = result["pipeline"]["overall"]
    grid = [[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]]
    fig, ax = plt.subplots(figsize=(5.2, 4.4), dpi=160)
    ax.imshow(grid, cmap="Blues")
    ax.set_xticks([0, 1], labels=["Predicted SAFE", "Predicted BLOCK_RENDER"])
    ax.set_yticks([0, 1], labels=["Actual legitimate", "Actual malicious"])
    peak = max(max(row) for row in grid) or 1
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(grid[i][j]), ha="center", va="center", fontsize=16,
                    color="white" if grid[i][j] > peak / 2 else "black")
    ax.set_title(f"Pipeline confusion matrix — Malaysian benchmark (n={cm['n']})", fontsize=10)
    fig.tight_layout()
    fig.savefig(out_dir / "confusion_matrix_pipeline.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(5.4, 4.6), dpi=160)
    labels = {"composite": "URL + page text", "url_raw": "URL only (raw)", "url_stripped": "URL only (scheme stripped)"}
    for variant, curve in roc_curves.items():
        ordered = sorted(curve)
        ax.plot([p[0] for p in ordered], [p[1] for p in ordered],
                label=f"{labels[variant]} (AUC = {result['bert_only'][variant]['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey", linewidth=1, label="Chance")
    ax.set_xlabel("False-positive rate")
    ax.set_ylabel("True-positive rate")
    ax.set_title("BERT-only ROC curves — Malaysian benchmark", fontsize=10)
    ax.legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(out_dir / "roc_bert_only.png")
    plt.close(fig)


def _write_summary(out_dir: Path, result: dict[str, Any]) -> None:
    lines = [
        f"# Malaysian benchmark results — `{result['tag']}` (v{result['app_version']})",
        "",
        f"Samples: {result['n_samples']} ({result['n_malicious']} malicious, {result['n_legitimate']} legitimate). "
        f"Device: {result['device']}. BERT threshold: {result['malicious_threshold']}. "
        f"BERT signal in pipeline: {'enabled' if result.get('bert_signal_enabled', True) else 'DISABLED (ablation)'}.",
        "",
        "## Pipeline verdict (BLOCK_RENDER vs SAFE)",
        "",
        "| Split | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for split in ("overall", "dev", "holdout"):
        m = result["pipeline"][split]
        lines.append(f"| {split} | {m['n']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['accuracy']:.4f} | "
                     f"{m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['false_positive_rate']:.4f} |")
    lines += ["", "## Pipeline accuracy per category", "", "| Category | n | Correct | Blocked | Accuracy |", "|---|---|---|---|---|"]
    for cat, m in result["pipeline"]["per_category"].items():
        lines.append(f"| {cat} | {m['n']} | {m['correct']} | {m['blocked']} | {m['accuracy']:.4f} |")
    if result.get("rule_histogram"):
        lines += ["", "## Rule that produced each BLOCK_RENDER", "", "| Rule | Pages blocked |", "|---|---|"]
        for rule, count in result["rule_histogram"].items():
            lines.append(f"| {rule} | {count} |")
    lines += ["", "## BERT-only (no rule layer)", "",
              "| Input formulation | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |", "|---|---|---|---|---|---|---|"]
    for variant, m in result["bert_only"].items():
        lines.append(f"| {variant} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | "
                     f"{m['f1']:.4f} | {m['false_positive_rate']:.4f} | {m['roc_auc']:.4f} |")
    lat = result["latency_ms"]
    lines += ["", "## In-process latency (ms)", "",
              f"- All requests: mean {lat['all_requests']['mean']}, p50 {lat['all_requests']['p50']}, "
              f"p95 {lat['all_requests']['p95']}, max {lat['all_requests']['max']}",
              f"- BERT path (n={lat['bert_path']['n']}): mean {lat['bert_path']['mean']}, p50 {lat['bert_path']['p50']}, p95 {lat['bert_path']['p95']}",
              f"- Whitelist bypass (n={lat['whitelist_bypass']['n']}): mean {lat['whitelist_bypass']['mean']}",
              "", f"## Misclassified samples ({len(result['misclassified'])})", ""]
    for item in result["misclassified"]:
        kind = "false negative" if item["label"] == 1 else "false positive"
        lines.append(f"- {item['id']} ({item['category']}, {kind}): {item['url']}")
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[2])
    parser.add_argument("--tag", default="final", help="Sub-folder of evaluation/results/ to write to.")
    parser.add_argument("--no-bert", action="store_true",
                        help="Ablation: run the endpoint with the BERT signal disabled.")
    args = parser.parse_args()
    result = asyncio.run(run(args.tag, no_bert=args.no_bert))
    print(json.dumps({"pipeline": {k: result["pipeline"][k] for k in ("overall", "dev", "holdout")},
                      "per_category": result["pipeline"]["per_category"],
                      "bert_only": result["bert_only"], "latency_ms": result["latency_ms"]}, indent=1))
    print("Misclassified:")
    for item in result["misclassified"]:
        print("  ", item["id"], item["category"], "label", item["label"], item["verdict"], item["url"])


if __name__ == "__main__":
    main()
