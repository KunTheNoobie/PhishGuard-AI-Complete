"""
Objective 3 — PhishGuard-AI against standard baselines on the same benchmark.
==============================================================================

Reads the per-sample results of ``evaluate_pipeline`` (120 Malaysian pages)
and scores four detectors on identical inputs:

B1  Browser padlock rule     a page is "unsafe" only if it is not HTTPS — what
                             the address-bar lock icon tells a user.
B2  Lexical URL heuristics   flag any structural anomaly (raw IP, abused TLD,
                             punycode, deep or deceptive subdomains ...).
B3  BERT URL model alone     P(phishing) >= 0.75, the single-model baseline.
PG  PhishGuard-AI v4.0       the corroborated multi-signal pipeline (BLOCK_RENDER).

Reports confusion matrices, precision, recall, F1, false-positive rate,
ROC-AUC (for the scored detectors) and latency, and draws two figures.

    python -m evaluation.compare_baselines --tag final_v4.0.0
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.evaluate_pipeline import auc, confusion, metrics_from_confusion, roc_points  # noqa: E402
from services.heuristic_engine import analyze_url_heuristics  # noqa: E402

FIGURES = ROOT / "report" / "figures"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="final_v4.0.0")
    args = parser.parse_args()
    folder = ROOT / "evaluation" / "results" / args.tag
    rows = list(csv.DictReader((folder / "per_sample.csv").open(encoding="utf-8")))
    metrics = json.loads((folder / "metrics.json").read_text(encoding="utf-8"))
    y = [int(r["label"]) for r in rows]
    threshold = float(metrics["malicious_threshold"])

    p_bert = [float(r["p_url_stripped"]) for r in rows]
    detectors = {
        "B1 Browser padlock (HTTPS) rule": [1 if r["url"].startswith("http://") else 0 for r in rows],
        "B2 Lexical URL heuristics": [1 if analyze_url_heuristics(r["url"])["is_suspicious"] else 0 for r in rows],
        "B3 BERT URL model alone": [1 if p >= threshold else 0 for p in p_bert],
        "PG PhishGuard-AI v4.0 pipeline": [int(r["pipeline_pred"]) for r in rows],
    }
    result = {"dataset": metrics["dataset"], "n": len(rows), "n_phishing": sum(y), "threshold": threshold, "detectors": {}}
    for name, pred in detectors.items():
        result["detectors"][name] = metrics_from_confusion(confusion(y, pred))

    roc_bert = roc_points(y, p_bert)
    roc_pg = roc_points(y, [float(r["risk_score"]) for r in rows])
    result["detectors"]["B3 BERT URL model alone"]["roc_auc"] = auc(roc_bert)
    result["detectors"]["PG PhishGuard-AI v4.0 pipeline"]["roc_auc"] = auc(roc_pg)
    result["detectors"]["PG PhishGuard-AI v4.0 pipeline"]["warnings_on_phishing"] = sum(
        1 for r in rows if r["label"] == "1" and r["pipeline_verdict"] == "WARNING")
    result["detectors"]["PG PhishGuard-AI v4.0 pipeline"]["warnings_on_legitimate"] = sum(
        1 for r in rows if r["label"] == "0" and r["pipeline_verdict"] == "WARNING")
    # The benchmark over-represents plain-HTTP phishing; in the wild most phishing
    # sites use HTTPS (APWG).  Recall on the HTTPS-only phishing pages shows what
    # each detector adds once the padlock is present.
    https_phish = [i for i, r in enumerate(rows) if r["label"] == "1" and r["url"].startswith("https://")]
    result["https_phishing_subset"] = {
        "n": len(https_phish),
        "recall": {name: round(sum(pred[i] for i in https_phish) / len(https_phish), 4) for name, pred in detectors.items()},
    }
    result["latency_ms"] = metrics["latency_ms"]
    (folder / "baselines.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    for name, m in result["detectors"].items():
        print(f"{name:34} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
              f"FPR={m['false_positive_rate']:.3f} AUC={m.get('roc_auc', '-')}  TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    print("HTTPS-only phishing subset:", result["https_phishing_subset"])
    draw(result, roc_bert, roc_pg)


def draw(result: dict, roc_bert, roc_pg) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "Times New Roman", "font.size": 11})
    names = list(result["detectors"])
    short = ["Padlock\n(HTTPS only)", "Lexical URL\nheuristics", "BERT URL\nmodel alone", "PhishGuard-AI\nv4.0 pipeline"]
    keys = [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1-score"), ("false_positive_rate", "False-positive rate")]
    colours = ["#1f3b73", "#3b82f6", "#16a34a", "#dc2626"]
    fig, ax = plt.subplots(figsize=(8.2, 4.2), dpi=300)
    width = 0.2
    for i, (key, label) in enumerate(keys):
        values = [result["detectors"][n][key] for n in names]
        bars = ax.bar([x + (i - 1.5) * width for x in range(len(names))], values, width, label=label, color=colours[i])
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 0.015, f"{value:.2f}", ha="center", fontsize=7.5)
    ax.set_xticks(range(len(names)), short)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score on 120-page Malaysian benchmark")
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.13), frameon=False, fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIGURES / "baseline_comparison.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(5.2, 4.6), dpi=300)
    ax.plot([p[0] for p in roc_bert], [p[1] for p in roc_bert], color="#16a34a",
            label=f"BERT URL model alone (AUC {result['detectors']['B3 BERT URL model alone']['roc_auc']:.3f})")
    ax.plot([p[0] for p in roc_pg], [p[1] for p in roc_pg], color="#dc2626",
            label=f"PhishGuard-AI pipeline (AUC {result['detectors']['PG PhishGuard-AI v4.0 pipeline']['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="#94a3b8", linewidth=1)
    ax.set_xlabel("False-positive rate")
    ax.set_ylabel("True-positive rate")
    ax.legend(loc="lower right", fontsize=9, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIGURES / "roc_pipeline_vs_bert.png")
    plt.close(fig)


if __name__ == "__main__":
    main()
