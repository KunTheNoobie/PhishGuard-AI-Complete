"""
PhishGuard-AI — Kaggle Hold-out Metrics Reconstruction.
========================================================

The Colab fine-tuning run evaluated the model once, at the end of its
single epoch, on the 20 % hold-out split (109,870 URLs) and logged
accuracy, precision, recall and F1 in ``trainer_state.json``.  The run did
not save the confusion matrix itself.

Because the four logged metrics and the split size are exact, the four
confusion-matrix cells are uniquely determined.  This script solves for
them, verifies that they reproduce every logged metric to nine decimal
places, and writes the matrix as JSON and PNG.

No ROC-AUC is reported for this split: the per-sample scores were not
saved and the Kaggle CSV is not redistributed with the repository.

Run from the repository root:
    python -m evaluation.kaggle_holdout_metrics
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRAINER_STATE = ROOT / "phishguard_custom_model" / "checkpoint-27468" / "trainer_state.json"
OUT_DIR = ROOT / "evaluation" / "results" / "kaggle_holdout"
HOLDOUT_SIZE = 109_870  # "Map: 109870 examples" in the Colab notebook output

# Values logged by the Trainer; kept here so the script still documents the
# result when the (git-ignored) checkpoint folder is absent.
LOGGED_FALLBACK = {
    "eval_accuracy": 0.987630836443069,
    "eval_f1": 0.9780079294441297,
    "eval_precision": 0.9876777251184834,
    "eval_recall": 0.968525641025641,
    "eval_loss": 0.04966192692518234,
    "step": 27468,
}


def load_logged_metrics() -> dict:
    if TRAINER_STATE.is_file():
        state = json.loads(TRAINER_STATE.read_text(encoding="utf-8"))
        final = [entry for entry in state["log_history"] if "eval_accuracy" in entry][-1]
        return {key: final[key] for key in LOGGED_FALLBACK}
    return dict(LOGGED_FALLBACK)


def reconstruct(logged: dict, n: int) -> dict:
    """Search for the integer (TP, FP, FN, TN) consistent with the logged metrics."""
    correct = round(logged["eval_accuracy"] * n)
    best = None
    for positives in range(1, n):
        tp = round(logged["eval_recall"] * positives)
        if tp == 0 or abs(tp / positives - logged["eval_recall"]) > 1e-9:
            continue
        predicted_pos = round(tp / logged["eval_precision"])
        fp = predicted_pos - tp
        if fp < 0 or abs(tp / (tp + fp) - logged["eval_precision"]) > 1e-9:
            continue
        fn = positives - tp
        tn = n - tp - fp - fn
        if tn < 0 or tp + tn != correct:
            continue
        best = {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
        break
    if best is None:
        raise RuntimeError("No integer confusion matrix reproduces the logged metrics.")
    return best


def main() -> None:
    logged = load_logged_metrics()
    cm = reconstruct(logged, HOLDOUT_SIZE)
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    derived = {
        "accuracy": (tp + tn) / HOLDOUT_SIZE,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall),
        "false_positive_rate": fp / (fp + tn),
        "false_negative_rate": fn / (fn + tp),
        "specificity": tn / (tn + fp),
    }
    checks = {
        "accuracy": abs(derived["accuracy"] - logged["eval_accuracy"]),
        "precision": abs(derived["precision"] - logged["eval_precision"]),
        "recall": abs(derived["recall"] - logged["eval_recall"]),
        "f1": abs(derived["f1"] - logged["eval_f1"]),
    }
    assert all(delta < 1e-9 for delta in checks.values()), checks

    result = {
        "source": "Colab fine-tuning run, epoch 1.0 evaluation (trainer_state.json)",
        "holdout_size": HOLDOUT_SIZE,
        "optimisation_steps": logged["step"],
        "eval_loss": logged["eval_loss"],
        "logged_metrics": {k: logged[k] for k in ("eval_accuracy", "eval_precision", "eval_recall", "eval_f1")},
        "confusion_matrix": cm,
        "class_support": {"phishing": tp + fn, "legitimate": tn + fp},
        "derived_metrics": {k: round(v, 6) for k, v in derived.items()},
        "max_abs_reconstruction_error": max(checks.values()),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    grid = [[tn, fp], [fn, tp]]
    fig, ax = plt.subplots(figsize=(5.4, 4.4), dpi=160)
    ax.imshow(grid, cmap="Blues")
    ax.set_xticks([0, 1], labels=["Predicted legitimate", "Predicted phishing"])
    ax.set_yticks([0, 1], labels=["Actual legitimate", "Actual phishing"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{grid[i][j]:,}", ha="center", va="center", fontsize=14,
                    color="white" if grid[i][j] > 40_000 else "black")
    ax.set_title(f"BERT URL classifier — Kaggle hold-out (n = {HOLDOUT_SIZE:,})", fontsize=10)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "confusion_matrix_kaggle_holdout.png")
    plt.close(fig)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
