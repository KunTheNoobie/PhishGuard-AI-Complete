"""
PhishGuard-AI — Dissertation Figure Generator.
===============================================

Regenerates every evaluation and design figure used in Chapters 4 and 5 of
the dissertation from the committed result files, so each figure can be
traced to data.  Output: ``report/figures/*.png``.

Run from the repository root (after the evaluation scripts):
    python -m evaluation.make_report_figures
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "evaluation" / "results"
OUT = ROOT / "report" / "figures"

INK = "#1f2937"
BLUE, ORANGE, GREEN, RED, GREY = "#2563eb", "#ea580c", "#059669", "#dc2626", "#6b7280"


def _load(tag: str) -> dict:
    return json.loads((RESULTS / tag / "metrics.json").read_text(encoding="utf-8"))


def fig_training_loss() -> None:
    state_path = ROOT / "phishguard_custom_model" / "checkpoint-27468" / "trainer_state.json"
    if not state_path.is_file():
        print("  (skipped training-loss figure: checkpoint folder not present)")
        return
    history = json.loads(state_path.read_text(encoding="utf-8"))["log_history"]
    steps = [h["step"] for h in history if "loss" in h]
    loss = [h["loss"] for h in history if "loss" in h]
    final = [h for h in history if "eval_loss" in h][-1]
    fig, ax = plt.subplots(figsize=(7.2, 3.8), dpi=170)
    ax.plot(steps, loss, color=BLUE, linewidth=1.6, label="Training loss (logged every 500 steps)")
    ax.scatter([final["step"]], [final["eval_loss"]], color=ORANGE, zorder=5,
               label=f"Validation loss at epoch end = {final['eval_loss']:.4f}")
    ax.set_xlabel("Optimisation step (batch size 16)")
    ax.set_ylabel("Cross-entropy loss")
    ax.set_title("BERT fine-tuning loss, 1 epoch / 27,468 steps (Colab, Tesla T4)", fontsize=10)
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig_bert_training_loss.png")
    plt.close(fig)


def fig_baseline_vs_final() -> None:
    runs = [("Baseline v3.0.0", _load("baseline_v3.0.0"), GREY),
            ("v3.2.0 without BERT (ablation)", _load("ablation_no_bert_v3.2.0"), ORANGE),
            ("Final v3.2.0", _load("final_v3.2.0"), BLUE)]
    metrics = [("accuracy", "Accuracy"), ("precision", "Precision"), ("recall", "Recall"),
               ("f1", "F1-score"), ("false_positive_rate", "False-positive rate")]
    fig, ax = plt.subplots(figsize=(7.6, 4.0), dpi=170)
    width = 0.26
    for idx, (label, data, colour) in enumerate(runs):
        values = [data["pipeline"]["overall"][key] * 100 for key, _ in metrics]
        xs = [i + (idx - 1) * width for i in range(len(metrics))]
        bars = ax.bar(xs, values, width, label=label, color=colour)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 1.2, f"{value:.1f}", ha="center", fontsize=6.5)
    ax.set_xticks(range(len(metrics)), [name for _, name in metrics], fontsize=8.5)
    ax.set_ylabel("Percent")
    ax.set_ylim(0, 112)
    ax.set_title("End-to-end verdict quality on the Malaysian benchmark (n = 120)", fontsize=10)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(fontsize=8, loc="upper center", ncol=3, frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "fig_benchmark_baseline_vs_final.png")
    plt.close(fig)


def fig_category_accuracy() -> None:
    base, final = _load("baseline_v3.0.0"), _load("final_v3.2.0")
    cats = list(final["pipeline"]["per_category"].keys())
    labels = [c.split("_", 1)[0] + " " + c.split("_", 1)[1].replace("_", " ") for c in cats]
    fig, ax = plt.subplots(figsize=(7.6, 4.0), dpi=170)
    ys = range(len(cats))
    ax.barh([y + 0.2 for y in ys], [base["pipeline"]["per_category"][c]["accuracy"] * 100 for c in cats],
            0.38, color=GREY, label="Baseline v3.0.0")
    ax.barh([y - 0.2 for y in ys], [final["pipeline"]["per_category"][c]["accuracy"] * 100 for c in cats],
            0.38, color=BLUE, label="Final v3.2.0")
    ax.set_yticks(list(ys), labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Correct verdicts (%)")
    ax.set_xlim(0, 105)
    ax.set_title("Verdict accuracy per benchmark category (L = legitimate, P = malicious)", fontsize=10)
    ax.grid(axis="x", alpha=0.25)
    ax.legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(OUT / "fig_benchmark_per_category.png")
    plt.close(fig)


def fig_locust() -> None:
    rows = list(csv.DictReader((RESULTS / "locust" / "run_50u_stats.csv").open(encoding="utf-8")))
    rows = [r for r in rows if r["Name"] != "Aggregated"]
    names = [r["Name"].replace("/analyze/semantics ", "analyze ") for r in rows]
    fig, ax = plt.subplots(figsize=(7.6, 4.0), dpi=170)
    width = 0.26
    for idx, (col, label, colour) in enumerate([("50%", "p50", GREEN), ("95%", "p95", ORANGE), ("99%", "p99", RED)]):
        values = [float(r[col]) for r in rows]
        xs = [i + (idx - 1) * width for i in range(len(rows))]
        bars = ax.bar(xs, values, width, label=label, color=colour)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 8, f"{value:.0f}", ha="center", fontsize=6.5)
    ax.set_xticks(range(len(rows)), names, fontsize=7, rotation=18, ha="right")
    ax.set_ylabel("Response time (ms)")
    ax.set_title("Locust: 50 concurrent users, 60 s, CPU inference — 1,333 requests, 0 failures", fontsize=10)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig_locust_50_users.png")
    plt.close(fig)


def fig_sequence() -> None:
    actors = ["Content\nscript", "Service\nworker", "FastAPI\ngateway", "Sanitiser", "BERT engine\n(worker thread)",
              "Mule\nscanner", "SQLite\n(WAL)", "Verdict\nengine", "SSE hub /\ndashboard"]
    xs = {i: 0.7 + i * 1.02 for i in range(len(actors))}
    msgs = [
        (0, 1, "1. PHISHGUARD_ANALYZE {url, DOM}", False),
        (1, 2, "2. POST /api/v1/analyze/semantics\n   Bearer key · 8 s AbortController timeout", False),
        (2, 2, "3. verify key (401) · 60/min limit (429)\n   · Pydantic validation (422)", False),
        (2, 3, "4. sanitize_dom(HTML)", False),
        (3, 2, "visible text", True),
        (2, 2, "5. whitelist lookup (trusted → skip BERT)", False),
        (2, 4, "6. predict(strip_scheme(url))  ‖ asyncio.gather", False),
        (2, 5, "7. scan_and_verify(text)  ‖", False),
        (5, 6, "8. SELECT … WHERE account_number IN (?)", False),
        (6, 5, "flagged rows", True),
        (5, 2, "accounts_extracted, flagged_accounts", True),
        (4, 2, "9. {label, confidence}  (max_length 128, softmax)", True),
        (2, 7, "10. decide(signals): brand tiers, URL heuristics,\n    credential form, scam lexicon → rules R1–R6", False),
        (7, 2, "verdict, rule, indicators, risk score", True),
        (2, 6, "11. if BLOCK: INSERT threat_telemetry", False),
        (2, 8, "12. broadcast new_threat (once)", False),
        (2, 1, "13. 200 AnalysisResponse {orchestration, threat_indicators}", True),
        (1, 0, "14. BLOCK_RENDER → full-screen shield · SAFE → badge OK", True),
    ]
    height = 0.80 * len(msgs) + 2.6
    fig, ax = plt.subplots(figsize=(9.6, height * 0.60), dpi=220)
    ax.set_xlim(0, xs[len(actors) - 1] + 0.75)
    ax.set_ylim(-height + 1.0, 1.1)
    ax.axis("off")
    for i, name in enumerate(actors):
        ax.add_patch(FancyBboxPatch((xs[i] - 0.46, 0.25), 0.92, 0.7, boxstyle="round,pad=0.03",
                                    fc="#e0e7ff", ec=BLUE, lw=1))
        ax.text(xs[i], 0.6, name, ha="center", va="center", fontsize=7.8, color=INK)
        ax.plot([xs[i], xs[i]], [0.25, -height + 1.3], color="#9ca3af", lw=0.8, ls="--")
    y = -0.35
    for src, dst, label, is_return in msgs:
        colour = GREY if is_return else INK
        style = "--" if is_return else "-"
        if src == dst:
            x = xs[src]
            ax.plot([x, x + 0.42, x + 0.42, x], [y, y, y - 0.26, y - 0.26], color=colour, lw=0.9)
            ax.annotate("", xy=(x, y - 0.26), xytext=(x + 0.12, y - 0.26),
                        arrowprops=dict(arrowstyle="->", color=colour, lw=0.9))
            ax.text(x + 0.5, y - 0.13, label, fontsize=7.4, va="center", color=colour)
        else:
            ax.annotate("", xy=(xs[dst], y), xytext=(xs[src], y),
                        arrowprops=dict(arrowstyle="->", color=colour, lw=0.9, ls=style))
            ax.text((xs[src] + xs[dst]) / 2, y + 0.06, label, fontsize=7.4, ha="center", va="bottom", color=colour)
        y -= 0.80
    ax.text(xs[0] - 0.55, y - 0.05,
            "alt  [backend unreachable or timeout]: service worker runs offline heuristics (fail-safe) and marks the result as degraded.",
            fontsize=7.4, color=RED, va="top")
    fig.savefig(OUT / "fig_sequence_analysis_pipeline.png", bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)


def fig_erd() -> None:
    tables = {
        "mule_registry": (0.4, [
            "PK  id               INTEGER  AUTOINCREMENT",
            "UQ  account_number   TEXT     NOT NULL",
            "    bank_name        TEXT     NOT NULL",
            "    platform_flagged TEXT     NOT NULL  DEFAULT 'manual_entry'",
            "    report_count     INTEGER  NOT NULL  CHECK (>= 0)",
            "    date_added       TEXT     NOT NULL  (ISO-8601 UTC)",
        ]),
        "mule_reports": (6.6, [
            "PK  report_id        INTEGER  AUTOINCREMENT",
            "    account_number   TEXT     NOT NULL  CHECK (length 6–34)",
            "    bank_name        TEXT     NOT NULL  DEFAULT 'Unknown'",
            "    source           TEXT     NOT NULL  DEFAULT 'extension'",
            "    page_url         TEXT     NULL",
            "    status           TEXT     CHECK IN (PENDING, APPROVED, REJECTED)",
            "FK  registry_id      INTEGER  NULL → mule_registry.id  ON DELETE SET NULL",
            "    created_at       TEXT     NOT NULL  (ISO-8601 UTC)",
            "    reviewed_at      TEXT     NULL",
        ]),
        "threat_telemetry": (0.4, [
            "PK  log_id           INTEGER  AUTOINCREMENT",
            "    malicious_url    TEXT     NOT NULL",
            "    bert_score       REAL     NOT NULL  CHECK (0.0–1.0)",
            "    timestamp        TEXT     NOT NULL  (ISO-8601 UTC)",
        ]),
    }
    tops = {"mule_registry": 6.9, "mule_reports": 6.9, "threat_telemetry": 3.5}
    fig, ax = plt.subplots(figsize=(10.2, 5.6), dpi=220)
    ax.set_xlim(0, 13.6)
    ax.set_ylim(0, 7.4)
    ax.axis("off")
    for name, (x, rows) in tables.items():
        top = tops[name]
        h = 0.36 * (len(rows) + 1) + 0.1
        bw = 6.7 if name == "mule_reports" else 5.9
        ax.add_patch(FancyBboxPatch((x, top - h), bw, h, boxstyle="round,pad=0.02", fc="white", ec=BLUE, lw=1.2))
        ax.add_patch(FancyBboxPatch((x, top - 0.42), bw, 0.42, boxstyle="round,pad=0.02", fc="#e0e7ff", ec=BLUE, lw=1.2))
        ax.text(x + bw / 2, top - 0.21, name, ha="center", va="center", fontsize=10, fontweight="bold", color=INK)
        for i, row in enumerate(rows):
            ax.text(x + 0.12, top - 0.66 - i * 0.36, row, fontsize=6.3, family="monospace", va="center", color=INK)
    ax.annotate("", xy=(6.3, 6.25), xytext=(6.6, 4.08),
                arrowprops=dict(arrowstyle="-|>", color=ORANGE, lw=1.4, connectionstyle="arc3,rad=0"))
    ax.text(6.45, 3.95, "0..N reports reference 0..1 registry row", fontsize=8, color=ORANGE, ha="right")
    ax.text(0.4, 0.55,
            "Indexes: idx_mule_account_number (account_number) · idx_telemetry_malicious_url (malicious_url) · "
            "idx_telemetry_timestamp (timestamp)\n"
            "         idx_mule_reports_status (status, created_at) · idx_mule_reports_registry_id (registry_id)      "
            "PRAGMA journal_mode = WAL; foreign_keys = ON",
            fontsize=7.3, family="monospace", color=GREY)
    fig.savefig(OUT / "fig_database_schema_erd.png", bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig_training_loss()
    fig_baseline_vs_final()
    fig_category_accuracy()
    fig_locust()
    fig_sequence()
    fig_erd()
    for src, name in [
        (RESULTS / "kaggle_holdout" / "confusion_matrix_kaggle_holdout.png", "fig_confusion_kaggle_holdout.png"),
        (RESULTS / "final_v3.2.0" / "confusion_matrix_pipeline.png", "fig_confusion_pipeline_final.png"),
        (RESULTS / "baseline_v3.0.0" / "confusion_matrix_pipeline.png", "fig_confusion_pipeline_baseline.png"),
        (RESULTS / "final_v3.2.0" / "roc_bert_only.png", "fig_roc_bert_only.png"),
    ]:
        shutil.copyfile(src, OUT / name)
    print("Figures written to", OUT)
    for path in sorted(OUT.glob("*.png")):
        print("  ", path.name)


if __name__ == "__main__":
    main()
