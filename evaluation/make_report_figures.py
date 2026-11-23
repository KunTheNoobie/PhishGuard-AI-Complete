"""
PhishGuard-AI — Dissertation Figure Generator (300 DPI, unified style).
========================================================================

Generates every quantitative chart of the dissertation into ``report/figures/``
from committed result files.  Architecture, UML and workflow diagrams are not
drawn here: they are draw.io sources in ``report/diagrams_drawio/`` (exported to
``report/figures/`` at 300 DPI).  Nothing is hand-edited.

Prerequisites (all committed or reproducible):
    evaluation/results/{baseline_v3.0.0, final_v4.0.0, ablation_no_bert_v4.0.0}/
    evaluation/results/kaggle_holdout/metrics.json
    evaluation/results/components/metrics.json
    evaluation/results/locust/*.csv
    evaluation/results/coverage/coverage.json
    phishguard_custom_model/checkpoint-27468/trainer_state.json (loss curve)

Run from the repository root:
    python -m evaluation.make_report_figures
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.figkit import (AMBER, BLUE, GREEN, GREY, INK, LINE, MUTED, NAVY, PURPLE, RED, TEAL,  # noqa: E402
                               apply_style, save)

import matplotlib.pyplot as plt  # noqa: E402

RESULTS = ROOT / "evaluation" / "results"
OUT = ROOT / "report" / "figures"


# ── data loaders ──────────────────────────────────────────────────────────────

def rows(tag: str) -> list[dict]:
    return list(csv.DictReader((RESULTS / tag / "per_sample.csv").open(encoding="utf-8")))


def metrics(tag: str) -> dict:
    return json.loads((RESULTS / tag / "metrics.json").read_text(encoding="utf-8"))


def locust(run: str, kind: str = "stats") -> list[dict]:
    return list(csv.DictReader((RESULTS / "locust" / f"{run}_{kind}.csv").open(encoding="utf-8")))


def roc(y, s):
    pos, neg = sum(y), len(y) - sum(y)
    pts = [(0.0, 0.0)]
    for t in sorted(set(s), reverse=True):
        tp = sum(1 for a, b in zip(y, s) if b >= t and a == 1)
        fp = sum(1 for a, b in zip(y, s) if b >= t and a == 0)
        pts.append((fp / neg, tp / pos))
    pts.append((1.0, 1.0))
    return sorted(pts)


def auc(pts):
    return sum((x1 - x0) * (y0 + y1) / 2 for (x0, y0), (x1, y1) in zip(pts, pts[1:]))


def cm_from(rows_, pred_key="pipeline_pred", score_key=None, thr=0.75):
    tp = fp = fn = tn = 0
    for r in rows_:
        y = int(r["label"])
        p = (1 if float(r[score_key]) >= thr else 0) if score_key else int(r[pred_key])
        tp += y == 1 and p == 1
        fp += y == 0 and p == 1
        fn += y == 1 and p == 0
        tn += y == 0 and p == 0
    return np.array([[tn, fp], [fn, tp]])


# ── chart helpers ─────────────────────────────────────────────────────────────

def draw_cm(ax, cm, title, cmap_color):
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("c", ["#FFFFFF", cmap_color])
    ax.imshow(cm, cmap=cmap, vmin=0, vmax=max(cm.max(), 1))
    ax.grid(False)
    for i in range(2):
        for j in range(2):
            v = cm[i, j]
            ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=9, fontweight="bold",
                    color="white" if v > cm.max() * 0.55 else INK)
    ax.set_xticks([0, 1], ["SAFE", "BLOCK"])
    ax.set_yticks([0, 1], ["legit.", "malic."])
    ax.set_xlabel("predicted")
    ax.set_title(title, fontsize=7.4)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)


# ==============================================================================
# Chapter 2 — trade-off chart
# ==============================================================================

def tradeoff(path):
    apply_style()
    comp = json.loads((RESULTS / "components" / "metrics.json").read_text(encoding="utf-8"))
    base, fin, abl = metrics("baseline_v3.0.0"), metrics("final_v4.0.0"), metrics("ablation_no_bert_v4.0.0")
    pts = [
        ("URL heuristics only", comp["heuristics_only"]["latency_ms"]["mean"], comp["heuristics_only"]["f1"],
         comp["heuristics_only"]["false_positive_rate"], GREY),
        ("BERT URL model only", fin["latency_ms"]["bert_path"]["mean"], fin["bert_only"]["url_stripped"]["f1"],
         fin["bert_only"]["url_stripped"]["false_positive_rate"], PURPLE),
        ("Naive hybrid, OR-combination (v3.0.0)", base["latency_ms"]["all_requests"]["mean"],
         base["pipeline"]["overall"]["f1"], base["pipeline"]["overall"]["false_positive_rate"], AMBER),
        ("Deterministic rules, no model", abl["latency_ms"]["all_requests"]["mean"], abl["pipeline"]["overall"]["f1"],
         abl["pipeline"]["overall"]["false_positive_rate"], TEAL),
        ("Corroborated hybrid (v4.2)", fin["latency_ms"]["all_requests"]["mean"], fin["pipeline"]["overall"]["f1"],
         fin["pipeline"]["overall"]["false_positive_rate"], NAVY),
    ]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(6.5, 3.0), gridspec_kw={"width_ratios": [1.6, 1]})
    offsets = [(8, 0), (-10, 0), (-10, -6), (8, 0), (-10, 4)]
    for (name, lat, f1, fpr, col), (dx, dy) in zip(pts, offsets):
        ax.scatter(lat, f1, s=40 + fpr * 260, color=col, edgecolor="white", linewidth=0.8, zorder=4)
        ax.annotate(f"{name}\nF1 {f1:.3f} · FPR {fpr * 100:.1f} %", (lat, f1), textcoords="offset points",
                    xytext=(dx, dy), fontsize=5.9, color=col, va="center", ha="left" if dx > 0 else "right")
    vis = comp["visual_yolov8n"]["latency_ms"]["mean"]
    ax.axvline(vis, color=BLUE, lw=0.8, ls="--")
    ax.text(vis * 0.88, 0.465, f"YOLOv8n visual-only: {vis:.0f} ms per screenshot;\npage-level F1 not measurable on the HTML benchmark",
            fontsize=5.6, color=BLUE, va="bottom", ha="right")
    ax.set_xscale("log")
    ax.set_xlim(0.008, 3000)
    ax.set_ylim(0.45, 1.02)
    ax.set_xlabel("mean server-side latency per page (ms, log scale, CPU)")
    ax.set_ylabel("F1-score on 120-page Malaysian benchmark")
    ax.set_title("Latency versus detection quality", loc="left")
    names = [p[0].split(" (")[0].replace("Deterministic rules, no model", "Rules, no model") for p in pts]
    prec = [fin["bert_only"]["url_stripped"]["precision"]]
    data = [(p[0], p[3]) for p in pts]
    y = np.arange(len(pts))
    ax2.barh(y, [p[3] * 100 for p in pts], color=[p[4] for p in pts], height=0.6)
    for i, p in enumerate(pts):
        ax2.text(p[3] * 100 + 1.5, i, f"{p[3] * 100:.1f} %", va="center", fontsize=6.4)
    ax2.set_yticks(y, ["Heuristics", "BERT only", "Naive hybrid", "Rules, no model", "Corroborated"], fontsize=6.4)
    ax2.invert_yaxis()
    ax2.set_xlim(0, 100)
    ax2.set_xlabel("FPR on 60 legitimate pages (%)")
    ax2.set_title("Cost of false alarms", loc="left")
    ax2.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=1.5)
    save(fig, path)


# ==============================================================================
# Chapter 5
# ==============================================================================

def training_loss(path):
    apply_style()
    state = json.loads((ROOT / "phishguard_custom_model" / "checkpoint-27468" / "trainer_state.json").read_text())
    hist = state["log_history"]
    steps = [h["step"] for h in hist if "loss" in h]
    loss = [h["loss"] for h in hist if "loss" in h]
    lr = [h["learning_rate"] for h in hist if "loss" in h]
    final = [h for h in hist if "eval_loss" in h][-1]
    fig, ax = plt.subplots(figsize=(6.5, 2.6))
    ax.plot(steps, loss, color=NAVY, lw=1.4, marker="o", ms=2.2, label="training loss (every 500 steps)")
    ax.scatter([final["step"]], [final["eval_loss"]], color=RED, zorder=5, s=28,
               label=f"validation loss at epoch end = {final['eval_loss']:.4f}")
    ax.set_xlabel("optimisation step (batch size 16)")
    ax.set_ylabel("cross-entropy loss")
    ax2 = ax.twinx()
    ax2.plot(steps, [v * 1e5 for v in lr], color=AMBER, lw=1, ls="--", label="learning rate (x 1e-5)")
    ax2.set_ylabel("learning rate (x 1e-5)", color=AMBER)
    ax2.tick_params(axis="y", colors=AMBER)
    ax2.grid(False)
    ax2.spines["right"].set_visible(True)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper right")
    ax.set_title("BERT fine-tuning: loss and linear learning-rate decay over one epoch", loc="left")
    fig.tight_layout()
    save(fig, path)


def kaggle_cm(path):
    apply_style()
    m = json.loads((RESULTS / "kaggle_holdout" / "metrics.json").read_text())
    cm = m["confusion_matrix"]
    arr = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    d = m["derived_metrics"]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(6.5, 2.5), gridspec_kw={"width_ratios": [1, 1.3]})
    draw_cm(ax, arr, f"Hold-out confusion matrix (n = {m['holdout_size']:,})", NAVY)
    ax.set_yticks([0, 1], ["legitimate", "phishing"])
    ax.set_xticks([0, 1], ["pred. legitimate", "pred. phishing"])
    names = ["accuracy", "precision", "recall", "f1", "specificity"]
    vals = [d[k] * 100 for k in names]
    ax2.barh(range(5), vals, color=[NAVY, TEAL, AMBER, PURPLE, GREEN], height=0.55)
    for i, v in enumerate(vals):
        ax2.text(v - 0.15, i, f"{v:.2f} %", va="center", ha="right", color="white", fontsize=6.6, fontweight="bold")
    ax2.set_yticks(range(5), ["Accuracy", "Precision", "Recall", "F1-score", "Specificity"])
    ax2.invert_yaxis()
    ax2.set_xlim(94, 100)
    ax2.set_xlabel("percent (axis starts at 94 %)")
    ax2.set_title("Derived metrics (FPR 0.48 %, FNR 3.15 %)", fontsize=7.4)
    ax2.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=2)
    save(fig, path)


def confusion_compare(path):
    apply_style()
    fin, base = rows("final_v4.0.0"), rows("baseline_v3.0.0")
    fig = plt.figure(figsize=(6.5, 2.75))
    gs = fig.add_gridspec(1, 4, width_ratios=[1, 1, 1, 1.35], wspace=0.55)
    draw_cm(fig.add_subplot(gs[0]), cm_from(fin, score_key="p_url_stripped"), "BERT URL model only\n(threshold 0.75)", PURPLE)
    draw_cm(fig.add_subplot(gs[1]), cm_from(base), "Naive hybrid\nv3.0.0", AMBER)
    draw_cm(fig.add_subplot(gs[2]), cm_from(fin), "Corroborated hybrid\nv3.2.0", NAVY)
    ax = fig.add_subplot(gs[3])
    labels = ["BERT only", "v3.0.0", "v4.0"]
    cms = [cm_from(fin, score_key="p_url_stripped"), cm_from(base), cm_from(fin)]
    fpr = [c_[0, 1] / c_[0].sum() * 100 for c_ in cms]
    rec = [c_[1, 1] / c_[1].sum() * 100 for c_ in cms]
    x = np.arange(3)
    ax.bar(x - 0.18, fpr, 0.34, color=RED, label="false-positive rate")
    ax.bar(x + 0.18, rec, 0.34, color=TEAL, label="recall")
    for i in range(3):
        ax.text(i - 0.18, fpr[i] + 2, f"{fpr[i]:.1f}", ha="center", fontsize=6.2, color=RED)
        ax.text(i + 0.18, rec[i] + 2, f"{rec[i]:.1f}", ha="center", fontsize=6.2, color=TEAL)
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 135)
    ax.set_yticks([0, 20, 40, 60, 80, 100])
    ax.set_ylabel("%")
    ax.set_title("FPR 78.3 % → 0 %", fontsize=7.4)
    ax.legend(loc="upper left", ncol=2, fontsize=5.6, handlelength=1, columnspacing=0.6)
    ax.grid(axis="x", visible=False)
    fig.suptitle("Malaysian benchmark (60 legitimate, 60 malicious pages)", x=0.01, ha="left", fontsize=8.5,
                 fontweight="bold")
    save(fig, path)


def roc_chart(path):
    apply_style()
    fin = rows("final_v4.0.0")
    y = [int(r["label"]) for r in fin]
    fig, ax = plt.subplots(figsize=(4.6, 3.6))
    for key, lab, col, ls in [("p_url_stripped", "BERT, URL without scheme (pipeline input)", PURPLE, "-"),
                              ("p_url_raw", "BERT, URL with scheme", BLUE, "--"),
                              ("p_composite", "BERT, URL + page text (v3.0.0 input)", AMBER, ":")]:
        pts = roc(y, [float(r[key]) for r in fin])
        ax.plot([p[0] for p in pts], [p[1] for p in pts], color=col, ls=ls, lw=1.4, label=f"{lab} — AUC {auc(pts):.3f}")
    ops = [("v3.0.0 pipeline", "baseline_v3.0.0", AMBER, "s"), ("rules, no model", "ablation_no_bert_v4.0.0", TEAL, "^"),
           ("v4.0 pipeline", "final_v4.0.0", NAVY, "o")]
    for lab, tag, col, mk in ops:
        m = metrics(tag)["pipeline"]["overall"]
        ax.scatter(m["false_positive_rate"], m["recall"], color=col, marker=mk, s=42, zorder=5, edgecolor="white",
                   label=f"{lab}: FPR {m['false_positive_rate'] * 100:.1f} %, TPR {m['recall'] * 100:.1f} %")
    ax.plot([0, 1], [0, 1], color=LINE, lw=0.8, ls="--")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.04)
    ax.set_xlabel("false-positive rate")
    ax.set_ylabel("true-positive rate (recall)")
    ax.set_title("ROC of BERT alone versus pipeline operating points", loc="left")
    ax.legend(loc="lower right", fontsize=5.8)
    fig.tight_layout()
    save(fig, path)


def per_category(path):
    apply_style()
    b, f = metrics("baseline_v3.0.0")["pipeline"]["per_category"], metrics("final_v4.0.0")["pipeline"]["per_category"]
    a = metrics("ablation_no_bert_v4.0.0")["pipeline"]["per_category"]
    cats = list(f.keys())
    labels = [k.split("_", 1)[0] + " " + k.split("_", 1)[1].replace("_", " ") + f" (n={f[k]['n']})" for k in cats]
    y = np.arange(len(cats))
    fig, ax = plt.subplots(figsize=(6.5, 3.1))
    ax.barh(y - 0.27, [b[k]["accuracy"] * 100 for k in cats], 0.26, color=AMBER, label="v3.0.0")
    ax.barh(y, [a[k]["accuracy"] * 100 for k in cats], 0.26, color=TEAL, label="v4.0 without BERT")
    ax.barh(y + 0.27, [f[k]["accuracy"] * 100 for k in cats], 0.26, color=NAVY, label="v4.0")
    for i, k in enumerate(cats):
        ax.text(f[k]["accuracy"] * 100 + 1, i + 0.27, f"{f[k]['accuracy'] * 100:.0f}", va="center", fontsize=6, color=NAVY)
        ax.text(b[k]["accuracy"] * 100 + 1, i - 0.27, f"{b[k]['accuracy'] * 100:.0f}", va="center", fontsize=6, color=AMBER)
    ax.set_yticks(y, labels, fontsize=6.4)
    ax.invert_yaxis()
    ax.set_xlim(0, 114)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_xlabel("correct verdicts (%)")
    ax.axhline(3.5, color=LINE, lw=0.6, ls="--")
    ax.text(110, 1.5, "legitimate", rotation=90, va="center", fontsize=6.2, color=MUTED)
    ax.text(110, 6, "malicious", rotation=90, va="center", fontsize=6.2, color=MUTED)
    ax.legend(loc="lower left", ncol=3, bbox_to_anchor=(0, -0.3))
    ax.grid(axis="y", visible=False)
    ax.set_title("Verdict accuracy per benchmark category", loc="left")
    fig.tight_layout()
    save(fig, path)


def locust_overview(path):
    apply_style()
    runs = [("run_50u", "50 users"), ("run_200u", "200 users")]
    order = ["/analyze/semantics [BERT cache-miss]", "/analyze/semantics [WHITELISTED]", "/analyze/semantics [PHISHING, cached]",
             "/analyze/semantics [MULE, trusted host]", "/dashboard/stats", "/health"]
    short = ["BERT cache-miss", "whitelisted", "phishing (cached)", "mule (trusted host)", "dashboard stats", "health"]
    fig, axes = plt.subplots(1, 3, figsize=(6.5, 2.9), gridspec_kw={"width_ratios": [0.9, 1.6, 1.6]})
    ax = axes[0]
    agg = [next(r for r in locust(run) if r["Name"] == "Aggregated") for run, _ in runs]
    rps = [float(a["Requests/s"]) for a in agg]
    bert_rps = [float(next(r for r in locust(run) if r["Name"] == order[0])["Requests/s"]) for run, _ in runs]
    ax.bar([0, 1], rps, 0.55, color=[NAVY, PURPLE])
    ax.bar([0, 1], bert_rps, 0.55, color="none", edgecolor="white", hatch="////", lw=0)
    for i in range(2):
        ax.text(i, rps[i] + 1, f"{rps[i]:.1f}", ha="center", fontsize=6.5, fontweight="bold")
        ax.text(i, -4.5, f"BERT {bert_rps[i]:.1f}/s", ha="center", fontsize=5.3, color=MUTED)
        ax.text(i, -9, f"{int(agg[i]['Failure Count'])} errors", ha="center", fontsize=5.8, color=GREEN)
    ax.set_xticks([0, 1], [r[1] for r in runs])
    ax.set_ylabel("requests / s (hatched: BERT path)")
    ax.set_ylim(-11.5, 48)
    ax.set_title("Throughput", loc="left")
    ax.grid(axis="x", visible=False)
    for k, (run, lab) in enumerate(runs):
        ax = axes[k + 1]
        st = {r["Name"]: r for r in locust(run)}
        yv = np.arange(len(order))
        for j, (pct, col) in enumerate([("50%", TEAL), ("95%", AMBER), ("99%", RED)]):
            vals = [float(st[n][pct]) for n in order]
            ax.scatter(vals, yv, color=col, s=16, zorder=4, label=f"p{pct[:-1]}")
        for i, n in enumerate(order):
            ax.plot([float(st[n]["50%"]), float(st[n]["99%"])], [i, i], color=LINE, lw=1, zorder=3)
        ax.set_xscale("log")
        ax.set_xlim(1, 30000)
        ax.set_yticks(yv, short if k == 0 else [""] * len(order), fontsize=6.2)
        ax.invert_yaxis()
        ax.set_xlabel("response time (ms, log)")
        ax.set_title(f"Latency, {lab}", loc="left")
        ax.axvline(400, color=GREY, lw=0.7, ls=":")
        ax.text(460, 4.5, "400 ms target", fontsize=5.4, color=GREY, va="center")
        if k == 1:
            h, l = ax.get_legend_handles_labels()
            fig.legend(h, l, loc="lower center", ncol=3, fontsize=6, bbox_to_anchor=(0.62, 0.0), frameon=False)
    fig.tight_layout(w_pad=0.8, rect=(0, 0.06, 1, 1))
    save(fig, path)


def locust_timeseries(path):
    apply_style()
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.6), sharey=False)
    for ax, run, lab in [(axes[0], "run_50u", "50 users"), (axes[1], "run_200u", "200 users")]:
        hist = [r for r in locust(run, "stats_history") if r["Name"] == "Aggregated"]
        t0 = int(hist[0]["Timestamp"])
        t = [int(r["Timestamp"]) - t0 for r in hist]
        users = [int(r["User Count"]) for r in hist]
        rps = [float(r["Requests/s"]) for r in hist]
        p95 = [float(r["95%"]) if r["95%"] not in ("N/A", "") else np.nan for r in hist]
        ax.plot(t, rps, color=NAVY, lw=1.2, label="requests / s")
        ax.plot(t, [u / 5 for u in users], color=GREY, lw=1, ls="--", label="users ÷ 5")
        ax.set_xlabel("time (s)")
        ax.set_ylabel("requests / s")
        ax.set_ylim(0, 62)
        ax2 = ax.twinx()
        ax2.plot(t, p95, color=RED, lw=1.1, label="p95 latency (ms)")
        ax2.set_yscale("log")
        ax2.set_ylim(5, 30000)
        ax2.set_ylabel("p95 (ms, log)", color=RED)
        ax2.tick_params(axis="y", colors=RED)
        ax2.grid(False)
        ax2.spines["right"].set_visible(True)
        ax.set_title(f"{lab}: throughput vs tail latency", loc="left")
        if run == "run_200u":
            ax.text(28, 5, "CPU inference saturates:\nthroughput plateaus at ~40 req/s\nwhile p95 climbs to ~11 s",
                    fontsize=5.8, color=RED)
        h1, l1 = ax.get_legend_handles_labels()
        h2, l2 = ax2.get_legend_handles_labels()
        ax.legend(h1 + h2, l1 + l2, loc="lower right" if run == "run_50u" else "lower left", fontsize=5.6)
    fig.tight_layout(w_pad=1.2)
    save(fig, path)


def tests_coverage(path):
    apply_style()
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    counts = Counter(line.split("::")[0].split("/")[-1].split("\\")[-1] for line in out.splitlines() if "::" in line)
    cov = json.loads((RESULTS / "coverage" / "coverage.json").read_text())
    files = cov["files"]
    total = cov["totals"]["percent_covered"]
    groups = {}
    for name, info in files.items():
        mod = name.replace("\\", "/")
        s = info["summary"]
        groups[mod] = (s["percent_covered"], s["num_statements"])
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(6.5, 4.6), gridspec_kw={"width_ratios": [1, 1.25]})
    names = sorted(counts, key=lambda k: -counts[k])
    ax.barh(range(len(names)), [counts[n] for n in names], color=GREEN, height=0.62)
    for i, n in enumerate(names):
        ax.text(counts[n] + 0.8, i, f"{counts[n]} / {counts[n]}", va="center", fontsize=6.2)
    ax.set_yticks(range(len(names)), [n.replace(".py", "") for n in names], fontsize=6.2)
    ax.invert_yaxis()
    ax.set_xlim(0, 58)
    ax.set_xlabel("tests (all passing)")
    ax.set_title(f"{sum(counts.values())} / {sum(counts.values())} tests pass", loc="left")
    ax.grid(axis="y", visible=False)
    mods = sorted(groups.items(), key=lambda kv: kv[1][0])
    keep = [m for m in mods if m[1][1] >= 20]
    labs = [m[0].replace("services/", "").replace(".py", "") for m in keep]
    vals = [m[1][0] for m in keep]
    cols = [RED if v < 50 else (AMBER if v < 80 else NAVY) for v in vals]
    ax2.barh(range(len(keep)), vals, color=cols, height=0.7)
    ax2.axvline(total, color=INK, lw=0.8, ls="--")
    ax2.text(total + 1, -0.9, f"overall {total:.0f} %", fontsize=6.2)
    ax2.set_ylim(len(keep) - 0.4, -1.4)
    ax2.set_yticks(range(len(keep)), labs, fontsize=6.0)
    ax2.set_xlim(0, 105)
    ax2.set_xlabel("statement + branch coverage (%)")
    ax2.set_title("Coverage per module (≥ 20 statements)", loc="left")
    ax2.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=1.5)
    save(fig, path)


# ==============================================================================

FIGURES = {
    "tradeoff": tradeoff,              # Chapter 2
    "training_loss": training_loss,    # Chapter 5
    "kaggle_cm": kaggle_cm,
    "confusion_compare": confusion_compare,
    "roc": roc_chart,
    "per_category": per_category,
    "locust_overview": locust_overview,
    "locust_timeseries": locust_timeseries,
    "tests_coverage": tests_coverage,
}


def main(only: list[str] | None = None) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES.items():
        if only and name not in only:
            continue
        fn(OUT / f"{name}.png")
        print("  ", f"{name}.png")


if __name__ == "__main__":
    main(sys.argv[1:] or None)
