"""
PhishGuard-AI — Engineering diagrams for the dissertation (Chapters 1–4 and 6).
================================================================================

Every component, route, table, column, threshold and timeout drawn here is
taken from the v3.2.0 source code; every number is taken from the committed
evaluation results.  Called by ``make_report_figures.py``.
"""

from __future__ import annotations

from datetime import date

from evaluation.figkit import (AMBER, BLUE, Canvas, GREEN, GREY, INK, LINE, MUTED, NAVY, PURPLE, RED, TEAL, TONES,
                               WHITE)


def _wrap(text: str, width_in: float, size: float) -> list[str]:
    """Greedy word wrap using an average Arial glyph width of 0.5 em."""
    max_chars = max(8, int(width_in / (size / 72 * 0.5)))
    out = []
    for para in text.split("\n"):
        cur = ""
        for word in para.split(" "):
            if cur and len(cur) + 1 + len(word) > max_chars:
                out.append(cur)
                cur = word
            else:
                cur = f"{cur} {word}".strip()
        out.append(cur)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Chapter 1
# ══════════════════════════════════════════════════════════════════════════════

def kill_chain(path):
    c = Canvas(6.5, 4.05)
    c.text(0.1, 3.93, "Malaysian financial-scam kill chain, threat taxonomy and PhishGuard-AI intervention points", size=8,
           weight="bold", ha="left")
    stages = [
        ("1  Lure delivery", "navy", ["SMS · WhatsApp · Telegram", "social & marketplace ads", "QR posters · fake e-mail",
                                       "caller posing as PDRM / LHDN"]),
        ("2  Deception surface", "purple", ["look-alike / punycode domain", "pixel-copied bank login",
                                             "urgent BM / Manglish text", "fake listing or aid portal"]),
        ("3  Harvest / instruction", "red", ["password + TAC / OTP form", "card number · CVV · PIN",
                                              "\"transfer deposit to …\"", "DuitNow QR / phone proxy"]),
        ("4  Monetisation", "amber", ["session relay (AiTM kit)", "funds to mule accounts",
                                       "layering across mules", "cash-out / crypto"]),
    ]
    w, gap, x0 = 1.5, 0.1, 0.12
    nodes = []
    for i, (title, tone, lines) in enumerate(stages):
        x = x0 + i * (w + gap)
        n = c.box(x, 3.0, w, 0.8, title=title, lines=lines, tone=tone, header=True, size=6.0, title_size=6.8)
        nodes.append(n)
        if i:
            c.arrow(nodes[i - 1].right, (x, nodes[i - 1].cy), color=INK, lw=1.0, head=5)
    c.text(0.12, 2.84, "Threat taxonomy — benchmark category in brackets", size=6.9, weight="bold", ha="left",
           color=NAVY)
    tax = [("Credential phishing", "bank look-alikes [P1]", "purple"), ("Authority lures", "LHDN, PDRM, KWSP [P2]", "red"),
           ("Payment diversion", "mule-account pages [P3]", "amber"), ("Wallet / brand lures", "TNG, GrabPay [P4]", "purple"),
           ("Evasive hosting", "neutral / shared hosts [P5]", "grey")]
    tw = (6.26 - 4 * 0.08) / 5
    for i, (t, sub, tone) in enumerate(tax):
        c.box(0.12 + i * (tw + 0.08), 2.22, tw, 0.48, title=t, lines=[sub], tone=tone, size=5.8, title_size=6.3)
    c.text(0.12, 2.04, "Detectors (stage acted on) → corroboration rule", size=6.9, weight="bold", ha="left", color=TEAL)
    det = [
        ("URL heuristics (2)", ["raw IP · punycode · risky TLD", "deep subdomain chains"], "teal"),
        ("Brand profiler (2)", ["brand in foreign host → R2", "homoglyph / edit distance → R3"], "teal"),
        ("BERT URL model (2)", ["P(phish) ≥ 0.75 = supporting", "signal only (R3–R6)"], "teal"),
        ("Credential & lexicon (3)", ["password / OTP / card field", "BM · EN · ZH phrases → R4, R5"], "teal"),
        ("Mule scanner (3–4)", ["8 bank formats + DuitNow", "registry match blocks → R1"], "green"),
        ("SOC review queue (4)", ["user report → analyst", "APPROVE → registry"], "green"),
    ]
    dw = (6.26 - 2 * 0.1) / 3
    for i, (t, ls, tone) in enumerate(det):
        col, row = i % 3, i // 3
        c.box(0.12 + col * (dw + 0.1), 1.4 - row * 0.52, dw, 0.46, title=t, lines=ls, tone=tone, size=5.7,
              title_size=6.2)
    c.box(0.12, 0.08, 6.26, 0.66, tone="grey", fill="white", edge=LINE, lines=[
        "Why request-time analysis: Oest et al. (2020) measured a mean of nine hours from a campaign's first victim to its "
        "detection, in campaigns lasting about 21 hours.",
        "PhishGuard-AI analyses each page when it is opened — median 190 ms on the BERT path, 0.28 ms for whitelisted sites."],
          size=6.0)
    c.save(path)


def decision_funnel(path, final_rows):
    total = len(final_rows)
    wl = [r for r in final_rows if r["is_whitelisted"] == "True"]
    rest = [r for r in final_rows if r["is_whitelisted"] != "True"]
    rules = {}
    for r in rest:
        if r["decision_rule"]:
            rules.setdefault(r["decision_rule"], []).append(r)
    safe = [r for r in rest if not r["decision_rule"]]
    c = Canvas(6.5, 3.3)
    c.text(0.1, 3.18, f"How the {total} benchmark pages were decided by the v3.2.0 pipeline", size=8, weight="bold",
           ha="left")
    scale = 2.45 / total
    c.box(0.15, 0.45, 1.0, 2.45, title=f"{total} pages", lines=["60 legitimate", "60 malicious"], tone="navy", size=6.4)
    h_wl = len(wl) * scale
    wl_legit = sum(r["label"] == "0" for r in wl)
    n_wl = c.box(1.6, 2.9 - h_wl, 1.45, h_wl, title=f"Whitelist bypass: {len(wl)}",
                 lines=[f"{wl_legit} legitimate · {len(wl) - wl_legit} malicious*"], tone="green", size=5.9, title_size=6.4)
    h_rest = len(rest) * scale
    n_rest = c.box(1.6, 0.45, 1.45, h_rest - 0.08, title=f"Analysed: {len(rest)}",
                   lines=["BERT || mule scan, then", "brand, heuristics,", "credential form, lexicon"], tone="blue", size=6.0)
    c.arrow((1.15, n_wl.cy), n_wl.left, color=GREEN)
    c.arrow((1.15, n_rest.cy), n_rest.left, color=BLUE)
    order = ["R1_MULE_REGISTRY", "R2_BRAND_IN_HOSTNAME", "R3_LOOKALIKE_DOMAIN", "R4_BRAND_CLONE",
             "R5_COERCIVE_CREDENTIAL_REQUEST", "R6_EVASIVE_INFRASTRUCTURE"]
    names = {"R1_MULE_REGISTRY": "R1 mule registry", "R2_BRAND_IN_HOSTNAME": "R2 brand in hostname",
             "R3_LOOKALIKE_DOMAIN": "R3 look-alike domain", "R4_BRAND_CLONE": "R4 brand clone",
             "R5_COERCIVE_CREDENTIAL_REQUEST": "R5 coercive credential request",
             "R6_EVASIVE_INFRASTRUCTURE": "R6 evasive infrastructure"}
    yy = 2.9
    blocked = 0
    for key in order:
        rows = rules.get(key, [])
        if not rows:
            continue
        h = 0.27
        n = c.box(3.55, yy - h, 2.8, h - 0.03, tone="red", lw=0.6)
        c.text(3.63, yy - h / 2 - 0.015, names[key], size=6.2, ha="left")
        c.text(6.28, yy - h / 2 - 0.015, f"{len(rows)} blocked", size=6.2, ha="right", weight="bold", color=RED)
        c.arrow(n_rest.right, n.left, color=LINE, lw=0.5, head=3)
        yy -= h
        blocked += len(rows)
    safe_legit = sum(r["label"] == "0" for r in safe)
    n = c.box(3.55, 0.45, 2.8, 0.6, tone="green", lw=0.6, title=f"SAFE, no rule satisfied: {len(safe)}",
              lines=[f"{safe_legit} legitimate · {len(safe) - safe_legit} malicious missed"], size=5.9, title_size=6.4)
    c.arrow(n_rest.right, n.left, color=GREEN, lw=0.6, head=3)
    c.text(0.15, 0.27, f"Blocked: {blocked} of 60 malicious and 0 of 60 legitimate pages. Missed: a sparse loading page "
                       f"and an investment scam without a credential form;", size=5.8, ha="left", color=MUTED)
    c.text(0.15, 0.13, "(*) one phishing form hosted on Google Forms, a whitelisted platform, bypassed analysis.",
           size=5.8, ha="left", color=MUTED)
    c.save(path)


def module_boundary(path):
    c = Canvas(6.5, 3.25)
    c.text(0.1, 3.13, "Team module boundary and the interface between the modules", size=8, weight="bold", ha="left")
    c.group(0.1, 0.42, 3.85, 2.55, "Module 1 — Backend & AI core (Liew Yi Ler)", tone="navy", dashed=False)
    c.group(4.1, 0.42, 2.3, 2.55, "Module 2 — Client & vision (Cheon Jie Han)", tone="teal", dashed=False)
    for y, t, ls in [(2.03, "Manifest V3 extension", ["content script · service worker", "popup · block overlay"]),
                     (1.3, "YOLOv8n logo detector", ["5 banks · synthetic dataset", "router /api/visual/analyze"]),
                     (0.57, "Offline heuristics", ["typosquat check · official list", "fail-safe on timeout / error"])]:
        c.box(4.22, y, 2.06, 0.6, title=t, lines=ls, tone="teal", fill=WHITE, size=5.9)
    items = [(0.22, 2.03, "FastAPI gateway", ["auth · rate limit · validation", "/api/v1 · /api/v1/dashboard"]),
             (2.08, 2.03, "BERT URL engine", ["bert-base-uncased, 1 epoch", "439,476 URLs · threshold 0.75"]),
             (0.22, 1.3, "Mule scanner", ["8 bank + DuitNow patterns", "indexed registry lookup"]),
             (2.08, 1.3, "Verdict engine", ["brand tiers · heuristics", "credential form · rules R1–R6"]),
             (0.22, 0.57, "SQLite persistence", ["mule_registry · threat_telemetry", "mule_reports (review queue)"]),
             (2.08, 0.57, "SOC dashboard", ["session auth · SSE stream", "STIX / CEF / Syslog export"])]
    for x, y, t, ls in items:
        c.box(x, y, 1.72, 0.6, title=t, lines=ls, tone="navy", fill=WHITE, size=5.9)
    c.arrow((4.22, 2.45), (3.8, 2.45), color=INK, lw=0.9, head=5)
    c.arrow((3.8, 2.15), (4.22, 2.15), color=INK, lw=0.9, head=5)
    c.text(0.12, 0.27, "Request: POST /api/v1/analyze/semantics · /analyze/quishing · /mule-reports with a Bearer key.",
           size=5.9, ha="left", color=MUTED)
    c.text(0.12, 0.11, "Response: orchestration (BLOCK_RENDER | SAFE), decision_rule, risk_score, threat_indicators, signals.",
           size=5.9, ha="left", color=MUTED)
    c.save(path)


def gantt(path):
    c = Canvas(6.5, 3.75)
    start, end = date(2026, 1, 19), date(2026, 12, 25)
    x0, x1 = 2.05, 6.4
    span = (end - start).days

    def X(d):
        return x0 + (d - start).days / span * (x1 - x0)

    rows = [
        ("Supervisor approach & assignment", date(2026, 2, 20), date(2026, 3, 16), "navy"),
        ("Proposal (Forms 1–3)", date(2026, 3, 16), date(2026, 4, 10), "navy"),
        ("Proposal moderation", date(2026, 6, 1), date(2026, 6, 12), "navy"),
        ("Ch. 1 Introduction", date(2026, 6, 15), date(2026, 6, 26), "blue"),
        ("Ch. 2 Literature review", date(2026, 6, 26), date(2026, 7, 10), "blue"),
        ("Ch. 3 Methodology", date(2026, 7, 10), date(2026, 7, 24), "blue"),
        ("Ch. 4 System design", date(2026, 7, 24), date(2026, 8, 14), "blue"),
        ("Prototype & Project I portfolio", date(2026, 8, 14), date(2026, 9, 11), "blue"),
        ("Benchmark, fixes & hardening", date(2026, 11, 2), date(2026, 11, 17), "teal"),
        ("Test plan & system preview", date(2026, 11, 17), date(2026, 11, 20), "teal"),
        ("Final testing (sup. + moderator)", date(2026, 11, 20), date(2026, 11, 27), "teal"),
        ("Draft and final report", date(2026, 11, 27), date(2026, 12, 11), "teal"),
        ("Mark entry", date(2026, 12, 11), date(2026, 12, 18), "teal"),
    ]
    top, rh = 3.2, 0.19
    for s, e, lab in [(date(2026, 1, 26), date(2026, 5, 1), "Jan semester"),
                      (date(2026, 6, 15), date(2026, 9, 20), "May semester"),
                      (date(2026, 11, 2), date(2026, 12, 20), "Short sem.")]:
        c.bar(X(s), 0.62, X(e) - X(s), top - 0.4, "#F3F5F8", z=1)
        c.text((X(s) + X(e)) / 2, top + 0.02, lab, size=6.2, color=MUTED)
    for m in range(1, 13):
        d = date(2026, m, 1)
        c.vline(X(d), 0.62, top - 0.1, color="#E3E7ED", lw=0.5, z=1.5)
        c.text(X(d) + 0.02, 0.5, d.strftime("%b"), size=6, color=MUTED, ha="left")
    for i, (name, s, e, tone) in enumerate(rows):
        y = top - 0.2 - i * rh
        c.text(1.98, y, name, size=6.3, ha="right")
        c.bar(X(s), y - 0.065, max(0.04, X(e) - X(s)), 0.13, TONES[tone][0], z=3)
    for i, (d, lab) in enumerate([(date(2026, 4, 10), "Proposal 10 Apr"), (date(2026, 9, 11), "Preview I 11 Sep"),
                                  (date(2026, 11, 17), "Preview II 17 Nov"), (date(2026, 12, 11), "Final 11 Dec")]):
        c.ax.plot([X(d)], [0.32], marker="D", ms=4, color=RED, zorder=6)
        lx, ly, ha = [(X(d), 0.18, "center"), (X(d) - 0.03, 0.18, "right"), (X(d) - 0.03, 0.06, "right"),
                      (X(d) + 0.04, 0.18, "right")][i]
        c.text(lx if i != 3 else 6.42, ly, lab, size=5.8, color=RED, ha=ha)
    c.text(0.1, 3.62, "Project I (session 202605) and Project II (session 202609) schedule, 2026", size=8,
           weight="bold", ha="left")
    c.text(1.98, 0.32, "milestones", size=6, ha="right", color=RED)
    c.save(path)


# ══════════════════════════════════════════════════════════════════════════════
# Chapter 2
# ══════════════════════════════════════════════════════════════════════════════

def exposure_window(path):
    c = Canvas(6.5, 1.75)
    x0, x1 = 0.45, 6.25

    def X(h):
        return x0 + h / 24 * (x1 - x0)

    y = 0.82
    c.hline(x0, x1, y, color=INK, lw=1)
    for h in range(0, 25, 3):
        c.vline(X(h), y - 0.05, y + 0.05, color=INK, lw=0.8)
        c.text(X(h), y - 0.14, f"{h} h", size=6.2, color=MUTED)
    c.bar(X(0), y + 0.07, X(9) - X(0), 0.2, "#F4C7C1", z=2)
    c.text((X(0) + X(9)) / 2, y + 0.17, "no blacklist protection (mean 9 h)", size=6.4, color=RED, weight="bold")
    c.bar(X(9), y + 0.07, X(21) - X(9), 0.2, "#F9E4BF", z=2)
    c.text((X(9) + X(21)) / 2, y + 0.17, "warnings propagate to browsers; campaign continues", size=6.4, color=AMBER)
    for h, lab, col in [(0, "first victim visits page", RED), (9, "detected by anti-phishing entity", AMBER),
                        (21, "campaign over (mean ≈ 21 h)", GREY)]:
        c.ax.plot([X(h)], [y], marker="o", ms=5, color=col, zorder=6)
        c.text(X(h) - (0.05 if h == 0 else 0), y + 0.42, lab, size=6.2, color=col, ha="left" if h == 0 else "center")
    c.arrow((X(0), 0.3), (X(0), y - 0.2), color=TEAL, lw=1, head=4)
    c.text(X(0) + 0.08, 0.22, "PhishGuard-AI analyses every page when it is opened: median 190 ms on the BERT path, "
                              "0.28 ms for whitelisted sites", size=6.3, color=TEAL, ha="left", weight="bold")
    c.text(0.1, 1.62, "Exposure window of reactive defences (timings from Oest et al., 2020)", size=8, weight="bold",
           ha="left")
    c.save(path)


def wordpiece(path, examples):
    """examples: list of (url, tokens, p_phish, label_text)."""
    c = Canvas(6.5, 0.55 + 0.78 * len(examples))
    y = c.H - 0.32
    c.text(0.1, c.H - 0.12, "WordPiece tokenisation of URLs by the fine-tuned model (real tokenizer output)", size=8,
           weight="bold", ha="left")
    for url, tokens, p, lab in examples:
        c.text(0.1, y - 0.06, url, size=6.8, mono=True, ha="left", weight="bold")
        tone = "red" if p >= 0.75 else "green"
        c.text(6.4, y - 0.06, f"P(phishing) = {p:.3f}  ·  {lab}", size=6.4, ha="right", color=TONES[tone][0],
               weight="bold")
        x = 0.1
        yy = y - 0.36
        for tok in ["[CLS]"] + tokens + ["[SEP]"]:
            w = max(0.2, len(tok) * 0.058 + 0.1)
            if x + w > 6.4:
                x = 0.1
                yy -= 0.24
            special = tok.startswith("[")
            cont = tok.startswith("##")
            c.box(x, yy - 0.09, w, 0.18, tone="grey" if special else ("purple" if cont else "blue"), radius=0.03,
                  lw=0.6)
            c.text(x + w / 2, yy, tok, size=6, mono=True, color=MUTED if special else INK)
            x += w + 0.04
        y = yy - 0.32
    c.text(0.1, 0.13, "blue = word-initial piece · purple = continuation (##) · grey = special token; sequences "
                      "padded/truncated to 128.\nThe official portal also scores 1.000: a URL-only model cannot separate "
                      "it from a clone, so BERT never blocks a page on its own.", size=5.8, color=MUTED, ha="left")
    c.save(path)


# ══════════════════════════════════════════════════════════════════════════════
# Chapter 3
# ══════════════════════════════════════════════════════════════════════════════

def methodology(path):
    c = Canvas(6.5, 4.15)
    c.text(0.1, 4.03, "End-to-end methodology and multi-modal evaluation pipeline", size=8, weight="bold", ha="left")
    phases = [("Requirements &", "threat modelling", "Project I", "navy"), ("Architecture &", "interface design", "Project I", "navy"),
              ("Implementation", "sprints", "Project II", "teal"), ("Evaluation &", "hardening", "Project II", "teal"),
              ("Release v3.2.0", "& report", "Project II", "teal")]
    pw = (6.3 - 4 * 0.08) / 5
    for i, (a, b, proj, tone) in enumerate(phases):
        x = 0.1 + i * (pw + 0.08)
        c.box(x, 3.38, pw, 0.5, title=a, lines=[b, proj], tone=tone, size=5.8, title_size=6.3)
        if i:
            c.arrow((x - 0.08, 3.63), (x, 3.63), color=INK, lw=0.8, head=4)
    aw = (6.1 - 4 * 0.1) / 5

    def track(y, label, tone, steps):
        c.group(0.1, y, 6.3, 1.0, label, tone=tone, fill="#FAFBFD")
        prev = None
        nodes = []
        for i, (t, ls) in enumerate(steps):
            n = c.box(0.2 + i * (aw + 0.1), y + 0.08, aw, 0.66, title=t, lines=ls, tone=tone, fill="white", size=5.7,
                      title_size=6.2)
            if prev:
                c.arrow(prev.right, n.left, color=TONES[tone][0], lw=0.8, head=4)
            prev = n
            nodes.append(n)
        return nodes

    a = track(2.22, "Track A — BERT URL classifier (Google Colab, Tesla T4)", "navy", [
        ("Kaggle corpus", ["549,346 labelled URLs", "good / bad"]), ("Cleaning", ["drop NaN · lower-case", "map 0 / 1 · int cast"]),
        ("Random 80 / 20", ["train 439,476", "hold-out 109,870"]), ("Fine-tune", ["lr 2e-5 · batch 16", "1 epoch · 27,468 steps"]),
        ("Hold-out test", ["acc 98.76 % · F1 97.80 %", "confusion matrix rebuilt"])])
    b = track(1.0, "Track B — Malaysian validation harness (local CPU, real model)", "teal", [
        ("Benchmark", ["120 pages · 9 categories", "60 legit / 60 malicious"]), ("Split", ["dev 60 (tuning)", "hold-out 60 (untouched)"]),
        ("Baseline v3.0.0", ["FPR 78.33 %", "root causes on dev"]), ("Redesign", ["rules R1–R6", "input realignment"]),
        ("Final + ablation", ["acc 97.50 % · FPR 0 %", "no BERT: recall 85 %"])])
    c.arrow((a[4].cx, a[4].y), (b[3].x + b[3].w * 0.7, b[3].y + b[3].h), color=NAVY, lw=0.8, ls="--", head=4,
            label="model weights", size=5.6, label_dx=0.2)
    c.group(0.1, 0.06, 6.3, 0.82, "Quality gates applied to every change", tone="grey", fill="#FBFBFC")
    gates = [("Unit & integration", "198 pytest tests pass", "green"), ("Coverage", "77 % stmt + branch", "green"),
             ("CI", "GitHub Actions per push", "green"), ("Regression", "0 FP on 60 legit pages", "amber"),
             ("Load", "Locust 50 users: 0 errors", "amber")]
    gw = (6.1 - 4 * 0.08) / 5
    for i, (t, s, tone) in enumerate(gates):
        c.box(0.2 + i * (gw + 0.08), 0.13, gw, 0.45, title=t, lines=[s], tone=tone, size=5.7, title_size=6.2)
    c.save(path)


def threat_model(path):
    rows = [
        ("Forge analysis requests", "Spoofing", "Bearer API key, constant-time compare", "test_endpoints.py (401)"),
        ("Read / delete SOC data, download DB", "Elevation", "Admin key or HttpOnly session (64 ops)", "test_security.py"),
        ("Guess the admin key online", "Spoofing", "Login limited to 5 / min / IP", "test_security.py (429)"),
        ("Flood the inference endpoint", "Denial of service", "60 req / min / IP; thread offloading", "Locust default-limit run"),
        ("Poison the mule registry", "Tampering", "PENDING queue + analyst approval", "test_mule_reports.py"),
        ("SQL injection via account field", "Tampering", "Pattern check (422) + parameterised SQL", "test_mule_reports.py"),
        ("Cross-origin calls from a malicious site", "Spoofing", "Explicit CORS allow-list, no credentials", "test_security.py"),
        ("Look-alike or punycode domain", "Evasion", "R3 edit distance / homoglyphs; heuristics", "Benchmark P1: 14 / 14"),
        ("Clone on a shared hosting platform", "Evasion", "Shared-hosting suffixes not whitelisted", "Benchmark P5: 7 / 10"),
        ("Stall the backend to suppress warnings", "Denial of service", "8 s / 12 s abort → offline fallback", "Extension manual test"),
    ]
    rh = 0.29
    c = Canvas(6.5, 0.62 + rh * len(rows))
    c.text(0.1, c.H - 0.12, "Misuse cases, countermeasures and the evidence that verifies each control", size=8,
           weight="bold", ha="left")
    cols = [(0.1, 2.05, "Misuse case (attacker goal)", "red"), (2.2, 0.95, "STRIDE / class", "purple"),
            (3.2, 1.95, "Countermeasure (v3.2.0)", "navy"), (5.2, 1.2, "Verified by", "green")]
    y = c.H - 0.46
    for x, w, t, tone in cols:
        c.box(x, y, w - 0.04, 0.2, tone=tone, fill=TONES[tone][0], radius=0.03)
        c.text(x + (w - 0.04) / 2, y + 0.1, t, size=6.4, weight="bold", color=WHITE)
    for i, row in enumerate(rows):
        yy = y - 0.04 - (i + 1) * rh
        for j, (x, w, _, tone) in enumerate(cols):
            c.box(x, yy, w - 0.04, rh - 0.04, tone=tone, fill=TONES[tone][1] if j != 1 else "white", radius=0.03, lw=0.5)
            c.text(x + 0.05, yy + (rh - 0.04) / 2, row[j], size=5.9, ha="left")
    c.save(path)


def data_splits(path, categories):
    c = Canvas(6.5, 2.55)
    c.text(0.1, 2.43, "Datasets, splits and class balance", size=8, weight="bold", ha="left")
    c.text(0.1, 2.2, "Training corpus — Kaggle phishing_site_urls (URL strings only, 549,346 rows)", size=6.8,
           weight="bold", ha="left", color=NAVY)
    total = 549346
    x0, W = 0.1, 6.3
    tr = 439476 / total * W
    c.bar(x0, 1.82, tr, 0.26, NAVY)
    c.text(x0 + tr / 2, 1.95, "train 439,476 (80 %)", size=6.4, color=WHITE, weight="bold")
    lg, ph = 78670 / total * W, 31200 / total * W
    c.bar(x0 + tr, 1.82, lg, 0.26, TEAL)
    c.bar(x0 + tr + lg, 1.82, ph, 0.26, RED)
    c.text(x0 + tr + lg / 2, 1.95, "legit", size=6.1, color=WHITE, weight="bold")
    c.text(x0 + tr + lg + ph / 2, 1.95, "phish", size=6.1, color=WHITE, weight="bold")
    c.text(6.4, 1.71, "hold-out 109,870 = 78,670 legitimate + 31,200 phishing (28.4 %)", size=6, color=MUTED, ha="right")
    c.text(0.1, 1.45, "Evaluation benchmark — 120 Malaysian pages (HTML documents, never used for training)", size=6.8,
           weight="bold", ha="left", color=TEAL)
    order = ["L1_official_portal", "L2_benign_brand_mention", "L3_general_benign", "L4_benign_with_accounts",
             "P1_bank_lookalike", "P2_bm_manglish_lure", "P3_mule_account", "P4_ewallet_brand", "P5_evasive"]
    short = ["L1 official", "L2 mention", "L3 general", "L4 accounts", "P1 look-alike", "P2 BM lure", "P3 mule",
             "P4 wallet", "P5 evasive"]
    x = 0.1
    for k, s in zip(order, short):
        n = categories[k]
        w = n / 120 * 6.3
        c.bar(x, 0.98, w - 0.02, 0.3, TEAL if k.startswith("L") else RED)
        c.text(x + w / 2, 1.13, str(n), size=6.2, color=WHITE, weight="bold")
        c.text(x + w / 2, 0.88, s, size=5.6, color=MUTED)
        x += w
    c.bar(0.1, 0.42, 3.13, 0.24, NAVY)
    c.text(0.1 + 1.565, 0.54, "dev split 60 (30 / 30) — used to tune rules", size=6.2, color=WHITE, weight="bold")
    c.bar(3.27, 0.42, 3.13, 0.24, GREY)
    c.text(3.27 + 1.565, 0.54, "hold-out split 60 (30 / 30) — not inspected", size=6.2, color=WHITE, weight="bold")
    c.text(0.1, 0.2, "Samples alternate between the splits within each category; a form is present wherever the real page "
                     "would show one, legitimate or not.", size=6, color=MUTED, ha="left")
    c.save(path)


# ══════════════════════════════════════════════════════════════════════════════
# Chapter 4
# ══════════════════════════════════════════════════════════════════════════════

def architecture(path):
    c = Canvas(6.5, 6.15)
    c.text(0.1, 6.03, "Client–server and multi-modal inference architecture (v3.2.0)", size=8, weight="bold",
           ha="left")
    c.group(0.1, 4.95, 6.3, 0.95, "Client tier — Chrome, Manifest V3 extension (Module 2)", tone="teal", fill="#F7FBFB")
    cs = c.box(0.22, 5.03, 1.8, 0.62, title="Content script", lines=["visible text incl. shadow DOM",
                                                                     "HTML ≤ 3,000,000 chars · overlay"],
               tone="teal", fill="white", size=5.8)
    sw = c.box(2.32, 5.03, 1.95, 0.62, title="Service worker", lines=["fetchWithTimeout 8 s / 12 s",
                                                                      "Bearer key · offline fallback"],
               tone="teal", fill="white", size=5.8)
    pp = c.box(4.55, 5.03, 1.73, 0.62, title="Popup", lines=["verdict · indicators", "report account · health ping"],
               tone="teal", fill="white", size=5.8)
    c.arrow(cs.right, sw.left, color=TEAL, head=4)
    c.arrow(pp.left, sw.right, color=TEAL, head=4)
    c.group(0.1, 3.95, 6.3, 0.85, "Gateway — FastAPI on Uvicorn (one process, asyncio event loop)", tone="navy",
            fill="#F8F9FC")
    mids = [("CORS allow-list", "no credentials"), ("Security headers", "nosniff · no-store"),
            ("Rate limiter", "60/min · login 5/min"), ("Authentication", "API key · admin session"),
            ("Pydantic v2", "URL · 5 MB · patterns")]
    mw = (4.45 - 4 * 0.06) / 5
    for i, (t, s) in enumerate(mids):
        c.box(0.22 + i * (mw + 0.06), 4.03, mw, 0.48, title=t, lines=[s], tone="navy", fill="white", size=5.5,
              title_size=5.9)
    c.text(5.4, 4.32, "router /api/visual", size=5.8, color=TEAL, weight="bold")
    c.text(5.4, 4.17, "(same application)", size=5.6, color=MUTED)
    c.arrow((2.9, 5.03), (2.9, 4.51), color=INK, lw=1, head=5)
    c.text(2.82, 4.88, "↓ POST /api/v1/analyze/semantics  ·  ↑ AnalysisResponse", size=5.6, color=INK, ha="right")
    c.path([(3.9, 5.03), (3.9, 4.88), (6.2, 4.88), (6.2, 3.6)], color=TEAL, lw=0.8, ls="--")
    c.ax.text(5.05, 4.88, "POST /api/visual/analyze", fontsize=5.6, color=TEAL, ha="center", va="center",
              family="Arial", zorder=7, bbox=dict(fc="white", ec="none", pad=0.8))
    c.group(0.1, 1.38, 6.3, 2.42, "Inference tier — parallel detectors and corroborated decision", tone="purple",
            fill="#FAF9FC")
    c.box(0.22, 3.1, 4.45, 0.32, title="DOM sanitiser — BeautifulSoup removes script, style, noscript, meta, link, svg, iframe",
          tone="purple", fill="white", title_size=5.9)
    c.arrow((2.45, 4.03), (2.45, 3.42), color=INK, lw=0.8, head=4)
    dets = [("Whitelist", ["frozenset", "match → SAFE,", "skip BERT"], "green"),
            ("BERT URL", ["to_thread", "128 tokens", "cache 600 s"], "purple"),
            ("Mule scanner", ["8 bank + DuitNow", "regex → IN (?)", "registry lookup"], "purple"),
            ("Brand profiler", ["host · look-alike", "· text mention"], "purple"),
            ("Heuristics +", ["URL structure", "credential form", "scam lexicon"], "purple")]
    dw = (4.45 - 4 * 0.06) / 5
    for i, (t, ls, tone) in enumerate(dets):
        n = c.box(0.22 + i * (dw + 0.06), 2.3, dw, 0.62, title=t, lines=ls, tone=tone, fill="white", size=5.4,
                  title_size=5.9)
        c.arrow((n.cx, 3.1), (n.cx, 2.92), color=LINE, lw=0.6, head=3)
        if i:
            c.arrow((n.cx, 2.3), (n.cx, 2.12), color=LINE, lw=0.6, head=3)
    c.text(3.6, 3.0, "asyncio.gather (BERT || mule scan)", size=5.5, color=MUTED)
    c.box(0.22, 1.48, 4.45, 0.64, title="Verdict engine — 11 boolean signals, rules evaluated in order", lines=[
        "R1 registry match (blocks alone) · R2 brand in foreign host · R3 look-alike domain",
        "R4 brand clone · R5 coercive credential request · R6 evasive infrastructure · else SAFE (advisory < 0.50)"],
          tone="red", fill="white", size=5.5, title_size=6.0)
    c.box(4.85, 1.48, 1.43, 2.12, title="YOLOv8n visual", lines=["(Module 2)", "screenshot ≤ 15 MB", "logo conf ≥ 0.85",
                                                                 "logo vs domain →", "safe / suspicious /", "dangerous",
                                                                 "combined in the", "service worker"],
          tone="teal", fill="white", size=5.5, title_size=6.1)
    c.group(0.1, 0.06, 6.3, 1.17, "Data & operations tier", tone="amber", fill="#FDFBF7")
    c.box(0.22, 0.14, 2.15, 0.72, title="SQLite (WAL, FK on)", lines=["mule_registry · threat_telemetry",
                                                                       "mule_reports (review queue)"],
          tone="amber", fill="white", size=5.6)
    sse = c.box(2.55, 0.14, 1.6, 0.72, title="SSE hub", lines=["one broadcast per", "blocked page"], tone="amber",
                fill="white", size=5.6)
    soc = c.box(4.33, 0.14, 1.95, 0.72, title="SOC dashboard (64 ops)", lines=["admin key or session",
                                                                                "review · export · backup"],
                tone="amber", fill="white", size=5.6)
    c.arrow((1.3, 1.48), (1.3, 0.86), color=AMBER, lw=0.7, head=4)
    c.text(1.35, 1.32, "registry lookup · telemetry insert", size=5.4, color=AMBER, ha="left")
    c.arrow((3.35, 1.48), (3.35, 0.86), color=AMBER, lw=0.7, head=4)
    c.text(3.4, 1.32, "BLOCK → broadcast", size=5.4, color=AMBER, ha="left")
    c.arrow(sse.right, soc.left, color=AMBER, lw=0.7, head=4)
    c.save(path)


def use_case(path):
    c = Canvas(6.5, 4.35)
    c.text(0.1, 4.23, "Use-case model of the PhishGuard-AI backend", size=8, weight="bold", ha="left")
    c.group(1.15, 0.1, 5.25, 3.95, "PhishGuard-AI backend (system boundary)", tone="navy", dashed=False, fill="#FAFBFD")
    c.actor(0.5, 2.75, "End user\n(via extension)")
    c.actor(0.5, 0.75, "SOC analyst /\nadministrator")
    nodes = {}
    for name, y in [("Analyse web page", 3.55), ("Analyse QR code image", 3.05), ("Report suspected mule account", 2.55),
                    ("Analyse screenshot\n(Module 2 router)", 2.05)]:
        nodes[name] = c.usecase(2.2, y, 1.65, 0.4, name, tone="blue", size=5.9)
        c.ax.plot([0.62, nodes[name].x], [3.0, y], color=INK, lw=0.6, zorder=2)
    for name, y in [("Sanitise DOM", 3.75), ("Classify URL (BERT)", 3.33), ("Scan accounts", 2.91), ("Decide verdict (R1–R6)", 2.49)]:
        nodes[name] = c.usecase(4.75, y, 1.55, 0.34, name, tone="grey", size=5.8)
        c.arrow((nodes["Analyse web page"].x + 1.65, 3.55), (nodes[name].x, y), color=LINE, lw=0.5, ls="--", head=3)
    c.text(3.55, 3.86, "«include»", size=5.5, color=MUTED, style="italic")
    for name, y in [("Sign in to dashboard", 1.62), ("Monitor live telemetry (SSE)", 1.2), ("Review mule reports", 0.78),
                    ("Manage mule registry", 0.36)]:
        nodes[name] = c.usecase(2.2, y, 1.75, 0.34, name, tone="amber", size=5.8)
        c.ax.plot([0.62, nodes[name].x], [0.95, y], color=INK, lw=0.6, zorder=2)
    for name, y in [("Export threat intelligence", 1.75), ("Back up / maintain database", 1.3),
                    ("Promote report to registry", 0.6)]:
        nodes[name] = c.usecase(4.85, y, 1.75, 0.36, name, tone="amber", size=5.8)
    c.arrow((nodes["Review mule reports"].x + 1.75, 0.78), (nodes["Promote report to registry"].x, 0.62), color=LINE,
            lw=0.5, ls="--", head=3)
    c.text(3.55, 0.88, "«extend» on APPROVE", size=5.4, color=MUTED, style="italic")
    for name in ("Export threat intelligence", "Back up / maintain database"):
        c.arrow((nodes[name].x, nodes[name].cy), (nodes["Sign in to dashboard"].x + 1.75, 1.62), color=LINE, lw=0.5,
                ls="--", head=3)
    c.text(3.62, 2.0, "dashboard use cases require a session", size=5.4, color=MUTED, style="italic")
    c.save(path)


def activity(path):
    c = Canvas(6.5, 6.55)
    c.text(0.1, 6.43, "Activity diagram — decision flow of POST /api/v1/analyze/semantics", size=8, weight="bold",
           ha="left")
    x = 2.2
    c.dot(x, 6.2)
    prev_y = 6.15
    for y, t in [(5.82, "Validate key, rate limit, schema"), (5.38, "Sanitise DOM → visible text")]:
        c.box(x - 1.05, y - 0.17, 2.1, 0.34, title=t, tone="navy", fill="white", title_size=6.4)
        c.arrow((x, prev_y), (x, y + 0.17), color=INK, lw=0.7, head=4)
        prev_y = y - 0.17
    c.diamond(x, 4.85, 1.5, 0.42, "trusted domain?")
    c.arrow((x, prev_y), (x, 5.06), color=INK, lw=0.7, head=4)
    safe_wl = c.box(4.2, 4.68, 2.1, 0.34, title="SAFE · risk 0.0 · BERT skipped", tone="green", fill="white", title_size=6.3)
    c.arrow((x + 0.75, 4.85), safe_wl.left, color=GREEN, lw=0.7, label="yes", size=5.8, head=4)
    c.arrow((x, 4.64), (x, 4.38), color=INK, lw=0.7, head=4)
    c.text(x + 0.1, 4.52, "no", size=5.8, color=MUTED, ha="left")
    c.bar(x - 1.3, 4.33, 2.6, 0.05, INK)
    b1 = c.box(x - 1.3, 3.72, 1.22, 0.45, title="BERT", lines=["strip_scheme(url)"], tone="purple", fill="white", size=5.8)
    b2 = c.box(x + 0.08, 3.72, 1.22, 0.45, title="Mule scan", lines=["regex → registry"], tone="purple", fill="white", size=5.8)
    for b in (b1, b2):
        c.arrow((b.cx, 4.33), b.top, color=INK, lw=0.6, head=3)
        c.arrow(b.bottom, (b.cx, 3.53), color=INK, lw=0.6, head=3)
    c.bar(x - 1.3, 3.48, 2.6, 0.05, INK)
    c.text(x + 1.4, 4.0, "asyncio.gather", size=5.8, color=MUTED, ha="left")
    pr = c.box(x - 1.05, 2.98, 2.1, 0.34, title="Brand tiers · heuristics · form · lexicon", tone="navy", fill="white",
               title_size=6.0)
    c.arrow((x, 3.48), pr.top, color=INK, lw=0.7, head=4)
    rules = [("R1 registry match?", 0.99), ("R2 brand in host + 1 signal?", 0.97), ("R3 look-alike + cred/BERT/strong?", 0.95),
             ("R4 mention + form + 1 signal?", 0.93), ("R5 form + coercion + BERT/heur?", 0.90),
             ("R6 strong heur + BERT + content?", 0.90)]
    y0 = 2.62
    prev = (x, 2.98)
    block = c.box(4.3, 1.05, 2.0, 0.95, title="BLOCK_RENDER", lines=["INSERT threat_telemetry", "broadcast SSE once",
                                                                       "return rule + indicators"], tone="red", fill="white",
                  size=5.8)
    for i, (t, score) in enumerate(rules):
        yy = y0 - i * 0.39
        c.diamond(x, yy, 2.45, 0.28, t, tone="amber", size=5.6)
        c.arrow(prev, (x, yy + 0.14), color=INK, lw=0.6, head=3)
        if i:
            c.text(x + 0.08, yy + 0.18, "no", size=5.2, color=MUTED, ha="left")
        c.hline(x + 1.225, 4.1, yy, color=RED, lw=0.6, z=3)
        c.text(3.75, yy + 0.08, f"yes → {score:.2f}", size=5.4, color=RED)
        prev = (x, yy - 0.14)
    c.vline(4.1, y0 - 5 * 0.39, y0, color=RED, lw=0.6, z=3)
    c.arrow((4.1, block.cy), block.left, color=RED, lw=0.6, head=3)
    safe = c.box(x - 1.05, 0.06, 2.1, 0.3, title="SAFE · advisory score < 0.50", tone="green", fill="white", title_size=6.3)
    c.arrow(prev, safe.top, color=INK, lw=0.6, head=3)
    c.text(x + 0.08, 0.45, "no", size=5.2, color=MUTED, ha="left")
    c.dot(5.3, 0.21, ring=True)
    c.arrow(safe.right, (5.2, 0.21), color=INK, lw=0.6, head=3)
    c.arrow((block.cx, block.y), (5.3, 0.31), color=INK, lw=0.6, head=3)
    c.path([(safe_wl.x + safe_wl.w, 4.85), (6.42, 4.85), (6.42, 0.21), (5.4, 0.21)], color=GREEN, lw=0.6)
    c.save(path)


def sequence(path):
    c = Canvas(6.5, 6.6)
    c.text(0.1, 6.48, "Request and verdict sequence across client and server (non-whitelisted page)", size=8,
           weight="bold", ha="left")
    lanes = [("Content", "script", "teal"), ("Service", "worker", "teal"), ("FastAPI", "router", "navy"), ("Sanitiser", "", "navy"),
             ("BERT", "thread", "purple"), ("Mule scan", "+ SQLite", "purple"), ("Verdict", "engine", "red"),
             ("YOLOv8n", "router", "teal"), ("SSE /", "dashboard", "amber")]
    lw = 6.3 / len(lanes)
    xs = []
    for i, (a, b, tone) in enumerate(lanes):
        x = 0.1 + i * lw
        c.box(x + 0.03, 5.98, lw - 0.06, 0.36, title=a, lines=[b] if b else [], tone=tone, size=5.8, title_size=6.0)
        xs.append(x + lw / 2)
        c.vline(x + lw / 2, 1.05, 5.98, color="#B8C0CC", lw=0.6, ls=(0, (3, 2)))
    msgs = [
        (0, 1, "ANALYZE {url, html ≤ 3 MB, text}", False),
        (1, 2, "POST /analyze/semantics · abort 8 s", False),
        (1, 7, "POST /api/visual/analyze · screenshot · abort 12 s", False),
        (2, 2, "401 key · 429 rate · 422 schema", None),
        (2, 3, "sanitize_dom(raw_html)", False),
        (3, 2, "visible text", True),
        (2, 2, "trusted? → SAFE, skip BERT", None),
        (2, 4, "predict(strip_scheme(url))", False),
        (2, 5, "scan_and_verify(text) || gather", False),
        (5, 5, "WHERE account_number IN (?, …)", None),
        (5, 2, "accounts_extracted, flagged_accounts", True),
        (4, 2, "label, confidence (softmax)", True),
        (2, 6, "decide(signals)", False),
        (6, 2, "verdict, rule, risk_score, indicators", True),
        (2, 8, "if BLOCK: INSERT telemetry · broadcast once", False),
        (2, 1, "200 AnalysisResponse", True),
        (7, 1, "detected_logos, risk_level", True),
        (1, 0, "overlay / REVIEW / SAFE badge", True),
    ]
    y = 5.82
    for src, dst, label, ret in msgs:
        col = MUTED if ret else INK
        if ret is None:
            c.path([(xs[src], y), (xs[src] + 0.2, y), (xs[src] + 0.2, y - 0.11), (xs[src] + 0.03, y - 0.11)],
                   color=INK, lw=0.6)
            c.text(xs[src] + 0.25, y - 0.055, label, size=5.6, ha="left")
            y -= 0.27
            continue
        c.arrow((xs[src], y), (xs[dst], y), color=col, lw=0.7, ls="--" if ret else "-", head=4)
        left = min(xs[src], xs[dst])
        c.text(left + 0.06, y + 0.075, label, size=5.6, color=col, ha="left")
        y -= 0.26
    c.box(0.1, 0.06, 3.1, 0.82, title="BLOCK_RENDER payload (excerpt)", lines=[
        '"orchestration": "BLOCK_RENDER",', '"decision_rule": "R2_BRAND_IN_HOSTNAME",', '"risk_score": 0.97,',
        '"threat_indicators": ["Hostname embeds …"]'], tone="red", mono=True, size=5.4, align="left", fill="white")
    c.box(3.3, 0.06, 3.1, 0.82, title="SAFE payload (excerpt)", lines=[
        '"orchestration": "SAFE",', '"decision_rule": null,', '"risk_score": 0.1015,',
        '"threat_indicators": ["Mentions \'Maybank\' …"]'], tone="green", mono=True, size=5.4, align="left", fill="white")
    c.save(path)


def class_diagram(path):
    c = Canvas(6.5, 5.35)
    c.text(0.1, 5.23, "Class and module structure of the backend (selected members)", size=8, weight="bold", ha="left")
    W = 2.05
    cols = [0.1, 2.225, 4.35]
    spec = [
        [("SemanticEngine", ["- _tokenizer", "- _model: BertForSequenceClassification"],
          ["+ warm_up()", "- _run_inference(text) → dict", "+ async predict(text) → dict", "+ shutdown()"], "singleton", "navy"),
         ("verdict_engine", [], ["+ decide(...) → Verdict", "+ collect_signals(...) → dict", "+ has_credential_form(html)",
                                 "+ has_credential_text(text)", "+ has_scam_language(text)"], "module", "red"),
         ("Verdict", ["is_threat · verdict · risk_score", "rule · indicators · signals"], ["+ as_dict()"], "dataclass", "red"),
         ("WebPayload", ["url: HttpUrl", "dom_content / text_content ≤ 5 MB"], [], "pydantic", "grey")],
        [("MuleScanner", ["- _bank_patterns: dict", "- _generic_pattern"],
          ["+ async scan_and_verify(text, db)", "+ extract_accounts(text)"], "singleton", "navy"),
         ("brand_profiler", [], ["+ profile_brand_impersonation(url, text)", "- _find_lookalike(host)"], "module", "purple"),
         ("heuristic_engine", [], ["+ analyze_url_heuristics(url) → dict"], "module", "purple"),
         ("domain_utils", [], ["+ registrable_domain(host)", "+ strip_scheme(url)", "+ levenshtein(a, b, max)"], "module",
          "purple"),
         ("AnalysisResponse", ["meta · data · orchestration", "decision_rule · threat_indicators"], [], "pydantic", "grey")],
        [("SemanticResultCache", ["- ttl_seconds = 600"], ["+ hash_key(text)", "+ get(key) / set(key, value)"], None, "navy"),
         ("VisualLogoDetector", ["- _model: YOLO (lazy)", "- _confidence_threshold = 0.85"],
          ["+ detect(screenshot)"], None, "teal"),
         ("repository", [], ["+ check_mule_accounts(list, db)", "+ log_threat_telemetry(url, s, db)",
                             "+ create_mule_report(...)", "+ review_mule_report(id, ok, db)"], "module", "amber"),
         ("security", ["_SESSIONS: dict[str, float]"], ["+ verify_api_key(credentials)", "+ verify_dashboard_access(req)",
                                                        "+ create_dashboard_session()"], "module", "navy"),
         ("MuleReportRequest", ["account_number (6–34)", "bank_name · page_url"], [], "pydantic", "grey")],
    ]
    placed = {}
    for x, column in zip(cols, spec):
        y = 5.0
        for name, attrs, methods, st, tone in column:
            n = c.uml_class(x, y, W, name, attrs, methods, stereotype=st, tone=tone, size=5.5)
            placed[name] = n
            y = n.y - 0.16
    p = placed
    c.arrow((p["verdict_engine"].cx, p["verdict_engine"].y), (p["Verdict"].cx, p["Verdict"].y + p["Verdict"].h),
            color=INK, lw=0.6, head=4)
    for src in ("brand_profiler", "heuristic_engine"):
        c.arrow((p[src].x, p[src].cy), (p["verdict_engine"].x + W, p["verdict_engine"].cy), color=LINE, lw=0.5, ls="--",
                head=3)
    c.arrow((p["MuleScanner"].x + W, p["MuleScanner"].cy), (p["repository"].x, p["repository"].cy), color=LINE, lw=0.5,
            ls="--", head=3)
    c.text(3.25, 0.08, "solid arrow = creates · dashed arrow = depends on · «pydantic» = contracts validated at the API edge",
           size=5.8, color=MUTED)
    c.save(path)


def erd(path):
    c = Canvas(6.5, 4.35)
    c.text(0.1, 4.23, "Physical data model — SQLite 3 (WAL, PRAGMA foreign_keys = ON) and in-memory state", size=8,
           weight="bold", ha="left")
    cx = (0.06, 0.31, 1.25, 1.83)
    reg, ry = c.entity(0.1, 3.98, 3.05, "mule_registry", [
        ("PK", "id", "INTEGER", "AUTOINCREMENT"), ("UQ", "account_number", "TEXT", "NOT NULL · indexed"),
        ("", "bank_name", "TEXT", "NOT NULL"), ("", "platform_flagged", "TEXT", "NOT NULL · default"),
        ("", "report_count", "INTEGER", "NOT NULL · CHECK ≥ 0"), ("", "date_added", "TEXT", "NOT NULL · ISO-8601")],
        col_x=cx)
    rep, py = c.entity(3.35, 3.98, 3.05, "mule_reports", [
        ("PK", "report_id", "INTEGER", "AUTOINCREMENT"), ("", "account_number", "TEXT", "CHECK length 6–34"),
        ("", "bank_name", "TEXT", "default 'Unknown'"), ("", "source", "TEXT", "default 'extension'"),
        ("", "page_url", "TEXT", "NULL"), ("IX", "status", "TEXT", "PENDING/APPROVED/REJ."),
        ("FK", "registry_id", "INTEGER", "→ registry.id, SET NULL"), ("IX", "created_at", "TEXT", "NOT NULL"),
        ("", "reviewed_at", "TEXT", "NULL")], col_x=cx)
    c.entity(0.1, 2.48, 3.05, "threat_telemetry", [
        ("PK", "log_id", "INTEGER", "AUTOINCREMENT"), ("IX", "malicious_url", "TEXT", "NOT NULL"),
        ("", "bert_score", "REAL", "CHECK 0.0–1.0"), ("IX", "timestamp", "TEXT", "NOT NULL · ISO-8601")], col_x=cx)
    c.path([(3.35, py[6]), (3.25, py[6]), (3.25, ry[0]), (3.15, ry[0])], color=RED, lw=0.9)
    c.text(3.25, ry[0] + 0.12, "1", size=6, color=RED, weight="bold")
    c.text(3.25, py[6] - 0.12, "0..N", size=6, color=RED, weight="bold")
    c.group(0.1, 0.64, 3.05, 0.8, "In-memory state (not persisted)", tone="grey")
    c.text(0.2, 1.16, "• dashboard sessions: token_urlsafe(32) → expiry (8 h)", size=5.9, ha="left")
    c.text(0.2, 0.98, "• trusted-domain whitelist: immutable frozenset", size=5.9, ha="left")
    c.text(0.2, 0.8, "• BERT result cache: SemanticResultCache (600 s)", size=5.9, ha="left")
    c.box(3.35, 0.64, 3.05, 1.1, tone="grey", fill="white", edge=LINE, title="Indexes", title_color=INK, align="left", lines=[
        "idx_mule_account_number (account_number)", "idx_telemetry_malicious_url (malicious_url)",
        "idx_telemetry_timestamp (timestamp)", "idx_mule_reports_status (status, created_at)",
        "idx_mule_reports_registry_id (registry_id)"], size=5.6, mono=True, title_size=6.3)
    c.box(0.1, 0.06, 6.3, 0.46, tone="grey", fill="white", edge=LINE, lines=[
        "Writes: registry upsert INSERT … ON CONFLICT(account_number) DO UPDATE; a report is promoted only on analyst APPROVE;",
        "telemetry is written only for BLOCK_RENDER. Key legend: PK primary · UQ unique · FK foreign · IX indexed."],
          size=5.8)
    c.save(path)


def security_layers(path):
    c = Canvas(6.5, 4.85)
    c.text(0.1, 4.73, "Defence-in-depth controls along the request path (v3.2.0)", size=8, weight="bold", ha="left")
    layers = [
        ("L1  Client (Manifest V3)", "teal", ["CSP: script-src 'self' · object-src 'none' · connect-src localhost / https",
                                              "8 s / 12 s AbortController · offline fallback"], "Malicious page script,\nstalled backend"),
        ("L2  Edge policy", "blue", ["CORS allow-list (no wildcard, no credentials)",
                                     "nosniff · X-Frame-Options · Referrer/Permissions-Policy · no-store"],
         "Cross-origin abuse,\nclickjacking, caching"),
        ("L3  Authentication", "navy", ["Analysis API: Bearer key, constant-time comparison",
                                        "64 dashboard operations: admin key or HttpOnly SameSite=Strict session (8 h)"],
         "Forged requests,\nSOC takeover"),
        ("L4  Abuse limits", "purple", ["SlowAPI, per client IP: 60 / min on analysis and report endpoints",
                                        "5 / min on dashboard login"], "Flooding,\nonline key guessing"),
        ("L5  Input validation", "amber", ["Pydantic v2: absolute URL · 5 MB content cap · account pattern 6–34",
                                           "BeautifulSoup strips script and style before analysis"], "Malformed or\noversized input"),
        ("L6  Data integrity", "red", ["parameterised SQL · CHECK and FK constraints",
                                       "reports need analyst APPROVE · immutable whitelist"], "SQL injection,\nregistry poisoning"),
        ("L7  Fault tolerance", "green", ["503 MODEL_INFERENCE_FAILURE handler · telemetry errors never fatal",
                                          "single SSE broadcast per blocked page"], "Model fault,\npartial failure"),
    ]
    h = 0.56
    top = 4.42
    for i, (name, tone, lines, threat) in enumerate(layers):
        inset = i * 0.06
        yy = top - (i + 1) * (h + 0.05)
        c.box(0.1 + inset, yy, 4.75 - 2 * inset, h, tone=tone, fill=TONES[tone][1], radius=0.04)
        c.text(0.2 + inset, yy + h - 0.13, name, size=6.6, weight="bold", color=TONES[tone][0], ha="left")
        c.text(0.2 + inset, yy + 0.26, lines[0], size=5.6, ha="left")
        c.text(0.2 + inset, yy + 0.11, lines[1], size=5.6, ha="left")
        c.box(5.05, yy + 0.06, 1.35, h - 0.12, tone="red", fill="white", lw=0.5, radius=0.03)
        c.text(5.725, yy + h / 2, threat, size=5.7, color=RED)
        c.arrow((4.85 - inset, yy + h / 2), (5.05, yy + h / 2), color=RED, lw=0.5, style="<|-", head=3)
    c.text(5.725, 4.5, "threat mitigated", size=6.2, color=RED, weight="bold")
    c.save(path)


def deployment(path):
    c = Canvas(6.5, 3.05)
    c.text(0.1, 2.93, "Physical deployment (demonstration configuration)", size=8, weight="bold", ha="left")
    c.group(0.1, 0.42, 2.3, 2.3, "Client device", tone="teal", dashed=False, fill="#F7FBFB")
    chrome = c.box(0.22, 1.62, 2.06, 0.78, title="Google Chrome", lines=["PhishGuard-AI extension (MV3)",
                                                                         "settings: apiBaseUrl, apiToken"],
                   tone="teal", fill="white", size=5.8)
    dash = c.box(0.22, 0.55, 2.06, 0.78, title="Dashboard tab", lines=["/dashboard/ (same origin)", "session cookie after sign-in"],
                 tone="teal", fill="white", size=5.8)
    c.group(2.85, 0.42, 3.55, 2.3, "Backend host — AMD Ryzen 7 5700G, 32 GB RAM, CPU only", tone="navy", dashed=False,
            fill="#F8F9FC")
    c.box(2.97, 1.55, 3.31, 0.85, title="uvicorn main:app — port 8000, 1 worker", lines=[
        "FastAPI · event loop · thread pool for BERT", "BERT 438 MB in RAM · YOLOv8n 6.2 MB · cache 600 s",
        "env: PHISHGUARD_API_KEY · _ADMIN_KEY · _RATE_LIMIT · _CORS_ORIGINS"], tone="navy", fill="white", size=5.6)
    c.box(2.97, 0.55, 1.6, 0.85, title="phishguard.db", lines=["SQLite + -wal / -shm", "3 tables · 5 indexes"],
          tone="amber", fill="white", size=5.7)
    c.box(4.68, 0.55, 1.6, 0.85, title="Model files", lines=["phishguard_custom_model/", "visual_identity/models/best.pt"],
          tone="purple", fill="white", size=5.6)
    c.arrow(chrome.right, (2.97, chrome.cy), color=INK, lw=1, head=5, label="HTTP :8000 (loopback)", size=5.6,
            label_dy=0.09)
    c.path([dash.right, (2.62, dash.cy), (2.62, 1.75), (2.97, 1.75)], color=INK, lw=0.7)
    c.text(0.1, 0.25, "Remote deployment: the extension's CSP permits only HTTPS for non-local backends; a Dockerfile "
                      "(python 3.11-slim, CPU wheels, HEALTHCHECK /health) is provided.", size=5.8, ha="left", color=MUTED)
    c.save(path)


# ══════════════════════════════════════════════════════════════════════════════
# Chapter 6
# ══════════════════════════════════════════════════════════════════════════════

def hosting_comparison(path):
    c = Canvas(6.5, 2.55)
    c.text(0.1, 2.43, "Where page content travels: self-hosted inference (adopted) versus a remote AI API", size=8,
           weight="bold", ha="left")
    for x, title, tone, steps, foot in [
        (0.1, "Adopted — self-hosted", "green", ["Browser", "Backend you\noperate", "BERT + rules\nin memory"],
         ["page text never leaves operator infrastructure", "no per-request fee; capacity = hardware",
          "measured: median 190 ms; ~10 inferences/s per CPU worker"]),
        (3.3, "Alternative — remote AI API", "amber", ["Browser", "Backend", "Third-party\nmodel API"],
         ["page text (may hold personal data) leaves the organisation", "per-request cost and provider rate limits",
          "adds WAN round trip and provider queueing (not measured)"])]:
        c.group(x, 0.08, 3.1, 2.15, title, tone=tone, dashed=False)
        prev = None
        for i, s in enumerate(steps):
            parts = s.split("\n")
            n = c.box(x + 0.12 + i * 1.0, 1.25, 0.86, 0.55, title=parts[0], lines=parts[1:], tone=tone, fill="white",
                      title_size=6.1, size=6.1)
            if prev:
                c.arrow(prev.right, n.left, color=TONES[tone][0], lw=0.8, head=4)
            prev = n
        for j, f in enumerate(foot):
            c.text(x + 0.15, 0.95 - j * 0.28, "• " + f, size=5.9, ha="left")
    c.save(path)


def challenges(path):
    rows = [
        ("False positives on legitimate pages", "URL model fed page text; single-signal blocking; substring keywords",
         "Input realigned to scheme-stripped URL; corroboration rules R1–R6; word-boundary matching",
         "FPR 78.33 % → 0.00 %\nBERT AUC 0.704 → 0.860"),
        ("Event loop blocked by inference", "PyTorch forward pass is CPU-bound inside an async handler",
         "asyncio.to_thread + gather; whitelist bypass before any inference",
         "200 users: whitelist p50 45 ms\nwhile BERT path queued"),
        ("GPU session limits during training", "Colab sessions expire; 439,476 sequences to train",
         "One epoch at batch 16; checkpoints written to Google Drive", "27,468 steps in 3 h 03 min\nvalidation loss 0.0497"),
        ("Open administrative surface", "64 dashboard operations had no authentication",
         "Admin key / HttpOnly session; login 5/min; CORS allow-list", "anonymous access → 401\n20 security tests pass"),
    ]
    heads = [("Challenge", 1.3, "red"), ("Root cause", 1.6, "amber"), ("Resolution", 1.85, "navy"), ("Measured effect", 1.55, "green")]
    rh = 0.56
    c = Canvas(6.5, 0.72 + rh * len(rows))
    c.text(0.1, c.H - 0.12, "Engineering challenges: root cause, resolution and measured effect", size=8, weight="bold",
           ha="left")
    x = 0.1
    xs = []
    top = c.H - 0.5
    for t, w, tone in heads:
        c.box(x, top, w - 0.05, 0.22, tone=tone, fill=TONES[tone][0], radius=0.03)
        c.text(x + (w - 0.05) / 2, top + 0.11, t, size=6.5, weight="bold", color=WHITE)
        xs.append((x, w))
        x += w
    for i, row in enumerate(rows):
        y = top - 0.05 - (i + 1) * rh
        for j, (cell, (x, w)) in enumerate(zip(row, xs)):
            tone = heads[j][2]
            c.box(x, y, w - 0.05, rh - 0.05, tone=tone, fill=TONES[tone][1], radius=0.03, lw=0.5)
            for k, ln in enumerate(_wrap(cell, w - 0.16, 5.8)[:3]):
                c.text(x + 0.06, y + rh - 0.05 - 0.13 - k * 0.13, ln, size=5.8, ha="left",
                       weight="bold" if j == 3 else "normal", color=GREEN if j == 3 else INK)
    c.save(path)


def roadmap(path):
    c = Canvas(6.5, 1.75)
    c.text(0.1, 1.63, "Roadmap from the evaluated prototype to a deployable service", size=8, weight="bold", ha="left")
    cols = [("Now (v3.2.0, measured)", "navy", ["English URL BERT, random split", "120-page authored benchmark",
                                                "1 CPU worker ≈ 10 inferences / s", "SQLite + in-memory sessions",
                                                "simulated mule registry"]),
            ("Next (data & capacity)", "teal", ["multilingual page-content model", "temporal, domain-disjoint evaluation",
                                                "real labelled Malaysian corpus", "distilled model, more workers",
                                                "shared session & rate-limit store"]),
            ("Later (integration & operations)", "purple", ["authorised NSRC / BNM data channels", "continuous retraining (MLflow)",
                                                            "replicas behind a load balancer", "drift & false-positive monitoring",
                                                            "independent security review"])]
    w = 2.0
    for i, (t, tone, items) in enumerate(cols):
        x = 0.1 + i * (w + 0.15)
        c.box(x, 0.06, w, 1.4, title=t, lines=items, tone=tone, header=True, size=6.0, title_size=6.6, align="left")
        if i:
            c.arrow((x - 0.15, 0.76), (x, 0.76), color=INK, lw=1, head=5)
    c.save(path)
