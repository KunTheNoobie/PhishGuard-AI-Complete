# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="105"/>
  <h3>Explainable phishing, quishing and mule-account protection for every website</h3>
  <p>A Manifest V3 browser extension and a FastAPI backend that combine a fine-tuned BERT URL classifier, URL canonicalisation, brand-impersonation profiling, page analysis, the connection's HTTPS status, DuitNow QR decoding and a Malaysian mule-account registry — and explain every verdict in plain language.</p>

  [![CI/CD Test Pipeline](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions/workflows/test.yml/badge.svg)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions)
  [![Tests: 140 Passed](https://img.shields.io/badge/Tests-140%20Passed-brightgreen)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete)
  [![Version](https://img.shields.io/badge/Version-v4.1.0-009688.svg?logo=fastapi&logoColor=white)](CHANGELOG.md)
  [![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
  [![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
</div>

---

## Overview

**PhishGuard-AI** is a final-year project (BMCS3404 / BMCS3414, TAR UMT). The browser extension sends every page
the user opens to the backend, which returns one of three verdicts:

| Verdict | Colour | What the user sees |
|---|---|---|
| `SAFE` | green | nothing (the popup shows a green status) |
| `WARNING` | amber | a "Not secure" banner at the top of the page — for example a plain-HTTP site |
| `BLOCK_RENDER` | red | a full-screen block page with the reasons and a **Back to safety** button |

No single model blocks a page. A page is blocked only when independent signals agree (for example a bank name in a
foreign hostname *and* a password field), or when a deterministic rule fires: a registered mule account, a disguised
`bank.com@evil.top` link, or a password/card form sent over plain HTTP. Every response carries a headline, a
plain-language explanation and the list of reasons.

| | |
|---|---|
| **Supervisor** | Dr. Ng Yen Phing |
| **Module 1 — Backend, BERT engine, mule scanner, SOC dashboard** | Liew Yi Ler (25WMR09747) |
| **Module 2 — Chrome extension, YOLOv8n logo detection** | Cheon Jie Han (25WMR09703) |

### Measured results (v4.1.0)

```
Malaysian benchmark (120 pages)   57/60 scams blocked, 0/60 legitimate pages blocked
                                   accuracy 97.5%  precision 1.000  recall 0.950  F1 0.974  ROC-AUC 0.983
Baselines (F1 / false-positive)    padlock 0.775 / 0%   lexical 0.581 / 1.7%   BERT alone 0.763 / 43.3%
HTTPS scam pages (22)              PhishGuard 91% caught   padlock 0%
Public URL suite (30 cases)        28 passed (2 hosts unreachable from the test network)
Latency (CPU)                      BERT path p50 116 ms, p95 139 ms; trusted sites about 1 ms
Automated tests                    140 passed, 80% statement + branch coverage
BERT hold-out (109,870 URLs)       accuracy 98.76%, F1 97.80%
```

---

## Features

### 1. Browser extension (`chrome_extension/`)
- Scans **every** `http://` and `https://` page, not only banking sites.
- **Online-first:** uses `https://phishguard-ai-backend-j74v.onrender.com` and falls back to the local server
  `http://127.0.0.1:8000`. The popup's settings choose *Automatic*, *Online only* or *Local only*, hold both server
  addresses and the API key, and the popup shows which server answered.
- Shadow-DOM block page and amber HTTP banner, so the site's own CSS cannot hide or restyle them.
- Offline rule: if no server answers, plain-HTTP pages are still marked *Not secure* — HTTP is never shown as safe.
- **Proceed anyway** allows a blocked site for 24 hours, and **Report account** sends a suspected mule account to the analyst queue.

### 2. Backend analysis (`services/`)
- **URL canonicalisation** — userinfo (`@`) tricks, IDN/punycode and Unicode confusables, integer/hex/octal IP
  addresses, backslashes, case and default ports are normalised before any check.
- **Brand registry** — 49 organisations (every licensed Malaysian bank and digital bank, the e-wallets and payment
  networks, and major global banks and payment brands) with 110 official domains, look-alikes and keywords.
- **BERT URL classifier** — fine-tuned `bert-base-uncased`, used as one signal among many.
- **Page analysis** — password/card/OTP fields, credential wording, a multilingual scam lexicon (English, Bahasa
  Melayu, Manglish), evasive infrastructure, free-hosting platforms and certificate errors.
- **Mule accounts** — contiguous, spaced (`5142 7610 3388`), hyphenated (`5142-7610-3388`) and `+60` forms are
  extracted; amounts and Luhn-valid card numbers are ignored.
- **QR codes** — DuitNow/EMVCo payloads are parsed and their accounts checked; URL payloads go through the full
  pipeline.
- **YOLOv8n logo detector** (partner module) — a bank logo on a foreign domain is a signal.
- **Safe page fetcher** — public IPs only, re-checked on every redirect; 8 s, 1.5 MB and 5 redirects at most.

### 3. HTTP vs HTTPS policy

| Page | Verdict |
|---|---|
| `https://` with no phishing signals | `SAFE` |
| `http://` without a sensitive form (e.g. `http://neverssl.com`, `http://httpforever.com`) | `WARNING` — not secure |
| `http://` with a login, password, payment or other sensitive form (e.g. `http://testphp.vulnweb.com/login.php`) | `BLOCK_RENDER` |
| Certificate error (e.g. `https://expired.badssl.com`) | `WARNING` |

### 4. SOC dashboard (`/dashboard/`) — four tabs, real data only
| Tab | What it shows |
|---|---|
| **Overview** | Total scans, blocked phishing, insecure-HTTP warnings, safe sites; the live scan log with a verdict filter and CSV/JSON export |
| **Mule Registry** | Review queue of user reports (approve / reject) and the searchable registry (add / delete) |
| **QR Scanner** | Upload a QR image; it is decoded and run through the full pipeline |
| **URL Analyzer** | Analyse any address live, with the step-by-step breakdown and the reasons |

Every counter is computed from the `scan_log` table; nothing on the dashboard is simulated.

---

## API

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/v1/analyze` | API key | Analyse a page (used by the extension) |
| `POST /api/v1/analyze/qr` | API key | Analyse a decoded QR payload |
| `POST /api/v1/mule-reports` | API key | Report a suspected mule account (enters the review queue) |
| `GET /health` | none | Service and model status |
| `/api/v1/dashboard/*` (13 operations) | admin key or session | Dashboard data, registry, review queue, exports, QR and live analysis |

Interactive documentation: `/docs` (links only to the Dashboard and the API docs).

Example:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Authorization: Bearer 12345678" -H "Content-Type: application/json" \
  -d '{"url": "https://maybank2u.com.my@evil-login.top/"}'
```

returns `"verdict": "BLOCK_RENDER"`, `"rule": "R7_USERINFO_SPOOF"` and an explanation of the disguised link.

---

## Quick start (local)

**One click (Windows):** double-click **`setup.bat`**. It runs `git lfs install` and `git lfs pull` (model weights), creates `venv`, installs `requirements.txt` (about 4 GB the first time) and copies `.env.example` to `.env` (admin key `12345678`). Then double-click `run_server.bat`.

Manual steps:

```bash
python -m venv venv
venv\Scripts\activate            # macOS / Linux: source venv/bin/activate
pip install -r requirements.txt  # add requirements-dev.txt for tests and evaluation
copy .env.example .env           # optional; defaults work for a demo
uvicorn main:app --host 127.0.0.1 --port 8000
```

Or double-click `run_server.bat`. Then open:

- Dashboard: <http://127.0.0.1:8000/dashboard/> — sign in with the admin key
- API docs: <http://127.0.0.1:8000/docs>
- Extension: `chrome://extensions` → Developer mode → **Load unpacked** → `chrome_extension/`

The model weights (`phishguard_custom_model/`, `visual_identity/models/`) are stored with **Git LFS**: run `git lfs install && git lfs pull` after cloning (`setup.bat` does this). Without them the service still runs, with the BERT and logo signals switched off.

**Demonstration keys.** `PHISHGUARD_API_KEY` and `PHISHGUARD_ADMIN_KEY` both default to `12345678`. Replace them
with long random values for any real deployment:
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.

---

## Online deployment (Render, free HTTPS web service)

Live and verified on 17 November 2026: `https://phishguard-ai-backend-j74v.onrender.com` (`/health`, `/dashboard/`, `/docs`).

`render.yaml` defines a free Docker web service (`phishguard-ai-backend`, health check `/health`, admin key `12345678`). To publish:

1. Sign in at render.com with GitHub, choose **New + → Blueprint**, and select this repository (`PhishGuard-AI-Complete`). Render reads `render.yaml`.
2. Render builds the `Dockerfile`: CPU-only PyTorch, `libzbar0` and `libgl1`; then `scripts/fetch_lfs_weights.py` replaces the Git LFS pointer files with the real 445 MB of weights from GitHub, and `scripts/quantize_bert.py` builds the small int8 BERT (about 105 MB).
3. After the first build (about 10-15 minutes) check `https://phishguard-ai-backend-j74v.onrender.com/health`.

**Memory (512 MB free tier).** BERT runs as an int8 TorchScript model on one thread inside `torch.inference_mode()` and the heap is trimmed after loading (`services/nlp_engine.py`); the larger YOLOv8n logo detector is switched off on Render (`PHISHGUARD_ENABLE_VISUAL=false`) and can be enabled on a bigger plan. Measure with `python -m evaluation.measure_memory`.

The free tier sleeps after 15 minutes without traffic (the first request wakes it in about a minute) and resets its SQLite file on restart; the demonstration dataset is reloaded automatically on every start.

**Demonstration dataset.** An empty database is filled at start-up from `database/demo_threat_intel.json`: 45 curated mule-account records, 30 recent scan-log rows (real pipeline verdicts for URLs from the OpenPhish community feed, public test sites, a mule page and a QR code) and four pending reports. Set `PHISHGUARD_SEED_DEMO=false` to disable it; `python -m evaluation.build_demo_seed` rebuilds it.

---

## Testing and evaluation

```bash
pip install -r requirements-dev.txt
python -m pytest --cov --cov-branch                        # 140 tests
python -m evaluation.evaluate_pipeline --tag final_v4.1.0  # 120-page Malaysian benchmark (real BERT)
python -m evaluation.compare_baselines --tag final_v4.1.0  # padlock, lexical, BERT-alone baselines and ROC
python -m evaluation.run_public_suite                      # 30 public URLs and scam patterns (live)
python -m evaluation.run_public_suite --base-url https://phishguard-ai-backend-j74v.onrender.com
python -m evaluation.make_report_figures                   # charts in report/figures/
python report/diagrams_drawio/update_v4.py                 # draw.io diagrams
```

Results are written to `evaluation/results/` (`final_v4.1.0`, `ablation_no_bert_v4.1.0`, `public_suite_v4.1.0`,
`pytest`, `coverage`, `locust`).

---

## Security model

| Control | Implementation |
|---|---|
| API authentication | `Authorization: Bearer <PHISHGUARD_API_KEY>`, constant-time comparison (`core/security.py`) |
| Dashboard authentication | Admin key (bearer) or a server-side session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS); 5 login attempts per minute |
| Rate limiting | SlowAPI per client IP, default `60/minute` |
| CORS | Explicit origin list plus `chrome-extension://` origins; never `*` |
| Input validation | Pydantic v2 schemas; only `http`/`https` URLs; 5 MB page cap |
| SSRF | Page fetcher resolves and checks every hop; private, loopback and link-local addresses are refused |
| SQL injection | Parameterised queries only |
| Registry integrity | User reports wait in a `PENDING` queue; nothing is added to the registry without an analyst |
| Privacy | The scan log stores scheme, host and path only — never query strings or page content |
| CSV export | Cells starting with `=`, `+`, `-` or `@` are neutralised |
| Response headers | `X-Content-Type-Options`, CSP `frame-ancestors 'self'`, `Referrer-Policy`, `Permissions-Policy`, HSTS over HTTPS |

**Known limitations.** The mule registry holds demonstration accounts (Semakmule has no public API). The BERT model
was trained on English-language URLs and over-scores some well-known domains; corroboration keeps those pages
`SAFE`. The logo detector was trained on a synthetic dataset of five banks. A page the dashboard cannot download is
judged on its URL alone.

---

## Repository layout

```
main.py                 FastAPI app, security headers, /docs, /health
api/                    public endpoints and dashboard endpoints
core/                   configuration, brand registry, security
services/               analysis pipeline, canonicaliser, verdict engine, BERT, YOLO, mule and QR scanners, fetcher
database/               schema, seed data and repository functions (SQLite, WAL)
schemas/                request and response models
dashboard/              four-tab SOC dashboard (HTML, CSS, JS)
chrome_extension/       Manifest V3 extension (service worker, content script, popup)
evaluation/             benchmark, baselines, public suite, figures and results
tests/                  pytest suite
render.yaml, Dockerfile  Render deployment (scripts/ holds the weight fetch and int8 build)
report/                 dissertation, figures and draw.io diagram sources
```

---

## License and attribution

Final Year Project (BMCS3404 Project I / BMCS3414 Project II), Bachelor of Information Technology (Honours) in
Information Security, Faculty of Computing and Information Technology, Tunku Abdul Rahman University of Management
and Technology (TAR UMT). Supervisor: Dr. Ng Yen Phing.
