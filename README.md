# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="105"/>
  <h3>Multi-Modal Financial Scam Detection for Malaysian Online Banking</h3>
  <p>Real-time phishing, quishing and mule-account detection combining a fine-tuned BERT URL classifier, YOLOv8 logo detection, DuitNow QR decoding, brand-impersonation profiling and a corroborated verdict engine.</p>

  [![CI/CD Test Pipeline](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions/workflows/test.yml/badge.svg)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions)
  [![Tests: 198 Passed](https://img.shields.io/badge/Tests-198%20Passed-brightgreen)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete)
  [![PhishGuard-AI](https://img.shields.io/badge/Version-v3.2.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
  [![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B%20%2F%203.14-blue.svg?logo=python&logoColor=white)](https://python.org)
  [![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
</div>

---

## 📖 System Overview & Abstract

**PhishGuard-AI** is a final-year project (BMCS3404 / BMCS3414, TAR UMT) that protects Malaysian online-banking users from financial phishing, quishing (QR-code fraud), brand impersonation and money-mule accounts. A Manifest V3 Chrome extension sends each page to a FastAPI backend, which combines several independent detectors and returns a `BLOCK_RENDER` or `SAFE` verdict.

No single probabilistic signal blocks a page. The backend's **corroborated verdict engine** blocks only when independent signals agree (for example a bank name in a foreign hostname *and* a password field), with one exception: a match against the mule-account registry.

| | |
|---|---|
| **Supervisor** | Dr. Ng Yen Phing |
| **Module 1 — Backend, BERT engine, mule scanner, SOC dashboard** | Liew Yi Ler |
| **Module 2 — Chrome extension, YOLOv8 logo detection** | Cheon Jie Han |

### Measured results (v3.2.0)

| Measurement | Result | Evidence |
|---|---|---|
| BERT URL classifier, Kaggle hold-out (109,870 URLs) | accuracy 98.76 %, precision 98.77 %, recall 96.85 %, F1 97.80 % | `evaluation/results/kaggle_holdout/` |
| End-to-end pipeline, Malaysian benchmark (120 hand-curated pages) | accuracy 97.50 %, precision 100 %, recall 95.00 %, false-positive rate 0 % | `evaluation/results/final_v3.2.0/` |
| Same benchmark before the v3.2.0 fixes | accuracy 57.50 %, false-positive rate 78.33 % | `evaluation/results/baseline_v3.0.0/` |
| Load test, 50 concurrent users, 60 s (CPU inference) | 22.4 req/s, 0 errors, p50 13 ms, p95 370 ms, p99 490 ms | `evaluation/results/locust/` |
| Automated tests | 198 passed, 77 % statement + branch coverage | `evaluation/results/pytest/` |

The benchmark is small and its page text was written for this project; see [evaluation artefacts](#-evaluation-artefacts-v320) below for the method, caveats, ablation and limitations before quoting these figures.

Detection layers:

```
+----------------------------------------------------------------------------------------------------+
|                                    PHISHGUARD MULTI-MODAL PIPELINE                                 |
+----------------------------------------------------------------------------------------------------+
|  1. BERT URL Classifier          --> bert-base-uncased fine-tuned on 439,476 labelled URLs          |
|  2. Visual Brand Classifier      --> YOLOv8n detection of 5 Malaysian bank logos in screenshots    |
|  3. Mule & DuitNow Registry      --> Regex extraction + indexed SQLite lookup (simulated registry) |
|  4. EMVCo PayNet QR Decoder      --> Unmasks hidden payment beneficiary proxies in QR code images   |
|  5. Brand Impersonation Profiler --> Brand-in-hostname, look-alike domain and text-mention tiers   |
|  6. Network & Domain Heuristics  --> Raw-IP hosts, punycode, high-risk TLDs, deep subdomain chains  |
|  7. Corroborated Verdict Engine  --> Rules R1-R6 combine the signals; exports for SOC tooling      |
+----------------------------------------------------------------------------------------------------+
```

---

## 🚀 Core Capabilities & Features

### 1. 🛡️ Chrome Extension (Manifest V3)
* **⚡ Real-Time Interception:** Background analysis on page navigation with cached verdict lookup; backend calls time out after 8 s (semantic) / 12 s (visual) and fall back to offline heuristics.
* **🌍 Universal Web & SPA Support:** Deep recursive extraction across Shadow DOM roots (`node.shadowRoot`), same-origin iframes, form placeholders, and accessibility labels.
* **Full-Screen Block Overlay (`BLOCK_RENDER`):** Replaces dangerous phishing portals with a high-impact red defense shield detailing exact threat vectors and giving an immediate escape path.
* **Explainable AI (XAI) Multi-Lingual Highlighter:** Highlights psychological coercion cues in English, Bahasa Melayu, Chinese (Simplified/Traditional), and Bahasa Indonesia.
* **🛡️ Trusted Sites & Whitelist Manager:** Dedicated "Trusted Sites" tab inside the popup allowing users to inspect active domain exemptions, view remaining expiration times, and revoke whitelists instantly.
* **📡 Real-Time SOC Ping & Latency Meter:** Displays live backend connection status and round-trip latency in milliseconds (`● SOC (18ms)`) with automatic fallback to autonomous offline protection.
* **📋 1-Click Scan Verdict Exporter:** Formats and copies full cryptographic threat verdict summaries to clipboard for incident ticketing.
* **🚨 Mule Account Reporting:** Reports a suspicious account from the popup to the backend review queue (`POST /api/v1/mule-reports`); an analyst approves it before it joins the blocking registry.
* **Dynamic Action Badges:** Toolbar badge updates in real time (`OK` in Green `#10b981`, `?` in Amber `#f59e0b`, `!` in Red `#ef4444`).

---

### 2. 📊 Live Threat Intelligence & SOC Dashboard (`/dashboard/`)
* **Admin Threat Inspector (Instant Multi-Modal Scanner):** Analyze any URL or scam text directly from the dashboard with automated HTML fetching, BERT classification, and mule detection.
* **🔊 Master Audio Alert Quick-Toggle (<kbd>M</kbd>):** Real-time synthesized threat sound effects toggleable via header button or hotkey <kbd>M</kbd>.
* **🔍 Global Multi-Filter Telemetry Hunting:** Live filtering across target institutions (Maybank, CIMB, Public Bank, RHB, Hong Leong, TNG, DuitNow), AI risk confidence, and free-text hunting queries.
* **⚡ Enterprise SOC Defense War Room:** Fullscreen cyber defense visualization featuring:
  - Dynamic SVG/Canvas global attack trajectory arcs originating from 6 major hosting hubs (Kuala Lumpur, Singapore, San Jose, Frankfurt, Hong Kong, Tokyo).
  - **DEFCON Cyber Readiness Controls (DEFCON 1 Emergency Lockdown, DEFCON 2 Elevated, DEFCON 3 Normal)** with glowing visual states.
  - Sovereign Loss Prevention Tracker computing shielded financial assets.
  - Live intercept ticker streaming real-time detections.
* **📷 Quishing (QR-Code Phishing) Optical Forensic Decoder:**
  - Drag-and-drop file upload dropzone, optical camera/file picker, and direct clipboard image pasting (`Ctrl+V`).
  - Powered by OpenCV `cv2.QRCodeDetector()` and PIL to decode payment proxies, DuitNow P2P targets, and obfuscated URLs.
* **🏛️ Malaysian National Anti-Scam NSRC 997 & NFP Gateway:**
  - Automated case escalation and National Fraud Portal (NFP) account freezing with persistent state retention across reloads.
  - **1-Click PDRM CCID & NSRC 997 Police Dispatch Export**: Auto-formats forensic telemetry into official Malaysian law enforcement dispatch format.
* **🎯 Pre-Emptive Typosquatting & Homoglyph Protection Radar:**
  - Detects Unicode homoglyph attacks, character permutations, and bit-squatting variants across monitored banking domains.
* **🛡️ Automated DNS Sinkhole & SIEM Firewall Exporter:**
  - Real-time generation of Pi-hole blocklists, BIND9 RPZ response policies, and Cloudflare DNS Firewall rules.
* **📜 Auto-Generated YARA & Suricata / Snort Rulesets:**
  - 1-click dynamic rule generation for threat hunting and network perimeter firewalls.
* **🎯 MITRE ATT&CK® v14.1 Enterprise Matrix & CTI Mapping:**
  - Interactive matrix mapping detected threats to standard adversary techniques (*T1566.002 Spearphishing Link*, *T1078 Valid Accounts*, *T1584.004 DNS Serverless Typosquatting*).
* **🏹 Enterprise Security Awareness & Phishing Red-Team Simulator:**
  - Standardized attack scenarios (`SAT-MY-001` through `SAT-MY-005`) for simulating staff phishing awareness campaigns.
* **✨ Dynamic Chart Hover Glow & Tooltip Micro-Animations:**
  - Real-time Threat Velocity bar chart with interactive floating tooltips showing attack rates, share percentages, and timestamp intervals.
  - Dynamic donut chart slice expansion and synchronized legend filtering.
* **⚙️ Multi-Channel SOC Alert Webhooks:**
  - Instant dispatch to Discord, Slack, and Telegram with 1-click demo sample testing.
* **💾 Database Maintenance & Hot Backup:**
  - Live SQLite WAL checkpointing, size auditing, VACUUM optimization, and downloadable hot backups (`.sqlite3`).
* **📥 Standardized Intelligence Exporters:**
  - Single-click export of threat telemetry and mule accounts in **CSV, JSON, OASIS STIX 2.1 JSON Bundle, CEF, and RFC 5424 Syslog**.

---

### 3. 🧪 Threat Simulation Sandbox & Custom Laboratory (`/dashboard/sandbox.html`)
* Interactive demonstration sandbox with multi-vector threat radar breakdown:
  1. **Scenario 1 • Phishing:** Deceptive Maybank2u credential & TAC harvesting clone.
  2. **Scenario 2 • Mule Account:** PDRM traffic summons scam redirecting payments to fraudulent mule accounts.
  3. **Scenario 3 • Quishing (QR Phishing):** Fake government cash aid portal with PayNet EMVCo QR code payloads.
  4. **Scenario 4 • Benchmark:** Authentic Malaysian banking portal for false-positive validation.
  5. **Scenario 5 • Custom Payload Laboratory:** Interactive playground to enter custom URLs and raw DOM payloads for live multi-modal AI inference.
* **📊 Multi-Vector Threat Radar Breakdown:** Dynamic neon progress bars quantifying BERT Semantic probability, Brand Impersonation Index, Mule/DuitNow match status, and domain heuristic indicators.

---

### 4. 🎯 Interactive Honeypot Target (`/dashboard/test_scam.html`)
* Multi-vector honeypot attack switcher:
  - **Vector A**: Maybank2u TAC Harvesting Portal
  - **Vector B**: PDRM Traffic Summons Alert
  - **Vector C**: KWSP / EPF Special Aid Grant Claim
  - **Vector D**: PayNet DuitNow QR Quishing Target

---

### 5. 🏦 10-Bank Malaysian Impersonation & Global Whitelist Matrix

Brand profiles and trusted-domain whitelisting for leading financial entities and global platforms (the YOLOv8 logo detector covers the first five banks):
1. **Maybank (Malayan Banking Berhad)**
2. **CIMB Bank Berhad**
3. **Public Bank Berhad**
4. **RHB Bank Berhad**
5. **Hong Leong Bank Berhad**
6. **AmBank (M) Berhad**
7. **Bank Islam Malaysia Berhad**
8. **Touch 'n Go eWallet (TNG Digital)**
9. **GrabPay Malaysia**
10. **ShopeePay Malaysia**
11. **Global Tech, Cloud & Banking:** Google, Microsoft, Apple, Amazon, PayPal, Chase, HSBC, DBS, OpenAI, Meta, WhatsApp, etc.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend Framework** | Python 3.11+ / 3.14, FastAPI, Uvicorn, AsyncIO |
| **AI / Machine Learning** | PyTorch, Hugging Face Transformers (`bert-base-uncased`, 1 epoch on 439,476 URLs), Ultralytics (YOLOv8n) |
| **Database & Persistence** | SQLite 3 in WAL mode (3 tables, 1 foreign key, 5 indexes), `aiosqlite` |
| **Real-Time Streaming** | Server-Sent Events (SSE) via `asyncio.Queue` broadcast |
| **Frontend Dashboard** | HTML5, Vanilla JavaScript (ES6+), High-Contrast Glassmorphism CSS, SVG Canvas |
| **Threat Sharing Formats** | OASIS STIX 2.1 JSON, ArcSight/Splunk CEF, RFC 5424 Syslog, CSV |
| **Testing & CI/CD** | Pytest + pytest-asyncio + pytest-cov (198 tests, 77 % coverage), Locust, GitHub Actions |

---

## ⚙️ Quickstart Guide

### 1. Clone & Setup Virtual Environment
```bash
git clone https://github.com/KunTheNoobie/PhishGuard-AI-Complete.git
cd PhishGuard-AI-Complete

# Create & activate virtual environment
python -m venv venv
.\venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure (optional for a local demo)
```bash
copy .env.example .env      # Linux/macOS: cp .env.example .env
```
`core/config.py` loads `.env` automatically. For anything beyond a local demonstration set
`PHISHGUARD_API_KEY` and a separate `PHISHGUARD_ADMIN_KEY`; the server logs a warning while
the public development key is in use.

### 4. Launch Backend Server & Dashboard
```bash
# Option A: Double click run_server.bat
run_server.bat

# Option B: Run via terminal
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Access Interactive Interfaces
* **Live SOC Threat Dashboard:** [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/) — sign in with the admin key (`PHISHGUARD_ADMIN_KEY`, or `PHISHGUARD_API_KEY` if no admin key is set)
* **Threat Simulation Sandbox:** [http://127.0.0.1:8000/dashboard/sandbox.html](http://127.0.0.1:8000/dashboard/sandbox.html)
* **Simulated Scam Target:** [http://127.0.0.1:8000/dashboard/test_scam.html](http://127.0.0.1:8000/dashboard/test_scam.html)
* **OpenAPI / Swagger Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧪 Automated Testing & Evaluation

```powershell
.\venv\Scripts\python.exe -m pytest --cov --cov-report=term
```

```
collected 198 items

tests\test_endpoints.py .........................                        [ 12%]
tests\test_enhancements.py ..............................................  [ 35%]
tests\test_mule_reports.py ............                                   [ 41%]
tests\test_mule_scanner.py ..............                                 [ 48%]
tests\test_nlp_engine.py .........                                        [ 53%]
tests\test_repository.py ........                                         [ 57%]
tests\test_sanitizer.py .............                                     [ 64%]
tests\test_security.py ....................                               [ 74%]
tests\test_verdict_engine.py ...........................................  [ 95%]
tests\test_visual.py ........                                             [100%]

TOTAL                              2788    542    668    105    77%
====================== 198 passed, 3 warnings in 12.76s =======================
```

Unit tests mock the BERT engine and use an in-memory database. The real model is exercised by
the evaluation harness:

```powershell
.\venv\Scripts\python.exe -m evaluation.evaluate_pipeline --tag final_v3.2.0   # 120-page Malaysian benchmark
.\venv\Scripts\python.exe -m evaluation.kaggle_holdout_metrics                 # hold-out confusion matrix
.\venv\Scripts\python.exe -m locust -f tests/locustfile.py --host http://127.0.0.1:8000 --headless -u 50 -r 5 -t 60s
```

Results, method and limitations: [evaluation artefacts](#-evaluation-artefacts-v320). Release notes: [`CHANGELOG.md`](CHANGELOG.md).

---

## 📐 Evaluation artefacts (v3.2.0)

Every quantitative claim in the dissertation is traceable to a file under `evaluation/`.
All numbers below were produced on the development machine:

| Item | Value |
|---|---|
| CPU / RAM | AMD Ryzen 7 5700G (8 cores / 16 threads), 32 GB |
| GPU | none used for inference (PyTorch 2.12.1 CPU build, 8 intra-op threads) |
| OS / Python | Windows 11, Python 3.14.3 |
| Model | `bert-base-uncased` fine-tuned for 1 epoch (27,468 steps) on 439,476 URLs |
| Date of runs | 16 November 2026 |

### 1. BERT URL classifier — Kaggle hold-out (109,870 URLs)

Source: the Colab training run (`trainer_state.json`, epoch 1.0 evaluation).
`evaluation/kaggle_holdout_metrics.py` reconstructs the confusion matrix that is uniquely
implied by the logged accuracy, precision, recall and F1.

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Actual legitimate** (78,670) | 78,293 (TN) | 377 (FP) |
| **Actual phishing** (31,200) | 982 (FN) | 30,218 (TP) |

Accuracy 98.76 %, precision 98.77 %, recall 96.85 %, F1 97.80 %, false-positive rate 0.48 %.
Training loss 0.0578, validation loss 0.0497. The run evaluated once (end of epoch); no
intermediate validation points and no ROC-AUC exist for this split.

```bash
python -m evaluation.kaggle_holdout_metrics
```

### 2. End-to-end pipeline — Malaysian benchmark (120 pages)

`evaluation/datasets/malaysia_eval_v1.jsonl` is a hand-curated benchmark: 60 legitimate and 60
malicious pages in nine categories, split 50/50 into `dev` and `holdout`.

**Read the caveats in `evaluation/build_dataset.py` before quoting these numbers.** The page text was
authored for this project (it is not scraped), malicious URLs are fictitious, mule samples
reference the seeded (simulated) registry, and the benchmark is small. The rule layer was
tuned on the `dev` split only; baseline errors on both splits were inspected when fixing
the whitelist. The results show that the pipeline behaves as designed on representative
Malaysian patterns; they are not an estimate of field accuracy.

| Configuration | Accuracy | Precision | Recall | F1 | False-positive rate | TP / FP / FN / TN |
|---|---|---|---|---|---|---|
| Baseline v3.0.0 (before fixes) | 57.50 % | 54.37 % | 93.33 % | 68.71 % | 78.33 % | 56 / 47 / 4 / 13 |
| **Final v3.2.0** | **97.50 %** | **100.00 %** | **95.00 %** | **97.44 %** | **0.00 %** | 57 / 0 / 3 / 60 |
| Final v3.2.0, `dev` split | 96.67 % | 100.00 % | 93.33 % | 96.55 % | 0.00 % | 28 / 0 / 2 / 30 |
| Final v3.2.0, `holdout` split | 98.33 % | 100.00 % | 96.67 % | 98.31 % | 0.00 % | 29 / 0 / 1 / 30 |
| Ablation: v3.2.0 without the BERT signal | 92.50 % | 100.00 % | 85.00 % | 91.89 % | 0.00 % | 51 / 0 / 9 / 60 |

BERT used alone on the same 120 pages (threshold 0.75), by input formulation:

| BERT input | Accuracy | Recall | False-positive rate | ROC-AUC |
|---|---|---|---|---|
| `URL: <url> \| <page text>` (v3.0.0 behaviour) | 50.00 % | 100.00 % | 100.00 % | 0.704 |
| URL as received (with scheme) | 53.33 % | 93.33 % | 86.67 % | 0.760 |
| URL without scheme / `www.` (v3.2.0, matches training data) | 72.50 % | 88.33 % | 43.33 % | 0.860 |

The three remaining false negatives are a sparse "Loading…" page on a neutral domain, an
investment-scam page with no credential request, and a phishing form hosted on Google Forms
(a whitelisted domain). They are documented as limitations.

In-process latency of the analysis endpoint (single client, CPU): BERT path mean 108 ms,
p95 115 ms; whitelist bypass mean 0.28 ms.

```bash
python -m evaluation.build_dataset
python -m evaluation.evaluate_pipeline --tag final_v3.2.0
python -m evaluation.evaluate_pipeline --tag ablation_no_bert_v3.2.0 --no-bert
```

### 3. Load test — Locust 2.44.4 (`evaluation/results/locust/`)

Server: `uvicorn main:app --host 127.0.0.1 --port 8765`, one worker process, real BERT model
on CPU. Locust ran on the same machine, so client and server competed for the same cores.
Task mix per user (wait 1–3 s): 3× non-whitelisted page with a unique URL (forces a real
BERT forward pass), 2× whitelisted page, 1× phishing page (BERT result cached), 1× mule
page on a trusted host, 2× `/health`, 1× `/dashboard/stats`.

| Run | Rate limit | Users | Requests | Errors | Throughput | p50 | p95 | p99 | Max |
|---|---|---|---|---|---|---|---|---|---|
| `run_50u` (60 s) | lifted (`1000000/minute`) | 50 | 1,333 | 0 (0.00 %) | 22.39 req/s | 13 ms | 370 ms | 490 ms | 600 ms |
| `run_200u` (60 s) | lifted | 200 | 2,418 | 0 (0.00 %) | 40.40 req/s | 96 ms | 11,000 ms | 12,000 ms | 12,266 ms |
| `run_50u_default_limit` (45 s) | default `60/minute` | 50 | 1,014 | 646 (63.71 %), all HTTP 429 | 23.04 req/s | 3 ms | 17 ms | 230 ms | 584 ms |

BERT cache-miss path only: 50 users — median 190 ms, p95 450 ms, p99 560 ms (6.73 req/s);
200 users — median 9,700 ms, p95 12,000 ms (10.69 req/s). A single CPU worker therefore
sustains roughly 10–11 uncached BERT inferences per second; above that, requests queue.
No request failed in either lifted-limit run.

With the default limit, all 50 simulated users share one IP address, so the limiter admitted
60 analysis requests and rejected the other 646 with HTTP 429 — the intended behaviour.

```bash
PHISHGUARD_RATE_LIMIT=1000000/minute python -m uvicorn main:app --host 127.0.0.1 --port 8765
python -m locust -f tests/locustfile.py --host http://127.0.0.1:8765 --headless -u 50 -r 5 -t 60s --csv evaluation/results/locust/run_50u
```

### 4. Automated tests and coverage (`evaluation/results/pytest/`, `evaluation/results/coverage/`)

198 tests in 10 modules, 198 passed (12.76 s with coverage, 10.21 s without).
Statement + branch coverage measured with `pytest-cov`: **77 %** overall
(2,788 statements, 542 missed; 668 branches). The unit tests use a mocked BERT engine and
an in-memory SQLite database; the real model is exercised by the benchmark above.

| Lowest-covered modules | Coverage | Reason |
|---|---|---|
| `services/webhook_notifier.py` | 27 % | outbound HTTP to Discord / Slack / Telegram is not called in tests |
| `services/visual_sandbox.py` | 37 % | requires a headless browser |
| `main.py` | 42 % | lifespan start-up, simulator loop and Swagger HTML are not run under the test client |
| `services/visual_detector.py` | 44 % | YOLO inference is mocked |
| `services/nlp_engine.py` | 56 % | real BERT forward pass is mocked in unit tests |

```bash
python -m pytest --cov --cov-report=term
```

### 5. Visual module — YOLOv8n logo detector (reference)

Training artefacts live in `visual_identity/runs/phishguard_logo_yolov8n/` (git-ignored).
Final epoch (46): precision 0.979, recall 0.996, mAP@0.5 0.991, mAP@0.5:0.95 0.979 on the
validation split (366 images). The dataset (1,286 train / 366 val / 187 test) was generated
synthetically from 39 source screenshots of five banks, so these figures describe
performance on synthetic compositions, not on live phishing pages.

### 6. Report figures

The dissertation (`report/PhishGuard-AI_Project_1_&_2_Report_LiewYiLer.docx`) uses three kinds of figure, all at 300 DPI:

* **Architecture, UML, ERD, sequence, activity, deployment and workflow diagrams** are native draw.io files in
  `report/diagrams_drawio/`. Open one in [diagrams.net](https://app.diagrams.net) (or the draw.io desktop app) to edit it,
  then export it as PNG at 300 DPI with a white background into `report/figures/` under the same name.
* **Quantitative charts** (confusion matrices, ROC, false-positive comparison, Locust latency and throughput, test and
  coverage breakdown, training loss) are generated from the committed results by `evaluation/make_report_figures.py`
  in the same palette as the diagrams (`evaluation/figkit.py`).
* **Screenshots** (`report/figures/ui_*.png`) were captured from the running v3.2.0 system with Playwright driving
  headless Microsoft Edge with the extension loaded.

```bash
python -m evaluation.benchmark_components      # per-component latency and F1 (trade-off chart)
python -m evaluation.make_report_figures       # all charts -> report/figures/*.png
python -m evaluation.make_report_figures roc tests_coverage   # regenerate selected charts only
```

---

## 🔒 Security Model

| Control | Implementation |
|---|---|
| Extension API authentication | `Authorization: Bearer <PHISHGUARD_API_KEY>`, constant-time comparison (`core/security.py`) |
| Dashboard authentication | Every `/api/v1/dashboard/*` route requires the admin key (bearer) or a server-side session cookie (`HttpOnly`, `SameSite=Strict`); login limited to 5 attempts/minute per IP |
| Rate limiting | SlowAPI, per client IP, default `60/minute` on analysis and report endpoints (HTTP 429 beyond that) |
| CORS | Explicit origin list + `chrome-extension://` origins; no wildcard, no credentialed cross-origin requests |
| Input validation | Pydantic v2 schemas (URL format, 5 MB DOM cap, account-number pattern); HTTP 422 on violation |
| SQL injection | Parameterised queries only; `CHECK` constraints and a foreign key in the schema |
| Registry integrity | User reports enter a `PENDING` queue; nothing is auto-inserted into the blocking registry |
| Response headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store` on API responses |
| Extension | Manifest V3 with explicit CSP; backend calls bounded by `AbortController` timeouts with offline fallback |

**Known limitations.** The mule registry is seeded with simulated accounts, not live PDRM Semak Mule data. The "live threat simulator" on the dashboard injects synthetic telemetry for demonstrations and is off by default. The geo/ASN view assigns illustrative infrastructure nodes; it does not resolve real network origins. The BERT model was trained on English-language URL strings only and is used as a supporting signal. The logo detector was trained on a synthetic dataset. The NSRC 997 / National Fraud Portal features format case data for hand-off; they do not call any government system.

---

## 📄 License & Attribution
Final Year Project (BMCS3404 Project I / BMCS3414 Project II), Bachelor of Information Technology (Honours) in Information Security.  
Faculty of Computing and Information Technology, Tunku Abdul Rahman University of Management and Technology (TAR UMT).  
Supervisor: Dr. Ng Yen Phing.
