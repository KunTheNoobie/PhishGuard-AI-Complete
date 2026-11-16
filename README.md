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

The benchmark is small and its page text was written for this project; see [`evaluation/README.md`](evaluation/README.md) for the method, caveats, ablation and limitations before quoting these figures.

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

Results, method and limitations: [`evaluation/README.md`](evaluation/README.md). Release notes: [`CHANGELOG.md`](CHANGELOG.md).

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
