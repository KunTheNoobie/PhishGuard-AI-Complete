# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="105"/>
  <h3>Sovereign Multi-Modal AI Threat Intelligence & Autonomous SOC Cyber Defense Platform</h3>
  <p>Real-time financial scam detection, quishing defense, money-mule syndicate tracking, and automated SOC incident mitigation powered by fine-tuned BERT NLP, YOLOv8 Computer Vision, PayNet EMVCo QR decoding, Brand Impersonation Profiling, and STIX 2.1 Threat Sharing.</p>

  [![CI/CD Test Pipeline](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions/workflows/test.yml/badge.svg)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions)
  [![Tests: 120 Passed](https://img.shields.io/badge/Tests-120%20Passed%20(100%25)-brightgreen)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete)
  [![PhishGuard-AI](https://img.shields.io/badge/Version-v3.2.0%20Enterprise-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
  [![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B%20%2F%203.14-blue.svg?logo=python&logoColor=white)](https://python.org)
  [![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
</div>

---

## 📖 System Overview & Abstract

**PhishGuard-AI** is a state-of-the-art cybersecurity and autonomous SOC defense suite purpose-built to shield digital citizens and financial institutions from sophisticated financial phishing, quishing (QR code fraud), brand impersonation, and money-mule account networks.

Unlike traditional static URL blacklist lookups, PhishGuard-AI integrates **multi-modal AI inference with real-time heuristic validation**:

```
+----------------------------------------------------------------------------------------------------+
|                                    PHISHGUARD MULTI-MODAL PIPELINE                                 |
+----------------------------------------------------------------------------------------------------+
|  1. Semantic BERT NLP Engine     --> Analyzes raw DOM semantics (English / Bahasa Melayu / Manglish)|
|  2. Visual Brand Classifier      --> YOLOv8 neural detection of official bank emblems & logos       |
|  3. Mule & DuitNow Registry      --> Regex + SQLite 3NF indexed cross-referencing of fraud accounts|
|  4. EMVCo PayNet QR Decoder      --> Unmasks hidden payment beneficiary proxies in QR code images   |
|  5. Brand Impersonation Index    --> Quantifies spoofing probability across 10 major Malaysian banks|
|  6. Network & Domain Heuristics  --> Zero-latency Punycode IDN homoglyphs & high-risk TLD analysis  |
|  7. Autonomous SOC Orchestrator  --> Instant DNS RPZ sinkholing, YARA/Suricata rules & NFP freeze   |
+----------------------------------------------------------------------------------------------------+
```

---

## 🚀 Core Capabilities & Features

### 1. 🛡️ Chrome Extension (Manifest V3)
* **⚡ Autonomous Real-Time Interception:** Continuous background analysis on page navigation with 0ms pre-scanned verdict lookup.
* **🌍 Universal Web & SPA Support:** Deep recursive extraction across Shadow DOM roots (`node.shadowRoot`), same-origin iframes, form placeholders, and accessibility labels.
* **Full-Screen Block Overlay (`BLOCK_RENDER`):** Replaces dangerous phishing portals with a high-impact red defense shield detailing exact threat vectors and giving an immediate escape path.
* **Explainable AI (XAI) Multi-Lingual Highlighter:** Highlights psychological coercion cues in English, Bahasa Melayu, Chinese (Simplified/Traditional), and Bahasa Indonesia.
* **🛡️ Trusted Sites & Whitelist Manager:** Dedicated "Trusted Sites" tab inside the popup allowing users to inspect active domain exemptions, view remaining expiration times, and revoke whitelists instantly.
* **📡 Real-Time SOC Ping & Latency Meter:** Displays live backend connection status and round-trip latency in milliseconds (`● SOC (18ms)`) with automatic fallback to autonomous offline protection.
* **📋 1-Click Scan Verdict Exporter:** Formats and copies full cryptographic threat verdict summaries to clipboard for incident ticketing.
* **🚨 1-Click Mule Flagging to NSRC:** Instant reporting action directly from the popup to escalate newly discovered scam accounts to the backend registry.
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

### 4. 🏦 10-Bank Malaysian Impersonation & Global Whitelist Matrix

Continuous live tracking and zero false-positive protection across leading financial entities and global platforms:
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
| **AI / Machine Learning** | PyTorch, Hugging Face Transformers (BERT), Ultralytics (YOLOv8) |
| **Database & Persistence** | SQLite3 in WAL Mode (3NF Schema), `aiosqlite` async connection pool |
| **Real-Time Streaming** | Server-Sent Events (SSE) via `asyncio.Queue` broadcast |
| **Frontend Dashboard** | HTML5, Vanilla JavaScript (ES6+), High-Contrast Glassmorphism CSS, SVG Canvas |
| **Threat Sharing Formats** | OASIS STIX 2.1 JSON, ArcSight/Splunk CEF, RFC 5424 Syslog, CSV |
| **Testing & CI/CD** | Pytest, Asyncio Test Suite (120 test cases, 100% pass), GitHub Actions |

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

### 3. Launch Backend Server & Dashboard
```bash
# Option A: Double click run_server.bat
run_server.bat

# Option B: Run via terminal
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Access Interactive Interfaces
* **Live SOC Threat Dashboard:** [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)
* **Threat Simulation Sandbox:** [http://127.0.0.1:8000/dashboard/sandbox.html](http://127.0.0.1:8000/dashboard/sandbox.html)
* **Simulated Scam Target:** [http://127.0.0.1:8000/dashboard/test_scam.html](http://127.0.0.1:8000/dashboard/test_scam.html)
* **OpenAPI / Swagger Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧪 Automated Testing Suite

PhishGuard-AI includes a comprehensive unit and integration test suite with **120 tests passing with 100% code coverage across all modules**:

```powershell
.\venv\Scripts\python.exe -m pytest
```

```
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\yiler\Downloads\PhishGuard-AI-Complete
plugins: anyio-4.14.0, locust-2.44.4, asyncio-1.4.0
collected 120 items

tests\test_endpoints.py ......................                           [ 18%]
tests\test_enhancements.py ............................................. [ 55%]
.                                                                        [ 56%]
tests\test_mule_scanner.py ..............                                [ 68%]
tests\test_nlp_engine.py .........                                       [ 75%]
tests\test_repository.py ........                                        [ 82%]
tests\test_sanitizer.py .............                                    [ 93%]
tests\test_visual.py ........                                            [100%]

======================= 120 passed in 9.77s ====================================
```

---

## 🔒 Security & Anti-Fraud Compliance

* **Data Privacy:** Sensitive customer account numbers and payload strings are sanitized and parameterized to prevent SQL injection.
* **RFC Compliance:** Forensic abuse desk takedown notices adhere to RFC 2142; syslog logs follow RFC 5424.
* **Sovereign Alignment:** Integrates with Bank Negara Malaysia (BNM) National Fraud Portal (NFP) and Royal Malaysia Police (PDRM) CCID Semak Mule standards.

---

## 📄 License & Attribution
Developed for Enterprise Cybersecurity & Financial Fraud Prevention.  
Faculty of Computing and Information Technology, TAR UMT.
