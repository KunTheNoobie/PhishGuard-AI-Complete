# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="100"/>
  <h3>Enterprise-Grade Multi-Modal Anti-Phishing Browser Security Suite</h3>
  <p>Real-time financial scam, quishing, and money-mule detection powered by fine-tuned BERT NLP, Computer Vision (YOLOv8), DuitNow EMVCo QR scanning, Brand Impersonation Profiling, and STIX 2.1 CTI Sharing.</p>

  [![CI/CD Test Pipeline](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions/workflows/test.yml/badge.svg)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions)
  [![Tests: 117 Passed](https://img.shields.io/badge/Tests-117%20Passed-brightgreen)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete)
  [![PhishGuard-AI](https://img.shields.io/badge/Version-v3.0.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
  [![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
  [![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
</div>

---

## 📖 Project Abstract

PhishGuard-AI is an end-to-end cybersecurity solution protecting users from advanced financial phishing, quishing (QR phishing), and money-mule syndicates. Unlike traditional blacklist-based blockers, PhishGuard utilizes a **multi-modal AI & heuristic pipeline**:

1. **Semantic NLP Engine (Fine-Tuned BERT):** Analyzes raw DOM structure and text semantics across English and Bahasa Melayu / Manglish to identify social engineering tactics.
2. **Visual Identity Engine (YOLOv8):** Scans the viewport for unauthorized use of official financial institution logos (e.g., Maybank, CIMB, Public Bank, RHB) hosted on unverified domains.
3. **Mule & DuitNow Account Registry (Regex + SQLite 3NF):** Extracts bank accounts, DuitNow mobile numbers (`+601X...`), and National IDs (NRIC) directly from the DOM and cross-references them in real time against an indexed registry of known scam accounts.
4. **DuitNow QR & EMVCo Quishing Scanner:** Decodes PayNet EMVCo QR code payloads embedded in images, URLs, and text to extract hidden beneficiary proxies and intercept QR code phishing attacks.
5. **Brand Impersonation Index (BII) & Target Profiler:** Computes deterministic spoofing likelihood by cross-referencing brand cues against authoritative Malaysian banking registries.
6. **STIX 2.1 CTI Threat Sharing:** Generates OASIS STIX 2.1 Threat Intelligence Bundles for direct ingestion by enterprise SIEM/SOAR/CERT solutions.
7. **Proactive Credential Interceptor:** Actively warns users before entering banking passwords, OTPs, or TAC codes on unverified domains.

---

## 🚀 Key Features

### 🛡️ Chrome Extension (Manifest V3)
- **Dynamic Toolbar Status Badge:** Real-time visual threat indicator on the extension icon badge (`OK` in Green `#10b981`, `?` in Amber `#f59e0b`, `!` in Glowing Red `#ef4444`) updating dynamically as you switch browser tabs.
- **Circular Threat Risk Gauge:** Interactive animated SVG score meter (0–100%) displaying real-time AI threat severity.
- **Full-Screen Interception (`BLOCK_RENDER`):** Replaces dangerous phishing pages with a full-screen red security alert screen detailing the exact threat vectors (BERT score, flagged mule accounts) and providing a **"Back to Safety"** escape route.
- **Explainable AI (XAI) Bilingual Keyword Highlighting:** Highlights detected social engineering phrases in English (*"urgent verification"*, *"account suspended"*) and Bahasa Melayu (*"akaun digantung"*, *"tindakan segera"*, *"saman tertunggak PDRM"*) with in-page warnings and explanatory tooltips.
- **Proactive Password & TAC / OTP Interceptor:** Displays an inline glowing cyber warning badge whenever a password, PIN, or TAC/OTP field is focused on an unverified domain.
- **Offline Typo-Squatting Resilience:** Detects domain spoofing targeting Malaysian banks locally via Levenshtein edit distance with zero server dependency.

### 📊 Live Threat Intelligence Dashboard
- **Admin Threat Inspector (Deep Page Scanner):** Directly inspect any suspicious URL or scam text from the dashboard with automated HTML fetching, BERT inference, and mule detection.
- **📄 Forensic Incident Report Generator (PDF / Printable Dossier):** Single-click incident dossier generator producing formatted, printable reports containing SHA-256 fingerprints, AI confidence breakdown, target entities, and referenced mule accounts for law enforcement (PDRM CCID) and CERT submissions.
- **🌐 STIX 2.1 Threat Intelligence Exporter:** 1-click export of threat telemetry and mule accounts in the standardized OASIS STIX 2.1 JSON bundle format.
- **🎮 Interactive Threat Simulation Sandbox (`/dashboard/sandbox.html`):** Dedicated live testing playground pre-loaded with realistic Malaysian phishing, quishing, and summon scams for live demos and examinations.
- **Synthesized Audio Threat Alerts:** Instant Web Audio API audio chimes when high-risk threats are received in the live telemetry stream.
- **Visual Analytics Charts:**
  - **Targeted Institutions (SVG Donut Chart):** Real-time breakdown of targeted financial institutions.
  - **24h Threat Velocity (Bar Timeline):** Hourly attack trends and peak detection frequencies.
  - **Scam Platform Vectors:** Distribution of fraud sources (WhatsApp, Telegram, Facebook Marketplace, Shopee).
- **Server-Sent Events (SSE) Live Stream:** Zero-latency real-time push stream (`/api/v1/dashboard/stream`) broadcasting threats across all clients instantly.

### ⚡ AI Engine & Backend (FastAPI)
- **Sub-Millisecond Inference Caching:** In-memory TTL LRU cache keyed by SHA-256 DOM hash.
- **DuitNow QR & EMVCo Decoder:** Parses `000201...` QR payment payloads to unmask mule accounts.
- **Domain & Network Security Heuristics:** Zero-latency detection of raw IP address URLs, Punycode IDN homoglyphs, and high-risk disposable TLDs (`.top`, `.xyz`, `.tk`).
- **Brand Impersonation Index (BII):** Categorizes targeted institutions and detects lookalikes.
- **Database Architecture (3NF):** SQLite WAL mode with explicit B-Tree indexes for $O(\log N)$ query speed.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend Framework** | Python 3.11+, FastAPI, Uvicorn |
| **AI / Machine Learning** | PyTorch, Transformers (BERT), Ultralytics (YOLOv8) |
| **Real-Time Streaming** | Server-Sent Events (SSE) via `asyncio.Queue` |
| **Threat Sharing Format** | OASIS STIX 2.1 JSON Bundles |
| **Caching & Storage** | In-Memory SHA-256 TTL Cache, SQLite (aiosqlite) with WAL Mode |
| **Browser Extension** | Manifest V3, Dynamic Action Badges, Vanilla JavaScript, Cyber Dark Glassmorphism CSS |
| **Dashboard & Sandbox** | HTML5, Vanilla JavaScript, Responsive SVG Charts, Web Audio API, Glassmorphism CSS |
| **CI / CD Pipeline** | GitHub Actions (`.github/workflows/test.yml`) |
| **Containerization** | Docker, Docker Compose |

---

## ⚙️ Quickstart & Installation

### Option 1: 1-Click Launch (Windows)
Double-click `run_server.bat` in the root folder to start the FastAPI server on `http://127.0.0.1:8000`.

### Option 2: Run via Terminal / VS Code
```powershell
# Activate environment & start server
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🧪 Testing & Verification

Run the automated test suite covering NLP, Visual Identity, Mule Scanning, EMVCo QR Quishing, Brand Profiling, STIX 2.1 export, and Dashboard endpoints:

```powershell
# Run Pytest suite
.\venv\Scripts\python.exe -m pytest
```

Expected Output:
```text
======================== 90 passed in 8.49s ========================
```

---

## 📄 License & Academic Reference

Developed as part of the Final Year Project (FYP) at the **Faculty of Computing and Information Technology (FOCS), Tunku Abdul Rahman University of Management and Technology (TAR UMT)**.

Licensed under the [MIT License](LICENSE).
