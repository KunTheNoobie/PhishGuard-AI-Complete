# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="100"/>
  <h3>Enterprise-Grade Multi-Modal Anti-Phishing Browser Security Suite</h3>
  <p>Real-time financial scam, quishing, and money-mule detection powered by fine-tuned BERT NLP, Computer Vision (YOLOv8), DuitNow EMVCo QR scanning, and High-Performance DOM Caching.</p>

  [![CI/CD Test Pipeline](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions/workflows/test.yml/badge.svg)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete/actions)
  [![Tests: 87 Passed](https://img.shields.io/badge/Tests-87%20Passed-brightgreen)](https://github.com/KunTheNoobie/PhishGuard-AI-Complete)
  [![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
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
5. **High-Performance In-Memory DOM Cache:** Uses deterministic SHA-256 digests with 10-minute TTL expiration to return instant (<1ms) threat assessments for repeated page scans.
6. **Proactive Credential Interceptor:** Actively warns users before entering banking passwords, OTPs, or TAC codes on unverified domains.
7. **Offline Typo-Squatting Heuristics:** Levenshtein edit-distance analyzer detecting lookalike domains locally with zero reliance on backend connectivity.

---

## 🚀 Key Features

### 🛡️ Chrome Extension (Manifest V3)
- **Circular Threat Risk Gauge:** Interactive animated SVG score meter (0–100%) displaying real-time AI threat severity.
- **Full-Screen Interception (`BLOCK_RENDER`):** Replaces dangerous phishing pages with a full-screen red security alert screen detailing the exact threat vectors (BERT score, flagged mule accounts) and providing a **"Back to Safety"** escape route.
- **Explainable AI (XAI) Bilingual Keyword Highlighting:** Highlights detected social engineering phrases in English (*"urgent verification"*, *"account suspended"*) and Bahasa Melayu (*"akaun digantung"*, *"tindakan segera"*, *"saman tertunggak PDRM"*) with in-page warnings and explanatory tooltips.
- **Proactive Password & TAC / OTP Interceptor:** Displays an inline glowing cyber warning badge whenever a password, PIN, or TAC/OTP field is focused on an unverified domain.
- **Offline Typo-Squatting Resilience:** Detects domain spoofing targeting Malaysian banks (e.g. `maybannk2u.com.my`, `cimb-clicks-verify.com`) locally via Levenshtein edit distance even if the server is offline.
- **Native OS Push Notifications:** Sends instant desktop notifications via `chrome.notifications` when a dangerous page is intercepted.
- **Scan History (Last 10 Scans):** Built-in history tab in the popup preserving recent scan results with color-coded risk badges and timestamps.
- **24-Hour Custom Domain Whitelisting:** Quickly trust development or private domains with the **"Trust Domain (24h)"** action or **"Report Safe"** button.

### 📊 Live Threat Intelligence Dashboard
- **Admin Threat Inspector (Deep Page Scanner):** Directly inspect any suspicious URL or scam text from the dashboard with automated HTML fetching, BERT inference, and mule detection.
- **📄 Forensic Incident Report Generator (PDF / Printable Dossier):** Single-click incident dossier generator producing a formatted, printable report containing SHA-256 fingerprints, AI confidence breakdown, target entities, and referenced mule accounts for law enforcement (PDRM CCID) and CERT submissions.
- **Synthesized Audio Threat Alerts:** Instant Web Audio API audio chimes when high-risk threats are received in the live telemetry stream.
- **Visual Analytics Charts:**
  - **Targeted Institutions (SVG Donut Chart):** Real-time breakdown of targeted financial institutions.
  - **24h Threat Velocity (Bar Timeline):** Hourly attack trends and peak detection frequencies.
  - **Scam Platform Vectors:** Distribution of fraud sources (WhatsApp, Telegram, Facebook Marketplace, Shopee).
- **Server-Sent Events (SSE) Live Stream:** Zero-latency real-time push stream (`/api/v1/dashboard/stream`) broadcasting threats across all clients instantly.
- **Instant Search & Filter:** Instant client-side search across URLs, Bank names, and Flagged Platforms, with BERT confidence thresholds (High, Medium, Low).
- **CSV & JSON Threat Intelligence Export:** 1-click download of threat intelligence logs and mule registry data for external SIEM or forensic reporting.
- **Interactive Mule Account Management (CRUD):** Add newly reported suspect bank accounts and delete cleared records directly from the web interface.
- **Live Threat Simulator:** Toggleable synthetic traffic injector to simulate live threats for stress testing and presentations.

### ⚡ AI Engine & Backend (FastAPI)
- **Sub-Millisecond Inference Caching:** In-memory TTL LRU cache keyed by SHA-256 DOM hash.
- **DuitNow QR & EMVCo Decoder:** Parses `000201...` QR payment payloads to unmask mule accounts.
- **Domain & Network Security Heuristics:** Zero-latency detection of raw IP address URLs, Punycode IDN homoglyphs, and high-risk disposable TLDs (`.top`, `.xyz`, `.tk`).
- **Asynchronous Concurrency:** Parallel execution of BERT inference and SQLite mule registry lookups via `asyncio.gather()`.
- **Database Architecture (3NF):** SQLite WAL mode with explicit B-Tree indexes for $O(\log N)$ query speed.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend Framework** | Python 3.11+, FastAPI, Uvicorn |
| **AI / Machine Learning** | PyTorch, Transformers (BERT), Ultralytics (YOLOv8) |
| **Real-Time Streaming** | Server-Sent Events (SSE) via `asyncio.Queue` |
| **Caching & Storage** | In-Memory SHA-256 TTL Cache, SQLite (aiosqlite) with WAL Mode |
| **Browser Extension** | Manifest V3, Vanilla JavaScript, Cyber Dark Glassmorphism CSS, `chrome.notifications` |
| **Dashboard** | HTML5, Vanilla JavaScript, Responsive SVG Charts, Web Audio API, Glassmorphism CSS |
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

### Option 3: Docker & Docker Compose
```bash
# Start containerized backend
docker-compose up -d

# View logs
docker-compose logs -f
```

---

## 🔌 Loading the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** ON in the top-right corner.
3. Click **Load unpacked** (top-left).
4. Select the `chrome_extension` folder in this repository.
5. Pin **PhishGuard-AI** to your Chrome extension bar.

---

## 🧪 Testing & Verification

Run the automated test suite covering NLP, Visual Identity, Mule Scanning, EMVCo QR Quishing, and Dashboard endpoints:

```powershell
# Run Pytest suite
.\venv\Scripts\python.exe -m pytest
```

Expected Output:
```text
======================== 87 passed in 8.15s ========================
```

---

## 📄 License & Academic Reference

Developed as part of the Final Year Project (FYP) at the **Faculty of Computing and Information Technology (FOCS), Tunku Abdul Rahman University of Management and Technology (TAR UMT)**.

Licensed under the [MIT License](LICENSE).
