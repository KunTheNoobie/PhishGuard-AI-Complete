# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="100"/>
  <h3>Enterprise-Grade Multi-Modal Anti-Phishing Browser Security Suite</h3>
  <p>Real-time financial scam and money-mule detection powered by fine-tuned BERT NLP, Computer Vision (YOLOv8), DuitNow threat scanning, and High-Performance DOM Caching.</p>
</div>

---

## 📖 Project Abstract

PhishGuard-AI is an end-to-end cybersecurity solution protecting users from advanced financial phishing and money-mule syndicates. Unlike traditional blacklist-based blockers, PhishGuard utilizes a **multi-modal AI & heuristic pipeline**:

1. **Semantic NLP Engine (Fine-Tuned BERT):** Analyzes raw DOM structure and text semantics to identify social engineering patterns typical in phishing campaigns.
2. **Visual Identity Engine (YOLOv8):** Scans the viewport for unauthorized use of official financial institution logos (e.g., Maybank, CIMB, Public Bank, RHB) hosted on unverified domains.
3. **Mule & DuitNow Account Registry (Regex + SQLite 3NF):** Extracts bank accounts, DuitNow mobile numbers (`+601X...`), and National IDs (NRIC) directly from the DOM and cross-references them in real time against an indexed registry of known scam accounts.
4. **High-Performance In-Memory DOM Cache:** Uses deterministic SHA-256 digests with 10-minute TTL expiration to return instant (<1ms) threat assessments for repeated page scans.
5. **Offline Typo-Squatting Heuristics:** Levenshtein edit-distance analyzer detecting lookalike domains locally with zero reliance on backend connectivity.

---

## 🚀 Key Features

### 🛡️ Chrome Extension (Manifest V3)
- **Full-Screen Interception (`BLOCK_RENDER`):** Replaces dangerous phishing pages with a full-screen red security alert screen detailing the exact threat vectors (BERT score, flagged mule accounts) and providing a **"Back to Safety"** escape route.
- **Explainable AI (XAI) Keyword Highlighting:** Highlights detected social engineering phrases (*"urgent verification"*, *"account suspended"*, *"transfer deposit"*) with in-page warnings and explanatory tooltips.
- **Offline Typo-Squatting Resilience:** Detects domain spoofing targeting Malaysian banks (e.g. `maybannk2u.com.my`, `cimb-clicks-verify.com`) locally via Levenshtein edit distance even if the server is offline.
- **Native OS Push Notifications:** Sends instant desktop notifications via `chrome.notifications` when a dangerous page is intercepted.
- **Scan History (Last 10 Scans):** Built-in history tab in the popup preserving recent scan results with color-coded risk badges and timestamps.
- **24-Hour Custom Domain Whitelisting:** Quickly trust development or private domains with the **"Trust Domain (24h)"** action.

### 📊 Live Threat Intelligence Dashboard
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
- **DuitNow & Multi-Bank Pattern Matching:** Normalizes and detects phone numbers, NRICs, and account formats for all major Malaysian banks.
- **Asynchronous Concurrency:** Parallel execution of BERT inference and SQLite mule registry lookups via `asyncio.gather()`.
- **Database Architecture (3NF):** SQLite WAL mode with explicit B-Tree indexes for $O(\log N)$ query speed.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend Framework** | Python 3.10+, FastAPI, Uvicorn |
| **AI / Machine Learning** | PyTorch, Transformers (BERT), Ultralytics (YOLOv8) |
| **Real-Time Streaming** | Server-Sent Events (SSE) via `asyncio.Queue` |
| **Caching & Storage** | In-Memory SHA-256 TTL Cache, SQLite (aiosqlite) with WAL Mode |
| **Browser Extension** | Manifest V3, Vanilla JavaScript, CSS3, `chrome.notifications` |
| **Dashboard** | HTML5, Vanilla JavaScript, Responsive SVG Charts, Glassmorphism CSS |
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

## 🧪 Testing PhishGuard Safely

### Method 1: Local Scam Test Page (HTTP)
1. Start the server and navigate to:
   👉 **[http://127.0.0.1:8000/dashboard/test_scam.html](http://127.0.0.1:8000/dashboard/test_scam.html)**
2. Click the **PhishGuard-AI** extension icon and click **Scan Page**.
3. PhishGuard will detect the seeded Maybank mule account (`112233445566`), block the page, highlight scam keywords, and display the full-screen protection alert.

### Method 2: Threat Intelligence Simulator
1. Open the Admin Dashboard:
   👉 **[http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)**
2. In the top-right header, toggle **Simulation: ON**.
3. Live synthetic threats will automatically stream into the Live Threat Feed via Server-Sent Events.

---

## 🧪 Running Automated Tests

Run the full Pytest suite (81 unit and integration tests):
```powershell
.\venv\Scripts\python.exe -m pytest
```

---

## 📁 System Architecture

```text
PhishGuard-AI-Complete/
├── api/                   # FastAPI Endpoints (Threat Analysis, Dashboard CRUD & SSE Stream, Visual)
├── chrome_extension/      # MV3 Extension (Service Worker, Content Script, Popup UI)
│   ├── background/        # Service worker (Levenshtein typosquatting, 24h whitelist, notifications)
│   ├── content/           # Content script (Full-Screen BLOCK_RENDER, in-page XAI keyword highlights)
│   └── popup/             # Popup UI (Scanner & Scan History tabs)
├── core/                  # Configuration, DuitNow & Bank Regex, Security Settings
├── dashboard/             # Threat Intelligence Dashboard (HTML, SVG Charts, SSE Stream, Export, Search)
├── database/              # SQLite 3NF Schema, Repository CRUD & SSE Broadcaster, Seed Data
├── schemas/               # Pydantic validation models
├── services/              # BERT NLP Engine, YOLOv8, Mule & DuitNow Scanner, SHA-256 Cache
├── tests/                 # 81 Unit & Integration tests
├── Dockerfile             # Container definition
├── docker-compose.yml     # Container orchestration
├── .env.example           # Configuration template
└── run_server.bat         # 1-Click Launch Script
```

---

## 🔐 Disclaimer
*This system is developed as a University Final Year Project (FYP). The threat data and mule accounts included within the default database are intended for academic research, security demonstration, and testing purposes.*
