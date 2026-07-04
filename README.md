# PhishGuard-AI Complete

<div align="center">
  <img src="chrome_extension/icons/icon128.png" alt="PhishGuard Logo" width="100"/>
  <h3>Enterprise-Grade Anti-Phishing Browser Security Suite</h3>
  <p>A multimodal Artificial Intelligence system utilizing NLP (BERT) and Computer Vision (YOLOv8) to detect and block financial phishing campaigns and money mule accounts in real-time.</p>
</div>

---

## 📖 Project Abstract (Final Year Project)

PhishGuard-AI is designed as an end-to-end security solution protecting users from Malaysian financial scams. Unlike traditional blacklist-based blockers, PhishGuard utilizes a **multi-modal AI approach**:
1. **Semantic NLP Engine (FinBERT):** Analyzes the raw DOM structure and text semantics of a webpage to identify social engineering patterns typical in phishing.
2. **Visual Identity Engine (YOLOv8):** Scans the viewport for the unauthorized use of major Malaysian financial logos (e.g., Maybank, CIMB, Public Bank) hosted on suspicious domains.
3. **Mule Account Registry (Regex + DB):** Extracts bank account numbers directly from the webpage and cross-references them against an actively maintained SQLite registry of known scam/money-mule accounts.

## 🚀 Features

- **Chrome Extension UI:** A sleek, glassmorphism-styled extension that integrates directly into the browser. Provides live risk scores and intercepts rendering of dangerous pages (`BLOCK_RENDER`).
- **Live Threat Intelligence Dashboard:** A premium, real-time web dashboard (Vanilla JS/CSS, no frameworks) for system administrators. Monitors incoming threats, visualizes data, and includes a **Live Simulator** for stress-testing and demonstration purposes.
- **RESTful API Backend (FastAPI):** High-performance backend utilizing `asyncio`, connection pooling, and PyTorch inference with in-memory caching.
- **Database Architecture (3NF):** Uses an append-only WAL mode SQLite database adhering to the Third Normal Form (3NF) for storing Threat Telemetry and Mule Account Registries.

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend Framework** | Python 3.10+, FastAPI, Uvicorn |
| **AI / Machine Learning** | PyTorch, Transformers (BERT), Ultralytics (YOLOv8) |
| **Database** | SQLite (aiosqlite) with WAL Mode |
| **Browser Extension** | Manifest V3, Vanilla JavaScript, CSS3 |
| **Dashboard** | HTML5, Vanilla JavaScript, CSS3 (Glassmorphism) |

## ⚙️ Installation & Setup (Windows)

This repository comes pre-packaged with all necessary assets to run locally.

### 1. Backend Server Setup
To bypass PowerShell execution policy issues and immediately start the server on Windows, simply double-click the included batch script:

1. Double-click `run_server.bat` in the root folder.
2. The script will automatically activate the virtual environment and start the FastAPI server via Uvicorn.
3. The server will run at: `http://127.0.0.1:8000`

*(If you prefer manual execution, use: `.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000`)*

### 2. Loading the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer Mode** ON in the top right corner.
3. Click **Load unpacked** in the top left corner.
4. Select the `chrome_extension` folder located in this repository.
5. The PhishGuard extension is now active. Ensure you pin it to your toolbar!

## 📊 Live Threat Dashboard
Once the backend server is running, the Threat Intelligence Dashboard can be accessed via:
👉 **[http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)**

**Dashboard Features:**
- **Real-Time Telemetry:** Instantly see the results of any page you scan via the extension.
- **Mule Registry:** View all known and flagged mule accounts in a scrollable view.
- **Simulation Mode:** Toggle the `Simulation: OFF/ON` switch in the top right to start injecting live, simulated threat traffic into the dashboard for load-testing and presentation demonstrations.

## 📁 System Architecture
```text
PhishGuard-AI-Complete/
├── api/                   # FastAPI Endpoints (Analysis, Dashboard, Visual)
├── chrome_extension/      # MV3 Extension (Background workers, Content scripts, Popup UI)
├── core/                  # Configuration, Security, Settings
├── dashboard/             # Admin Dashboard UI (HTML, CSS, JS)
├── database/              # SQLite Schema, Initialization scripts
├── schemas/               # Pydantic validation models
├── services/              # AI Orchestration (BERT, YOLO, Mule Scanner, Caching)
├── tests/                 # Pytest Integration tests
└── run_server.bat         # 1-Click Launch Script
```

## 🔐 Disclaimer
*This system is developed as a University Final Year Project (FYP). The threat data and mule accounts included within the default database are intended for academic demonstration and simulation purposes.*
