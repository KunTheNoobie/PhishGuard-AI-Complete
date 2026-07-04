# PhishGuard-AI Complete Package

This package contains the complete FastAPI backend, BERT model, YOLO logo
detector, Chrome Extension, dashboard, tests, and visual-identity training
assets.

## Requirements

- Windows 10 or Windows 11 (64-bit)
- Python 3.11 or 3.12 (64-bit)
- Google Chrome
- Internet access during the first dependency installation
- About 5 GB of free disk space for Python dependencies

## First-Time Setup

1. Extract the ZIP completely. Do not run it from inside the ZIP preview.
2. Double-click `SETUP_WINDOWS.bat`.
3. Wait until `Setup completed successfully` appears.

The setup creates a local `.venv` folder and installs all dependencies. The
BERT and YOLO model files are already included, so they are not downloaded.

## Start the Backend

Double-click `START_BACKEND.bat` and keep the terminal window open.

When startup is complete:

- API health: http://127.0.0.1:8000/health
- API documentation: http://127.0.0.1:8000/docs
- Dashboard: http://127.0.0.1:8000/dashboard

The first startup can take longer because the BERT model is loaded and warmed
up on the CPU.

## Load the Chrome Extension

1. Open `chrome://extensions` in Chrome.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the `chrome_extension` folder from this package.
5. Open a normal HTTP/HTTPS webpage and click the PhishGuard-AI icon.
6. Click `Scan page`.

The default backend address is `http://127.0.0.1:8000`. It can be changed from
the popup's Backend settings when the backend runs on another machine.

## Verify the Package

Double-click `RUN_TESTS.bat` after setup. A successful package should report
all backend tests as passed.

Important model locations:

- BERT: `phishguard_custom_model/model.safetensors`
- YOLO: `visual_identity/models/best.pt`

Cheon Jie Han's module documentation is in
`README_CHEON_VISUAL_MODULE.md`.

