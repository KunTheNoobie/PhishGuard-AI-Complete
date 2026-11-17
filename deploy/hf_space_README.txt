---
title: PhishGuard-AI Backend
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: gradio
sdk_version: 5.29.0
python_version: "3.11"
app_file: app.py
app_port: 7860
pinned: false
short_description: Real-time phishing detection API and SOC dashboard
---

# PhishGuard-AI backend

FastAPI service behind the PhishGuard-AI browser extension (TAR UMT final year project),
served through a minimal Gradio status card at `/hf`.

* SOC dashboard: `/dashboard/` (demonstration admin key `12345678`)
* Interactive API documentation: `/docs`
* Health probe: `/health`

Runs on the free CPU Basic tier (no GPU, no `spaces` package). Source code and documentation:
https://github.com/KunTheNoobie/PhishGuard-AI-Complete
