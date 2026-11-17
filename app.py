"""
Hugging Face Space entry point (SDK: gradio, app_file: app.py).

The real service is the FastAPI app in main.py (extension API, SOC dashboard, /docs, /health).
This file adds a small Gradio status card at /hf and serves everything on port 7860.
Run locally:  python app.py   (port 7860)  or  uvicorn main:app --port 8000
"""

from __future__ import annotations

import logging
import os

from main import app
from core.config import APP_VERSION

logger = logging.getLogger("phishguard.space")


def _status() -> str:
    state = app.state
    bert = getattr(state, "semantic_engine", None) is not None
    yolo = getattr(state, "visual_detector", None) is not None
    return (
        f"### PhishGuard-AI v{APP_VERSION}\n"
        f"- BERT URL model: **{'loaded' if bert else 'loading / off'}**\n"
        f"- YOLOv8n logo detector: **{'loaded' if yolo else 'loading / off'}**\n\n"
        "[Open the SOC dashboard](/dashboard/) · [API documentation](/docs) · [Health](/health)"
    )


try:  # the Gradio card is optional: the API and dashboard work without it
    import gradio as gr

    with gr.Blocks(title="PhishGuard-AI status") as demo:
        gr.Markdown("# 🛡️ PhishGuard-AI backend")
        card = gr.Markdown(_status())
        gr.Button("Refresh").click(lambda: _status(), outputs=card)
        demo.load(lambda: _status(), outputs=card)
    app = gr.mount_gradio_app(app, demo, path="/hf")
except Exception as exc:  # noqa: BLE001
    logger.warning("Gradio status card disabled: %s", exc)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=7860, proxy_headers=True, forwarded_allow_ips="*")
