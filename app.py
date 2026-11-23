"""
Hugging Face Space entry point (SDK: gradio, app_file: app.py).

The real service is the FastAPI app in main.py (extension API, SOC dashboard, /docs, /health).
This file adds a small Gradio status page at /gradio and serves everything on port 7860, with the
BERT URL model and the YOLOv8n logo detector both enabled.
Run locally:  python app.py   (port 7860)   or   start_local.bat (port 8000)
"""

from __future__ import annotations

import logging
import os

# Must be set before main is imported: core.config reads these once at import time.
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")  # CPU only: never touch a GPU, even on a ZeroGPU container
os.environ.setdefault("PHISHGUARD_ENABLE_VISUAL", "true")
os.environ.setdefault("PHISHGUARD_ENABLE_SEMANTIC", "true")
os.environ.setdefault("PHISHGUARD_DB_PATH", "/tmp/phishguard.db" if os.name != "nt" else "phishguard.db")

# Hugging Face ZeroGPU Spaces refuse to start unless a @spaces.GPU function exists. This do-nothing function only
# satisfies that startup check: all inference stays on the CPU. `spaces` is not in requirements.txt (it is provided
# by Hugging Face), so Render and local installs simply skip this block. It must come before torch is imported.
try:
    import spaces  # type: ignore[import-not-found]

    @spaces.GPU
    def _zero_gpu_startup_check() -> None:
        return None
except ImportError:
    pass

import torch  # noqa: E402

torch.cuda.is_available = lambda: False  # ZeroGPU fakes a GPU; the models must stay on the CPU

from core.config import APP_VERSION  # noqa: E402
from main import app  # noqa: E402

logger = logging.getLogger("phishguard.space")


def _status() -> str:
    state = app.state
    bert = getattr(state, "semantic_engine", None) is not None
    yolo = getattr(state, "visual_detector", None) is not None
    return (
        f"### PhishGuard-AI v{APP_VERSION}\n"
        f"- BERT URL model: **{'loaded' if bert else 'loading / off'}**\n"
        f"- YOLOv8n logo detector: **{'enabled' if yolo else 'off'}**\n\n"
        "[Open the SOC dashboard](/dashboard/) · [API documentation](/docs) · [Health](/health)"
    )


try:  # the Gradio page is optional: the API and dashboard work without it
    import gradio as gr

    with gr.Blocks(title="PhishGuard-AI status") as demo:
        gr.Markdown("# 🛡️ PhishGuard-AI backend")
        card = gr.Markdown(_status())
        gr.Button("Refresh").click(lambda: _status(), outputs=card)
        demo.load(lambda: _status(), outputs=card)
    app = gr.mount_gradio_app(app, demo, path="/gradio")
except Exception as exc:  # noqa: BLE001
    logger.warning("Gradio status page disabled: %s", exc)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=7860, proxy_headers=True, forwarded_allow_ips="*")
