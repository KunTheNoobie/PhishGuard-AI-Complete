"""
Hugging Face Space entry point (SDK: gradio, app_file: app.py).

ZeroGPU Spaces start the Gradio launcher themselves and proxy it on port 7860, so a second Uvicorn server on that port
collides with it. Instead this file lets Gradio create and launch its own web app, and injects PhishGuard-AI into it:
our routes (/, /health, /docs, /openapi.json, /dashboard/, /api/v1/*), middleware, exception handlers and start-up
lifespan (which loads BERT and the 29-bank YOLOv8n detector) are placed in front of Gradio's own routes, so Gradio's
/config and /gradio_api keep working for the platform's health check.

All inference runs on the CPU. Run locally with:  python app.py   (port 7860)  or  start_local.bat (port 8000).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

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
import main as phishguard  # noqa: E402

logger = logging.getLogger("phishguard.space")
app = phishguard.app  # the PhishGuard FastAPI application (also what `uvicorn main:app` serves)


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


def _inject_phishguard(gradio_app) -> None:
    """Put PhishGuard-AI in front of the web app that Gradio created."""
    gradio_app.router.routes[0:0] = list(app.routes)                  # our routes first, Gradio's catch-alls after
    gradio_app.user_middleware[0:0] = list(app.user_middleware)       # our middleware (CORS, headers, logging)
    gradio_app.exception_handlers.update(app.exception_handlers)      # e.g. rate-limit responses
    gradio_app.state.limiter = phishguard.limiter                     # SlowAPI reads request.app.state.limiter

    gradio_lifespan = gradio_app.router.lifespan_context

    @asynccontextmanager
    async def combined_lifespan(application):
        async with gradio_lifespan(application):
            async with phishguard.lifespan(application):               # loads BERT + YOLO, opens the database
                yield

    gradio_app.router.lifespan_context = combined_lifespan


try:
    import gradio as gr

    with gr.Blocks(title="PhishGuard-AI status") as demo:
        gr.Markdown("# 🛡️ PhishGuard-AI backend")
        card = gr.Markdown(_status())
        gr.Button("Refresh").click(lambda: _status(), outputs=card)
        demo.load(lambda: _status(), outputs=card)

    # Gradio builds its web app inside launch(); wrap App.create_app so that app gets PhishGuard-AI injected.
    _create_app = gr.routes.App.create_app

    def _create_app_with_phishguard(*args, **kwargs):
        gradio_app = _create_app(*args, **kwargs)
        _inject_phishguard(gradio_app)
        return gradio_app

    gr.routes.App.create_app = staticmethod(_create_app_with_phishguard)
except Exception as exc:  # noqa: BLE001
    demo = None
    logger.warning("Gradio is not available (%s): serving PhishGuard-AI on its own.", exc)

if __name__ == "__main__":
    if demo is not None:
        demo.launch(server_name="0.0.0.0", server_port=7860)
    else:  # local run without Gradio
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=7860, proxy_headers=True, forwarded_allow_ips="*")
