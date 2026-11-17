"""
PhishGuard-AI — NLP Semantic Engine Service.
==============================================

Encapsulates the Hugging Face ``transformers`` pipeline wrapping a
custom fine-tuned BERT URL classifier (bert-base-uncased, 439,476 training URLs).
The class follows the **Singleton** pattern: a single instance is
created during the FastAPI ``lifespan`` cold-start and shared across
all concurrent requests via ``app.state``.

Key Design Decisions
--------------------
- **Thread-offloading**: PyTorch inference is CPU-bound (or GPU-bound).
  Running it on the ASGI event loop would starve all concurrent I/O.
  We delegate each ``predict()`` call to a background thread via
  ``asyncio.to_thread()``, keeping the event loop responsive.

- **Model warm-up**: A dummy inference pass is executed at startup to
  JIT-compile any lazy CUDA kernels and pre-allocate memory.

Architecture Layer : Service / ML Inference
Thesis Reference   : §4.2 — BERT Inference Pipeline & Thread Isolation
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
from pathlib import Path
from typing import Any, Final

import torch

from core.config import BERT_MODEL_NAME, MALICIOUS_THRESHOLD

logger: Final[logging.Logger] = logging.getLogger("phishguard.nlp_engine")

# ==============================================================================
# Label Mapping
# ==============================================================================
# The PhishGuard custom BERT URL classifier emits:
#   label 0 → "LEGITIMATE"  (benign URL)
#   label 1 → "PHISHING"    (malicious URL)
_LABEL_MAP: Final[dict[int, str]] = {
    0: "LEGITIMATE",
    1: "PHISHING",
}


_MAX_LEN: Final[int] = 128


def release_memory() -> None:
    """Collect garbage and give freed heap pages back to the OS (Linux)."""
    gc.collect()
    try:
        import ctypes

        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass  # not glibc (Windows, macOS): nothing to trim


class SemanticEngine:
    """Singleton NLP engine backed by a HuggingFace BERT model.

    Lifecycle
    ---------
    1. ``__init__``   — Downloads/loads the model and tokenizer.
    2. ``warm_up``    — Runs a throwaway inference to prime caches.
    3. ``predict``    — Async method invoked per-request.
    4. ``shutdown``   — Explicit cleanup hook (releases VRAM if on GPU).
    """

    def __init__(self, model_name: str = BERT_MODEL_NAME) -> None:
        """Load the BERT model and tokenizer into memory.

        Parameters
        ----------
        model_name : str
            Hugging Face model identifier or local path.
        """
        logger.info("Loading BERT model '%s' …", model_name)
        torch.set_num_threads(1)  # one inference thread: predictable memory use on small hosts

        self._device: Final[torch.device] = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._scripted = None       # TorchScript int8 model (low-memory path)
        self._fast_tokenizer = None  # `tokenizers` tokenizer used with the scripted model
        self._tokenizer = None
        self._model = None

        scripted_file = Path(model_name) / "bert_int8.ts"
        if self._device.type == "cpu" and scripted_file.is_file() and os.getenv("PHISHGUARD_QUANTIZE", "true").lower() not in ("0", "false", "no"):
            # Low-memory path: int8 TorchScript model built by scripts/quantize_bert.py. It needs neither
            # `transformers` nor the 440 MB fp32 weights, which keeps the process under about 450 MB on Linux.
            from tokenizers import Tokenizer

            self._fast_tokenizer = Tokenizer.from_file(str(Path(model_name) / "tokenizer.json"))
            self._fast_tokenizer.enable_truncation(max_length=_MAX_LEN)
            self._fast_tokenizer.enable_padding(length=_MAX_LEN)
            self._scripted = torch.jit.load(str(scripted_file)).eval()
            logger.info("BERT loaded from %s (int8 TorchScript).", scripted_file.name)
        else:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(model_name)
            self._model = (
                AutoModelForSequenceClassification.from_pretrained(model_name, low_cpu_mem_usage=True)
                .to(self._device)
                .eval()  # Inference mode — disables dropout.
            )
            if self._device.type == "cpu" and os.getenv("PHISHGUARD_QUANTIZE", "true").lower() not in ("0", "false", "no"):
                self._model = torch.ao.quantization.quantize_dynamic(self._model, {torch.nn.Linear}, dtype=torch.qint8)
                logger.info("BERT quantised to int8 (dynamic) to cut memory use.")
            logger.info("BERT model loaded on device '%s' (params: %s).", self._device,
                        f"{sum(p.numel() for p in self._model.parameters()):,}")
        release_memory()

    # ------------------------------------------------------------------
    # Warm-up
    # ------------------------------------------------------------------
    def warm_up(self) -> None:
        """Execute a dummy forward pass to pre-allocate tensors."""
        logger.info("Warming up BERT engine …")
        self._run_inference("PhishGuard warm-up probe.")
        logger.info("BERT engine warm-up complete.")

    # ------------------------------------------------------------------
    # Synchronous inference (runs on a worker thread)
    # ------------------------------------------------------------------
    def _run_inference(self, text: str) -> dict[str, Any]:
        """Run a **blocking** forward pass through the BERT model.

        This method MUST NOT be called directly on the event loop.
        It is designed to be invoked via ``asyncio.to_thread()``.

        Parameters
        ----------
        text : str
            Sanitized plaintext to classify.

        Returns
        -------
        dict
            ``{"label": str, "confidence": float, "is_malicious": bool}``
        """
        # ── Tokenize and run the model (no gradients) ──
        with torch.inference_mode():
            if self._scripted is not None:
                enc = self._fast_tokenizer.encode(text)
                logits: torch.Tensor = self._scripted(
                    torch.tensor([enc.ids]), torch.tensor([enc.attention_mask]), torch.tensor([enc.type_ids]))[0]
            else:
                inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=_MAX_LEN,
                                         padding="max_length").to(self._device)
                logits = self._model(**inputs).logits

        # ── Softmax → probabilities ──
        probabilities: torch.Tensor = torch.nn.functional.softmax(
            logits, dim=-1
        )
        predicted_class: int = int(torch.argmax(probabilities, dim=-1).item())
        confidence: float = round(float(probabilities[0][predicted_class].item()), 6)
        phishing_probability: float = round(float(probabilities[0][1].item()), 6)

        return {
            "label": _LABEL_MAP.get(predicted_class, "UNKNOWN"),
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "is_malicious": phishing_probability >= MALICIOUS_THRESHOLD,
        }

    # ------------------------------------------------------------------
    # Async public API
    # ------------------------------------------------------------------
    async def predict(self, text: str) -> dict[str, Any]:
        """Classify the supplied text asynchronously.

        Offloads the CPU-bound PyTorch inference to a worker thread
        via ``asyncio.to_thread()`` so the ASGI event loop remains
        unblocked for concurrent I/O operations.

        Parameters
        ----------
        text : str
            Sanitized plaintext extracted from the DOM.

        Returns
        -------
        dict[str, Any]
            Classification result with ``label``, ``confidence``, and
            ``is_malicious`` keys.
        """
        logger.debug("Scheduling BERT inference on thread pool …")
        result: dict[str, Any] = await asyncio.to_thread(
            self._run_inference, text
        )
        logger.info(
            "BERT inference complete — label=%s, confidence=%.4f, malicious=%s",
            result["label"],
            result["confidence"],
            result["is_malicious"],
        )
        return result

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def shutdown(self) -> None:
        """Release model resources (useful for GPU VRAM reclamation)."""
        logger.info("Shutting down SemanticEngine — releasing resources.")
        self._model = self._tokenizer = self._scripted = self._fast_tokenizer = None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()


def build_model_input(url: str) -> str:
    """Return the BERT input for ``url``: the URL without scheme or ``www.``.

    The classifier was fine-tuned on bare URL strings.  Feeding it page text,
    or a URL that still carries its scheme, is out of distribution and was
    measured to raise the false-positive rate on the Malaysian benchmark from
    43% to 87-100%.
    """
    from services.url_canonicalizer import canonicalize

    return canonicalize(url).model_url
