"""Build phishguard_custom_model/bert_int8.ts: TorchScript BERT with int8 weights (about 105 MB).

Run once at image build time (see Dockerfile). The server then loads this file with torch.jit.load and the
`tokenizers` package, so it never imports `transformers` or holds the 440 MB fp32 weights in memory.
    python scripts/quantize_bert.py [model_dir]
"""
import gc
import sys
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MAX_LEN = 128
src = Path(sys.argv[1] if len(sys.argv) > 1 else "phishguard_custom_model")
model = AutoModelForSequenceClassification.from_pretrained(src, low_cpu_mem_usage=True, torchscript=True).eval()
fq = torch.ao.quantization.float_qparams_weight_only_qconfig
for name in ("word_embeddings", "position_embeddings", "token_type_embeddings"):
    getattr(model.bert.embeddings, name).qconfig = fq
model = torch.ao.quantization.quantize_dynamic(
    model, {torch.nn.Linear: torch.ao.quantization.default_dynamic_qconfig, torch.nn.Embedding: fq}, dtype=torch.qint8)
tok = AutoTokenizer.from_pretrained(src)
sample = tok("https://example.com/login", return_tensors="pt", truncation=True, max_length=MAX_LEN, padding="max_length")
with torch.inference_mode():
    traced = torch.jit.trace(model, (sample["input_ids"], sample["attention_mask"], sample["token_type_ids"]), strict=False)
    reference = model(sample["input_ids"], sample["attention_mask"], sample["token_type_ids"])[0]
    assert torch.allclose(traced(sample["input_ids"], sample["attention_mask"], sample["token_type_ids"])[0], reference, atol=1e-4)
gc.collect()
out = src / "bert_int8.ts"
traced.save(str(out))
print("saved", out, round(out.stat().st_size / 1048576), "MB")
