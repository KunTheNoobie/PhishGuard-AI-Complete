"""Replace Git LFS pointer files with the real binaries (Render does not run `git lfs pull`).

A pointer is a tiny text file ("version https://git-lfs.github.com/spec/v1 ..."). For every model file that is
smaller than 10 KB and starts like that, download the real file from GitHub's LFS media endpoint.
    python scripts/fetch_lfs_weights.py
"""
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEDIA = "https://media.githubusercontent.com/media/KunTheNoobie/PhishGuard-AI-Complete/main/"
WEIGHTS = ["phishguard_custom_model/model.safetensors", "phishguard_custom_model/tokenizer.json", "visual_identity/models/best.pt"]

for rel in WEIGHTS:
    path = ROOT / rel
    if path.exists() and path.stat().st_size >= 10_000:
        print("ok     ", rel, path.stat().st_size // 1024, "KB")
        continue
    if path.exists() and not path.read_bytes()[:40].startswith(b"version https://git-lfs"):
        print("small but not a pointer, kept:", rel)
        continue
    print("fetch  ", rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(MEDIA + rel, path)
    if path.stat().st_size < 10_000:
        sys.exit(f"download of {rel} looks wrong ({path.stat().st_size} bytes)")
    print("saved  ", rel, path.stat().st_size // 1048576, "MB")
