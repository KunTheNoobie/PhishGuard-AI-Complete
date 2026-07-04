from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from common import MODELS_DIR, latest_best_pt


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Copy a trained YOLOv8 best.pt into visual_identity/models/best.pt."
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="Specific best.pt path. If omitted, the latest runs/**/weights/best.pt is used.",
    )
    args = parser.parse_args()

    source = args.source or latest_best_pt()
    if not source:
        raise SystemExit("No best.pt found under visual_identity/runs. Train YOLOv8 first.")
    if not source.exists():
        raise SystemExit(f"Source model not found: {source}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    target = MODELS_DIR / "best.pt"
    shutil.copy2(source, target)

    print(f"Copied trained model:\n  from: {source}\n  to:   {target}")


if __name__ == "__main__":
    main()
