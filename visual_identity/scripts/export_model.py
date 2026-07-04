from __future__ import annotations

import argparse
import os
from pathlib import Path

from common import ULTRALYTICS_CONFIG_DIR, ensure_dataset_dirs


def main() -> None:
    parser = argparse.ArgumentParser(description="Export trained YOLOv8 logo detector.")
    parser.add_argument("--weights", required=True, type=Path, help="Path to best.pt.")
    parser.add_argument("--format", default="onnx", choices=["onnx", "torchscript", "openvino", "engine"])
    parser.add_argument("--imgsz", type=int, default=640)
    args = parser.parse_args()

    ensure_dataset_dirs()
    os.environ.setdefault("YOLO_CONFIG_DIR", str(ULTRALYTICS_CONFIG_DIR))

    try:
        from ultralytics import YOLO
    except ImportError as exc:
        raise SystemExit("Install ultralytics first: pip install ultralytics") from exc

    if not args.weights.exists():
        raise SystemExit(f"Weights file not found: {args.weights}")

    model = YOLO(str(args.weights))
    exported_path = model.export(format=args.format, imgsz=args.imgsz)
    print(f"Exported model: {exported_path}")


if __name__ == "__main__":
    main()
