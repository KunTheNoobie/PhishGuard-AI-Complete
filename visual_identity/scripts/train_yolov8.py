from __future__ import annotations

import argparse
import os

from pathlib import Path

from common import (
    DATA_YAML,
    MPL_CONFIG_DIR,
    ROOT_DIR,
    ULTRALYTICS_CONFIG_DIR,
    ensure_dataset_dirs,
    write_data_yaml,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train YOLOv8 logo detector for Cheon's visual module.")
    parser.add_argument("--model", default="yolov8n.pt", help="Base YOLOv8 model.")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--imgsz", type=int, default=640)
    parser.add_argument("--batch", type=int, default=8)
    parser.add_argument("--name", default="phishguard_logo_yolov8n")
    parser.add_argument(
        "--resume",
        type=Path,
        help="Resume training from a YOLO checkpoint, usually visual_identity/runs/.../weights/last.pt.",
    )
    args = parser.parse_args()

    ensure_dataset_dirs()
    # Refresh the absolute dataset path for whichever computer runs training.
    write_data_yaml()
    os.environ.setdefault("YOLO_CONFIG_DIR", str(ULTRALYTICS_CONFIG_DIR))
    os.environ.setdefault("MPLCONFIGDIR", str(MPL_CONFIG_DIR))

    try:
        from ultralytics import YOLO
    except ImportError as exc:
        raise SystemExit("Install ultralytics first: pip install ultralytics") from exc

    if args.resume:
        if not args.resume.exists():
            raise SystemExit(f"Resume checkpoint not found: {args.resume}")
        model = YOLO(str(args.resume))
        model.train(resume=True)
        print("Resume training complete.")
        return

    model = YOLO(args.model)
    model.train(
        data=str(DATA_YAML),
        epochs=args.epochs,
        imgsz=args.imgsz,
        batch=args.batch,
        project=str(ROOT_DIR / "runs"),
        name=args.name,
        patience=15,
    )

    print("Training complete.")
    print(f"Best model is usually under: {ROOT_DIR / 'runs' / args.name / 'weights' / 'best.pt'}")


if __name__ == "__main__":
    main()
