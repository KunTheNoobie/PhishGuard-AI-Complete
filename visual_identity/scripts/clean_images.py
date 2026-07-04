from __future__ import annotations

import argparse
import csv
from pathlib import Path

from common import RAW_DIR, REPORTS_DIR, ensure_dataset_dirs, iter_images


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate raw logo image files and optionally re-save them as clean RGB images."
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Re-save valid images in RGB mode. This does not delete originals.",
    )
    args = parser.parse_args()

    try:
        from PIL import Image
    except ImportError as exc:
        raise SystemExit("Install Pillow first: pip install Pillow") from exc

    ensure_dataset_dirs()
    rows: list[dict[str, str]] = []
    checked = 0
    fixed = 0

    for image_path in iter_images(RAW_DIR):
        checked += 1
        try:
            with Image.open(image_path) as image:
                image.verify()

            if args.fix:
                with Image.open(image_path) as image:
                    cleaned = image.convert("RGB")
                    cleaned.save(image_path)
                    fixed += 1
        except Exception as exc:  # noqa: BLE001 - report all image read failures.
            rows.append(
                {
                    "image": str(image_path),
                    "issue": f"Cannot open or verify image: {exc}",
                }
            )

    report_path = REPORTS_DIR / "image_cleaning_report.csv"
    with report_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["image", "issue"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Checked raw images: {checked}")
    print(f"Re-saved images: {fixed}")
    print(f"Issues found: {len(rows)}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()

