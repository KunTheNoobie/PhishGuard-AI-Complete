from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path

from common import (
    BRANDS,
    RAW_DIR,
    REPORTS_DIR,
    brand_slug,
    ensure_dataset_dirs,
    infer_brand_from_path,
    iter_images,
    yolo_label_for_image,
)


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path

    counter = 2
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def copy_image_and_label(source_image: Path, brand: str) -> tuple[Path, bool]:
    slug = brand_slug(brand)
    image_dir = RAW_DIR / slug / "images"
    label_dir = RAW_DIR / slug / "labels"
    image_dir.mkdir(parents=True, exist_ok=True)
    label_dir.mkdir(parents=True, exist_ok=True)

    target_image = unique_destination(image_dir / source_image.name)
    shutil.copy2(source_image, target_image)

    label_source = yolo_label_for_image(source_image)
    label_copied = False
    if label_source.exists():
        shutil.copy2(label_source, label_dir / f"{target_image.stem}.txt")
        label_copied = True

    return target_image, label_copied


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import logo images into the Cheon YOLOv8 raw dataset folders."
    )
    parser.add_argument("--source", required=True, type=Path, help="Folder containing raw images.")
    parser.add_argument(
        "--brand",
        choices=BRANDS,
        help="Use this brand for all imported images. If omitted, brand is inferred from folder/file names.",
    )
    args = parser.parse_args()

    ensure_dataset_dirs()
    skipped_rows: list[dict[str, str]] = []
    imported = 0
    labels = 0

    for image_path in iter_images(args.source):
        brand = args.brand or infer_brand_from_path(image_path)
        if not brand:
            skipped_rows.append(
                {
                    "image": str(image_path),
                    "reason": "Cannot infer target brand from path. Re-run with --brand.",
                }
            )
            continue

        _, copied_label = copy_image_and_label(image_path, brand)
        imported += 1
        labels += int(copied_label)

    if skipped_rows:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        skipped_csv = REPORTS_DIR / "import_skipped.csv"
        with skipped_csv.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["image", "reason"])
            writer.writeheader()
            writer.writerows(skipped_rows)
        print(f"Skipped {len(skipped_rows)} image(s). See {skipped_csv}")

    print(f"Imported {imported} image(s). Copied {labels} YOLO label file(s).")


if __name__ == "__main__":
    main()

