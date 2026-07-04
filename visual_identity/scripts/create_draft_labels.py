from __future__ import annotations

import argparse
import csv

from common import CLASS_TO_ID, DRAFT_LABELS_CSV, YOLO_DIR, brand_slug


def infer_brand_from_split_name(name: str) -> str | None:
    for brand in CLASS_TO_ID:
        prefix = f"{brand_slug(brand)}__"
        if name.startswith(prefix):
            return brand
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Create draft YOLO labels for missing files. This is a helper only; "
            "open preview images and manually correct every generated box."
        )
    )
    parser.add_argument("--box-size", type=float, default=0.8, help="Draft square box size in normalized YOLO units.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing labels.")
    args = parser.parse_args()

    size = max(0.05, min(args.box_size, 1.0))
    created = 0
    skipped = 0
    review_rows: list[dict[str, str]] = []

    for split in ("train", "val", "test"):
        image_dir = YOLO_DIR / "images" / split
        label_dir = YOLO_DIR / "labels" / split
        label_dir.mkdir(parents=True, exist_ok=True)

        for image_path in image_dir.glob("*"):
            if not image_path.is_file():
                continue

            label_path = label_dir / f"{image_path.stem}.txt"
            if label_path.exists() and not args.overwrite:
                skipped += 1
                continue

            brand = infer_brand_from_split_name(image_path.name)
            if not brand:
                skipped += 1
                continue

            class_id = CLASS_TO_ID[brand]
            label_path.write_text(f"{class_id} 0.5 0.5 {size:.4f} {size:.4f}\n", encoding="utf-8")
            review_rows.append(
                {
                    "split": split,
                    "image": str(image_path),
                    "label": str(label_path),
                    "issue": "Draft center bbox generated. Manually adjust and confirm logo bounding box.",
                }
            )
            created += 1

    DRAFT_LABELS_CSV.parent.mkdir(parents=True, exist_ok=True)
    with DRAFT_LABELS_CSV.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["split", "image", "label", "issue"])
        writer.writeheader()
        writer.writerows(review_rows)

    print(f"Draft labels created: {created}. Skipped: {skipped}.")
    print(f"Manual review draft report: {DRAFT_LABELS_CSV}")
    print("Important: draft boxes are not final labels. Review them with preview_labels.py.")


if __name__ == "__main__":
    main()
