from __future__ import annotations

import csv
from pathlib import Path

from common import CLASS_TO_ID, DRAFT_LABELS_CSV, REPORTS_DIR, YOLO_DIR, ensure_dataset_dirs


def validate_label_line(line: str) -> str | None:
    parts = line.strip().split()
    if len(parts) != 5:
        return "YOLO label must have 5 values: class x_center y_center width height"

    try:
        class_id = int(parts[0])
        values = [float(value) for value in parts[1:]]
    except ValueError:
        return "Label contains non-numeric values"

    if class_id not in CLASS_TO_ID.values():
        return f"Invalid class id {class_id}"

    if any(value < 0.0 or value > 1.0 for value in values):
        return "Bounding-box values must be normalized between 0 and 1"
    if values[2] <= 0.0 or values[3] <= 0.0:
        return "Bounding-box width and height must be greater than zero"

    return None


def main() -> None:
    ensure_dataset_dirs()
    review_rows: list[dict[str, str]] = []
    image_count = 0
    valid_label_count = 0
    negative_image_count = 0

    for split in ("train", "val", "test"):
        image_dir = YOLO_DIR / "images" / split
        label_dir = YOLO_DIR / "labels" / split

        for image_path in image_dir.glob("*"):
            if not image_path.is_file():
                continue
            image_count += 1
            label_path = label_dir / f"{image_path.stem}.txt"
            if not label_path.exists():
                review_rows.append(
                    {
                        "split": split,
                        "image": str(image_path),
                        "label": str(label_path),
                        "issue": "Missing label file. Draw the logo bbox manually or run create_draft_labels.py for a draft.",
                    }
                )
                continue

            lines = [line for line in label_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if not lines:
                if image_path.stem.lower().startswith("synthetic_negative_"):
                    negative_image_count += 1
                else:
                    review_rows.append(
                        {
                            "split": split,
                            "image": str(image_path),
                            "label": str(label_path),
                            "issue": "Empty label file on an image not marked as a negative sample.",
                        }
                    )
                continue

            for line_number, line in enumerate(lines, start=1):
                issue = validate_label_line(line)
                if issue:
                    review_rows.append(
                        {
                            "split": split,
                            "image": str(image_path),
                            "label": str(label_path),
                            "issue": f"Line {line_number}: {issue}",
                        }
                    )
                else:
                    valid_label_count += 1

    for split in ("train", "val", "test"):
        label_dir = YOLO_DIR / "labels" / split
        image_dir = YOLO_DIR / "images" / split
        for label_path in label_dir.glob("*.txt"):
            image_matches = list(image_dir.glob(f"{label_path.stem}.*"))
            if not image_matches:
                review_rows.append(
                    {
                        "split": split,
                        "image": "",
                        "label": str(label_path),
                        "issue": "Label file has no matching image.",
                    }
                )

    if DRAFT_LABELS_CSV.exists():
        with DRAFT_LABELS_CSV.open("r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("image") and row.get("label"):
                    review_rows.append(
                        {
                            "split": row.get("split", ""),
                            "image": row.get("image", ""),
                            "label": row.get("label", ""),
                            "issue": row.get(
                                "issue",
                                "Draft label needs manual review.",
                            ),
                        }
                    )

    report_path = REPORTS_DIR / "manual_review.csv"
    with report_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["split", "image", "label", "issue"])
        writer.writeheader()
        writer.writerows(review_rows)

    print(f"Checked {image_count} image(s). Valid label rows: {valid_label_count}.")
    print(f"Valid background-only negative image(s): {negative_image_count}.")
    print(f"Manual review items: {len(review_rows)}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
