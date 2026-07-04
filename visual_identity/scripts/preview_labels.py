from __future__ import annotations

import argparse
import csv
from pathlib import Path

from common import ID_TO_CLASS, PREVIEWS_DIR, REPORTS_DIR, YOLO_DIR, ensure_dataset_dirs

COLORS = {
    0: "yellow",
    1: "red",
    2: "deepskyblue",
    3: "lime",
    4: "orange",
}


def draw_preview(image_path: Path, label_path: Path, output_path: Path) -> str | None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise SystemExit("Install Pillow first: pip install Pillow") from exc

    image = Image.open(image_path).convert("RGB")
    draw = ImageDraw.Draw(image)
    width, height = image.size

    for line in label_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 5:
            return "Invalid label line"

        class_id = int(parts[0])
        x_center, y_center, box_width, box_height = [float(value) for value in parts[1:]]
        x1 = int((x_center - box_width / 2) * width)
        y1 = int((y_center - box_height / 2) * height)
        x2 = int((x_center + box_width / 2) * width)
        y2 = int((y_center + box_height / 2) * height)
        color = COLORS.get(class_id, "white")
        label = ID_TO_CLASS.get(class_id, f"class {class_id}")

        draw.rectangle((x1, y1, x2, y2), outline=color, width=3)
        draw.rectangle((x1, max(0, y1 - 18), x1 + 170, y1), fill=color)
        draw.text((x1 + 4, max(0, y1 - 16)), label, fill="black")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Create preview images with YOLO bounding boxes.")
    parser.add_argument("--split", choices=["train", "val", "test", "all"], default="all")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    ensure_dataset_dirs()
    splits = ("train", "val", "test") if args.split == "all" else (args.split,)
    issues: list[dict[str, str]] = []
    created = 0

    for split in splits:
        image_dir = YOLO_DIR / "images" / split
        label_dir = YOLO_DIR / "labels" / split
        output_dir = PREVIEWS_DIR / split

        for image_path in image_dir.glob("*"):
            if created >= args.limit:
                break
            if not image_path.is_file():
                continue

            label_path = label_dir / f"{image_path.stem}.txt"
            if not label_path.exists():
                issues.append(
                    {
                        "split": split,
                        "image": str(image_path),
                        "issue": "Missing label; preview skipped.",
                    }
                )
                continue

            output_path = output_dir / f"{image_path.stem}.jpg"
            issue = draw_preview(image_path, label_path, output_path)
            if issue:
                issues.append({"split": split, "image": str(image_path), "issue": issue})
            else:
                created += 1

    if issues:
        report_path = REPORTS_DIR / "preview_issues.csv"
        with report_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["split", "image", "issue"])
            writer.writeheader()
            writer.writerows(issues)
        print(f"Preview issues: {len(issues)}. See {report_path}")

    print(f"Preview images created: {created}. Output folder: {PREVIEWS_DIR}")


if __name__ == "__main__":
    main()

