from __future__ import annotations

import argparse
import random
import shutil
from pathlib import Path

from common import BRANDS, RAW_DIR, YOLO_DIR, brand_slug, ensure_dataset_dirs, yolo_label_for_image


def copy_sample(image_path: Path, brand: str, split: str) -> None:
    slug = brand_slug(brand)
    target_name = f"{slug}__{image_path.name}"
    target_image = YOLO_DIR / "images" / split / target_name
    target_label = YOLO_DIR / "labels" / split / f"{Path(target_name).stem}.txt"

    shutil.copy2(image_path, target_image)

    raw_label = yolo_label_for_image(
        image_path,
        labels_root=RAW_DIR / slug / "labels",
    )
    if raw_label.exists():
        shutil.copy2(raw_label, target_label)


def main() -> None:
    parser = argparse.ArgumentParser(description="Split raw logo images into YOLO train/val/test folders.")
    parser.add_argument("--train", type=float, default=0.7, help="Training ratio.")
    parser.add_argument("--val", type=float, default=0.2, help="Validation ratio.")
    parser.add_argument("--test", type=float, default=0.1, help="Test ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    args = parser.parse_args()

    if round(args.train + args.val + args.test, 5) != 1.0:
        raise SystemExit("Split ratios must add up to 1.0")

    ensure_dataset_dirs()
    random.seed(args.seed)

    counts = {"train": 0, "val": 0, "test": 0}
    for brand in BRANDS:
        slug = brand_slug(brand)
        images = sorted((RAW_DIR / slug / "images").glob("*"))
        images = [image for image in images if image.is_file()]
        random.shuffle(images)

        total = len(images)
        train_end = int(total * args.train)
        val_end = train_end + int(total * args.val)
        split_map = {
            "train": images[:train_end],
            "val": images[train_end:val_end],
            "test": images[val_end:],
        }

        for split, split_images in split_map.items():
            for image_path in split_images:
                copy_sample(image_path, brand, split)
                counts[split] += 1

    print("Dataset split complete.")
    for split, count in counts.items():
        print(f"  {split}: {count} image(s)")
    print("Run check_dataset.py next to find missing or invalid labels.")


if __name__ == "__main__":
    main()

