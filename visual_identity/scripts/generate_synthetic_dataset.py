from __future__ import annotations

import argparse
import csv
import json
import random
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

from common import (
    BRANDS,
    CLASS_TO_ID,
    ID_TO_CLASS,
    IMAGE_EXTENSIONS,
    PREVIEWS_DIR,
    RAW_DIR,
    REPORTS_DIR,
    YOLO_DIR,
    brand_slug,
    ensure_dataset_dirs,
    iter_images,
    write_data_yaml,
)

CLASS_DISPLAY_NAMES: dict[str, str] = {
    "Maybank": "Maybank",
    "CIMB": "CIMB",
    "Public Bank": "PublicBank",
    "RHB": "RHB",
    "Hong Leong Bank": "HongLeongBank",
}

SPLITS = ("train", "val", "test")
BACKGROUND_TYPES = (
    "white",
    "light_grey",
    "dark",
    "fake_login",
    "banking_header",
)


@dataclass(frozen=True)
class GeneratedSample:
    brand: str | None
    split: str
    image_path: Path
    label_path: Path
    bbox_xyxy: tuple[int, int, int, int] | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate synthetic YOLOv8 training screenshots by placing official "
            "bank logo images on webpage-like backgrounds."
        )
    )
    parser.add_argument("--per-class", type=int, default=300)
    parser.add_argument("--img-width", type=int, default=1280)
    parser.add_argument("--img-height", type=int, default=720)
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument("--val-ratio", type=float, default=0.2)
    parser.add_argument("--test-ratio", type=float, default=0.1)
    parser.add_argument(
        "--negative-count",
        type=int,
        default=0,
        help="Generate background-only images with empty YOLO labels. These are not a new class.",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--preview-limit", type=int, default=150)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.per_class < 0 or args.negative_count < 0:
        raise SystemExit("--per-class and --negative-count cannot be negative.")
    if args.per_class == 0 and args.negative_count == 0:
        raise SystemExit("Request at least one positive or negative image.")
    if args.img_width < 480 or args.img_height < 320:
        raise SystemExit("--img-width and --img-height are too small for webpage-style images.")

    ratio_sum = args.train_ratio + args.val_ratio + args.test_ratio
    if abs(ratio_sum - 1.0) > 0.00001:
        raise SystemExit("train/val/test ratios must add up to 1.0.")


def yolo_targets_have_files() -> bool:
    for split in SPLITS:
        for folder_type in ("images", "labels"):
            folder = YOLO_DIR / folder_type / split
            if any(path.is_file() for path in folder.iterdir()):
                return True
    return False


def next_synthetic_sequence(brand: str) -> int:
    slug = brand_slug(brand)
    pattern = re.compile(rf"^synthetic_{re.escape(slug)}_(\d+)\.")
    highest = -1
    for split in SPLITS:
        image_dir = YOLO_DIR / "images" / split
        for image_path in image_dir.iterdir():
            match = pattern.match(image_path.name)
            if match:
                highest = max(highest, int(match.group(1)))
    return highest + 1


def clear_yolo_targets() -> None:
    for split in SPLITS:
        for folder_type in ("images", "labels"):
            folder = YOLO_DIR / folder_type / split
            for path in folder.iterdir():
                if path.is_file():
                    path.unlink()

    synthetic_preview_dir = PREVIEWS_DIR / "synthetic"
    if synthetic_preview_dir.exists():
        shutil.rmtree(synthetic_preview_dir)


def load_logo_sources() -> dict[str, list[Path]]:
    sources: dict[str, list[Path]] = {}
    for brand in BRANDS:
        image_dir = RAW_DIR / brand_slug(brand) / "images"
        sources[brand] = sorted(
            path
            for path in iter_images(image_dir)
            if path.suffix.lower() in IMAGE_EXTENSIONS
        )
    return sources


def split_logo_sources(
    sources: list[Path],
    args: argparse.Namespace,
    rng: random.Random,
) -> dict[str, list[Path]]:
    """Keep variants from one raw logo source inside a single dataset split."""
    shuffled = sources[:]
    rng.shuffle(shuffled)
    if len(shuffled) < 3:
        return {split: shuffled for split in SPLITS}

    train_count = max(1, int(len(shuffled) * args.train_ratio))
    val_count = max(1, int(len(shuffled) * args.val_ratio))
    if train_count + val_count >= len(shuffled):
        train_count = max(1, len(shuffled) - val_count - 1)

    return {
        "train": shuffled[:train_count],
        "val": shuffled[train_count : train_count + val_count],
        "test": shuffled[train_count + val_count :],
    }


def load_logo(path: Path) -> Image.Image:
    image = Image.open(path).convert("RGBA")
    alpha_bbox = image.getbbox()
    if alpha_bbox:
        image = image.crop(alpha_bbox)
    return image


def random_logo_variant(
    logo: Image.Image,
    img_width: int,
    img_height: int,
    rng: random.Random,
) -> tuple[Image.Image, tuple[int, int, int, int]]:
    logo = logo.copy()

    brightness = rng.uniform(0.82, 1.18)
    contrast = rng.uniform(0.85, 1.18)
    rgb = logo.convert("RGB")
    rgb = ImageEnhance.Brightness(rgb).enhance(brightness)
    rgb = ImageEnhance.Contrast(rgb).enhance(contrast)
    logo = Image.merge("RGBA", (*rgb.split(), logo.getchannel("A")))

    target_width = rng.randint(max(120, img_width // 9), max(180, img_width // 4))
    scale = target_width / max(1, logo.width)
    target_height = max(32, int(logo.height * scale))
    if target_height > img_height // 3:
        target_height = img_height // 3
        target_width = max(80, int(logo.width * (target_height / max(1, logo.height))))

    logo = logo.resize((target_width, target_height), Image.Resampling.LANCZOS)

    if rng.random() < 0.28:
        logo = logo.filter(ImageFilter.GaussianBlur(radius=rng.uniform(0.25, 0.8)))

    pad_x = rng.randint(0, max(4, target_width // 8))
    pad_y = rng.randint(0, max(4, target_height // 5))
    padded = Image.new("RGBA", (target_width + pad_x * 2, target_height + pad_y * 2), (255, 255, 255, 0))
    padded.alpha_composite(logo, (pad_x, pad_y))
    visible_bbox_in_padded = (pad_x, pad_y, pad_x + target_width, pad_y + target_height)

    return padded, visible_bbox_in_padded


def draw_input(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int, label: str) -> None:
    draw.text((x, y - 20), label, fill=(71, 85, 105))
    draw.rounded_rectangle((x, y, x + w, y + h), radius=6, outline=(203, 213, 225), fill=(255, 255, 255))


def create_background(
    img_width: int,
    img_height: int,
    rng: random.Random,
) -> tuple[Image.Image, str, list[tuple[int, int, int, int]]]:
    bg_type = rng.choice(BACKGROUND_TYPES)
    candidates: list[tuple[int, int, int, int]] = []

    if bg_type == "white":
        image = Image.new("RGB", (img_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, img_width, 74), fill=(248, 250, 252))
        draw.line((0, 74, img_width, 74), fill=(226, 232, 240), width=2)
        draw.text((48, 25), "Secure Online Banking", fill=(30, 41, 59))
        candidates = [(42, 12, img_width // 3, 64), (img_width // 2, 130, img_width - 80, 240)]

    elif bg_type == "light_grey":
        image = Image.new("RGB", (img_width, img_height), (241, 245, 249))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((80, 110, img_width - 80, img_height - 80), radius=12, fill=(255, 255, 255))
        draw.rectangle((80, 110, img_width - 80, 180), fill=(248, 250, 252))
        draw.text((120, 135), "Personal Banking Portal", fill=(15, 23, 42))
        candidates = [(110, 124, 430, 170), (img_width - 430, 126, img_width - 120, 174)]

    elif bg_type == "dark":
        image = Image.new("RGB", (img_width, img_height), (17, 24, 39))
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, img_width, 88), fill=(3, 7, 18))
        draw.rounded_rectangle((130, 150, img_width - 130, img_height - 90), radius=14, fill=(31, 41, 55))
        draw.text((170, 185), "Digital Banking Login", fill=(229, 231, 235))
        candidates = [(46, 18, 390, 72), (170, 210, 520, 285)]

    elif bg_type == "fake_login":
        image = Image.new("RGB", (img_width, img_height), (236, 242, 248))
        draw = ImageDraw.Draw(image)
        card_w = rng.randint(390, 460)
        card_h = 430
        card_x = rng.randint(80, max(90, img_width - card_w - 80))
        card_y = rng.randint(110, max(120, img_height - card_h - 60))
        draw.rounded_rectangle((card_x, card_y, card_x + card_w, card_y + card_h), radius=12, fill=(255, 255, 255))
        draw.text((card_x + 34, card_y + 118), "Sign in to continue", fill=(15, 23, 42))
        draw_input(draw, card_x + 34, card_y + 180, card_w - 68, 44, "Username")
        draw_input(draw, card_x + 34, card_y + 268, card_w - 68, 44, "Password")
        draw.rounded_rectangle((card_x + 34, card_y + 345, card_x + card_w - 34, card_y + 394), radius=7, fill=(15, 118, 110))
        draw.text((card_x + 52, card_y + 360), "Login", fill=(255, 255, 255))
        candidates = [(card_x + 34, card_y + 28, card_x + card_w - 34, card_y + 104)]

    else:
        image = Image.new("RGB", (img_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        header_h = rng.randint(82, 118)
        draw.rectangle((0, 0, img_width, header_h), fill=(248, 250, 252))
        draw.line((0, header_h, img_width, header_h), fill=(226, 232, 240), width=2)
        nav_x = img_width // 2
        for i, text in enumerate(("Accounts", "Cards", "Loans", "Support")):
            draw.text((nav_x + i * 120, header_h // 2 - 8), text, fill=(71, 85, 105))
        draw.rectangle((0, header_h, img_width, img_height), fill=(239, 246, 255))
        draw.rounded_rectangle((90, header_h + 70, img_width - 90, img_height - 80), radius=14, fill=(255, 255, 255))
        draw.text((130, header_h + 110), "Welcome to online banking", fill=(15, 23, 42))
        candidates = [(42, 20, 410, header_h - 16), (130, header_h + 140, 520, header_h + 230)]

    return image, bg_type, candidates


def choose_position(
    canvas_size: tuple[int, int],
    logo_size: tuple[int, int],
    candidates: list[tuple[int, int, int, int]],
    rng: random.Random,
) -> tuple[int, int]:
    canvas_w, canvas_h = canvas_size
    logo_w, logo_h = logo_size

    if candidates and rng.random() < 0.78:
        x1, y1, x2, y2 = rng.choice(candidates)
        max_x = max(x1, x2 - logo_w)
        max_y = max(y1, y2 - logo_h)
        if max_x >= x1 and max_y >= y1:
            return rng.randint(x1, max_x), rng.randint(y1, max_y)

    max_x = max(0, canvas_w - logo_w - 24)
    max_y = max(0, canvas_h - logo_h - 24)
    return rng.randint(24, max(24, max_x)), rng.randint(24, max(24, max_y))


def split_for_index(index: int, total: int, args: argparse.Namespace) -> str:
    train_count = int(total * args.train_ratio)
    val_count = int(total * args.val_ratio)
    if index < train_count:
        return "train"
    if index < train_count + val_count:
        return "val"
    return "test"


def save_label(label_path: Path, class_id: int, bbox: tuple[int, int, int, int], image_size: tuple[int, int]) -> None:
    x1, y1, x2, y2 = bbox
    width, height = image_size
    x_center = ((x1 + x2) / 2) / width
    y_center = ((y1 + y2) / 2) / height
    box_width = (x2 - x1) / width
    box_height = (y2 - y1) / height
    label_path.write_text(
        f"{class_id} {x_center:.6f} {y_center:.6f} {box_width:.6f} {box_height:.6f}\n",
        encoding="utf-8",
    )


def draw_preview(sample: GeneratedSample, preview_root: Path) -> None:
    image = Image.open(sample.image_path).convert("RGB")
    draw = ImageDraw.Draw(image)
    if sample.bbox_xyxy is not None and sample.brand is not None:
        x1, y1, x2, y2 = sample.bbox_xyxy
        label = CLASS_DISPLAY_NAMES.get(sample.brand, sample.brand)
        draw.rectangle((x1, y1, x2, y2), outline=(239, 68, 68), width=4)
        draw.rectangle((x1, max(0, y1 - 24), x1 + 190, y1), fill=(239, 68, 68))
        draw.text((x1 + 6, max(0, y1 - 20)), label, fill=(255, 255, 255))
    else:
        draw.rectangle((12, 12, 205, 42), fill=(15, 23, 42))
        draw.text((20, 20), "NEGATIVE - no target logo", fill=(255, 255, 255))

    preview_path = preview_root / sample.split / sample.image_path.name
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(preview_path, quality=90)


def generate_one(
    brand: str,
    source_logo: Path,
    split: str,
    sequence: int,
    args: argparse.Namespace,
    rng: random.Random,
) -> GeneratedSample:
    background, _bg_type, candidates = create_background(args.img_width, args.img_height, rng)
    logo = load_logo(source_logo)
    logo_variant, visible_bbox = random_logo_variant(logo, args.img_width, args.img_height, rng)
    paste_x, paste_y = choose_position(background.size, logo_variant.size, candidates, rng)

    composed = background.convert("RGBA")
    composed.alpha_composite(logo_variant, (paste_x, paste_y))
    image = composed.convert("RGB")

    vx1, vy1, vx2, vy2 = visible_bbox
    bbox = (paste_x + vx1, paste_y + vy1, paste_x + vx2, paste_y + vy2)

    slug = brand_slug(brand)
    filename = f"synthetic_{slug}_{sequence:05d}.jpg"
    image_path = YOLO_DIR / "images" / split / filename
    label_path = YOLO_DIR / "labels" / split / f"{Path(filename).stem}.txt"
    image.save(image_path, quality=rng.randint(82, 94))
    save_label(label_path, CLASS_TO_ID[brand], bbox, image.size)

    return GeneratedSample(
        brand=brand,
        split=split,
        image_path=image_path,
        label_path=label_path,
        bbox_xyxy=bbox,
    )


def generate_negative(
    split: str,
    sequence: int,
    args: argparse.Namespace,
    rng: random.Random,
) -> GeneratedSample:
    image, _bg_type, _candidates = create_background(args.img_width, args.img_height, rng)
    filename = f"synthetic_negative_{sequence:05d}.jpg"
    image_path = YOLO_DIR / "images" / split / filename
    label_path = YOLO_DIR / "labels" / split / f"{Path(filename).stem}.txt"
    image.save(image_path, quality=rng.randint(82, 94))
    label_path.write_text("", encoding="utf-8")

    return GeneratedSample(
        brand=None,
        split=split,
        image_path=image_path,
        label_path=label_path,
        bbox_xyxy=None,
    )


def count_missing_labels() -> int:
    missing = 0
    for split in SPLITS:
        image_dir = YOLO_DIR / "images" / split
        label_dir = YOLO_DIR / "labels" / split
        for image_path in image_dir.iterdir():
            if image_path.is_file() and image_path.suffix.lower() in IMAGE_EXTENSIONS:
                if not (label_dir / f"{image_path.stem}.txt").exists():
                    missing += 1
    return missing


def dataset_inventory() -> dict[str, object]:
    per_class: dict[str, int] = defaultdict(int)
    per_split: dict[str, int] = defaultdict(int)
    negative_images = 0

    for split in SPLITS:
        image_dir = YOLO_DIR / "images" / split
        label_dir = YOLO_DIR / "labels" / split
        for image_path in image_dir.iterdir():
            if not image_path.is_file() or image_path.suffix.lower() not in IMAGE_EXTENSIONS:
                continue
            per_split[split] += 1
            label_path = label_dir / f"{image_path.stem}.txt"
            if not label_path.exists():
                continue
            lines = [line for line in label_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if not lines:
                negative_images += 1
                continue
            for line in lines:
                parts = line.split()
                if not parts:
                    continue
                try:
                    class_id = int(parts[0])
                except ValueError:
                    continue
                brand = ID_TO_CLASS.get(class_id)
                if brand:
                    per_class[CLASS_DISPLAY_NAMES[brand]] += 1

    return {
        "class_instances": dict(per_class),
        "split_images": {split: per_split.get(split, 0) for split in SPLITS},
        "negative_images": negative_images,
    }


def write_summary(
    generated: list[GeneratedSample],
    missing_raw_brands: list[str],
    args: argparse.Namespace,
) -> Path:
    per_class: dict[str, int] = defaultdict(int)
    per_split: dict[str, int] = defaultdict(int)
    negative_count = 0
    for sample in generated:
        if sample.brand is None:
            negative_count += 1
        else:
            per_class[CLASS_DISPLAY_NAMES.get(sample.brand, sample.brand)] += 1
        per_split[sample.split] += 1

    summary = {
        "classes": {str(CLASS_TO_ID[brand]): CLASS_DISPLAY_NAMES[brand] for brand in BRANDS},
        "requested_per_class": args.per_class,
        "requested_negative_images": args.negative_count,
        "generated_per_class": dict(per_class),
        "generated_negative_images": negative_count,
        "split_counts": {split: per_split.get(split, 0) for split in SPLITS},
        "dataset_totals": dataset_inventory(),
        "missing_raw_logo_classes": [CLASS_DISPLAY_NAMES.get(brand, brand) for brand in missing_raw_brands],
        "missing_labels": count_missing_labels(),
        "output_folders": {
            "train_images": str(YOLO_DIR / "images" / "train"),
            "val_images": str(YOLO_DIR / "images" / "val"),
            "test_images": str(YOLO_DIR / "images" / "test"),
            "train_labels": str(YOLO_DIR / "labels" / "train"),
            "val_labels": str(YOLO_DIR / "labels" / "val"),
            "test_labels": str(YOLO_DIR / "labels" / "test"),
            "previews": str(PREVIEWS_DIR / "synthetic"),
        },
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORTS_DIR / "synthetic_dataset_summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    csv_path = REPORTS_DIR / "synthetic_dataset_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["metric", "value"])
        writer.writerow(["requested_per_class", args.per_class])
        writer.writerow(["requested_negative_images", args.negative_count])
        for brand, count in summary["generated_per_class"].items():
            writer.writerow([f"generated_{brand}", count])
        for split, count in summary["split_counts"].items():
            writer.writerow([f"{split}_images", count])
        writer.writerow(["generated_negative_images", summary["generated_negative_images"]])
        dataset_totals = summary["dataset_totals"]
        for brand, count in dataset_totals["class_instances"].items():
            writer.writerow([f"dataset_total_{brand}", count])
        for split, count in dataset_totals["split_images"].items():
            writer.writerow([f"dataset_total_{split}_images", count])
        writer.writerow(["dataset_total_negative_images", dataset_totals["negative_images"]])
        writer.writerow(["missing_labels", summary["missing_labels"]])
        writer.writerow(["missing_raw_logo_classes", ", ".join(summary["missing_raw_logo_classes"])])

    return json_path


def main() -> None:
    args = parse_args()
    validate_args(args)
    ensure_dataset_dirs()
    write_data_yaml()

    if args.overwrite and yolo_targets_have_files():
        clear_yolo_targets()

    rng = random.Random(args.seed)
    logo_sources = load_logo_sources()
    missing_raw_brands = [brand for brand, paths in logo_sources.items() if not paths]
    generated: list[GeneratedSample] = []

    for brand in BRANDS:
        sources = logo_sources[brand]
        if not sources:
            continue

        split_sources = split_logo_sources(sources, args, rng)
        start_sequence = next_synthetic_sequence(brand)
        order = list(range(args.per_class))
        rng.shuffle(order)
        for sequence_index, _ in enumerate(order):
            split = split_for_index(sequence_index, args.per_class, args)
            source_logo = rng.choice(split_sources[split])
            try:
                sample = generate_one(
                    brand,
                    source_logo,
                    split,
                    start_sequence + sequence_index,
                    args,
                    rng,
                )
            except Exception as exc:  # noqa: BLE001 - keep generation moving and report failures.
                print(f"Skipped {source_logo}: {exc}")
                continue
            generated.append(sample)

    if args.negative_count:
        start_sequence = next_synthetic_sequence("negative")
        order = list(range(args.negative_count))
        rng.shuffle(order)
        for sequence_index, _ in enumerate(order):
            split = split_for_index(sequence_index, args.negative_count, args)
            generated.append(
                generate_negative(
                    split,
                    start_sequence + sequence_index,
                    args,
                    rng,
                )
            )

    preview_root = PREVIEWS_DIR / "synthetic"
    preview_samples = generated[:]
    rng.shuffle(preview_samples)
    for sample in preview_samples[: args.preview_limit]:
        draw_preview(sample, preview_root)

    summary_path = write_summary(generated, missing_raw_brands, args)
    print(f"Generated synthetic samples: {len(generated)}")
    print(f"Summary report: {summary_path}")
    print(f"Preview folder: {preview_root}")
    if missing_raw_brands:
        missing = ", ".join(CLASS_DISPLAY_NAMES.get(brand, brand) for brand in missing_raw_brands)
        print(f"Missing raw logo folders/images for: {missing}")


if __name__ == "__main__":
    main()
