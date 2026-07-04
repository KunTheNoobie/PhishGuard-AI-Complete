from __future__ import annotations

from pathlib import Path

BRANDS: list[str] = [
    "Maybank",
    "CIMB",
    "Public Bank",
    "RHB",
    "Hong Leong Bank",
]

CLASS_TO_ID: dict[str, int] = {brand: index for index, brand in enumerate(BRANDS)}
ID_TO_CLASS: dict[int, str] = {index: brand for brand, index in CLASS_TO_ID.items()}

ROOT_DIR: Path = Path(__file__).resolve().parents[1]
DATA_DIR: Path = ROOT_DIR / "data"
RAW_DIR: Path = DATA_DIR / "raw"
YOLO_DIR: Path = DATA_DIR / "yolo"
REPORTS_DIR: Path = DATA_DIR / "reports"
PREVIEWS_DIR: Path = REPORTS_DIR / "previews"
MODELS_DIR: Path = ROOT_DIR / "models"
ULTRALYTICS_CONFIG_DIR: Path = ROOT_DIR / ".ultralytics"
MPL_CONFIG_DIR: Path = ROOT_DIR / ".matplotlib"
DATA_YAML: Path = YOLO_DIR / "data.yaml"
CLASSES_TXT: Path = ROOT_DIR / "classes.txt"
DRAFT_LABELS_CSV: Path = REPORTS_DIR / "draft_labels_for_review.csv"

IMAGE_EXTENSIONS: set[str] = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

BRAND_ALIASES: dict[str, list[str]] = {
    "Maybank": ["maybank", "maybank2u"],
    "CIMB": ["cimb", "cimbclicks"],
    "Public Bank": ["publicbank", "public_bank", "public bank", "pbe", "pbebank"],
    "RHB": ["rhb", "rhbgroup"],
    "Hong Leong Bank": ["hongleong", "hong_leong", "hong leong", "hlb"],
}


def brand_slug(brand: str) -> str:
    return brand.lower().replace(" ", "_")


def ensure_dataset_dirs() -> None:
    for brand in BRANDS:
        (RAW_DIR / brand_slug(brand) / "images").mkdir(parents=True, exist_ok=True)
        (RAW_DIR / brand_slug(brand) / "labels").mkdir(parents=True, exist_ok=True)

    for split in ("train", "val", "test"):
        (YOLO_DIR / "images" / split).mkdir(parents=True, exist_ok=True)
        (YOLO_DIR / "labels" / split).mkdir(parents=True, exist_ok=True)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PREVIEWS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    ULTRALYTICS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    MPL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def write_classes_file() -> None:
    CLASSES_TXT.write_text("\n".join(BRANDS) + "\n", encoding="utf-8")


def write_data_yaml() -> None:
    names = "\n".join(f"  {index}: {brand}" for index, brand in ID_TO_CLASS.items())
    content = (
        f"path: {YOLO_DIR.as_posix()}\n"
        "train: images/train\n"
        "val: images/val\n"
        "test: images/test\n"
        f"names:\n{names}\n"
    )
    DATA_YAML.write_text(content, encoding="utf-8")


def iter_images(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS:
            yield path


def infer_brand_from_text(text: str) -> str | None:
    normalized = text.lower().replace("-", "_")
    for brand, aliases in BRAND_ALIASES.items():
        if any(alias in normalized for alias in aliases):
            return brand
    return None


def infer_brand_from_path(path: Path) -> str | None:
    parts = [path.stem, *[part for part in path.parts]]
    for part in parts:
        brand = infer_brand_from_text(part)
        if brand:
            return brand
    return None


def yolo_label_for_image(image_path: Path, labels_root: Path | None = None) -> Path:
    if labels_root:
        return labels_root / f"{image_path.stem}.txt"
    return image_path.with_suffix(".txt")


def latest_best_pt() -> Path | None:
    candidates = sorted(
        ROOT_DIR.glob("runs/**/weights/best.pt"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None
