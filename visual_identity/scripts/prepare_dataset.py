from __future__ import annotations

from common import BRANDS, DATA_YAML, RAW_DIR, ensure_dataset_dirs, write_classes_file, write_data_yaml


def main() -> None:
    ensure_dataset_dirs()
    write_classes_file()
    write_data_yaml()

    print("Dataset folders prepared.")
    print(f"Raw image folder: {RAW_DIR}")
    print(f"YOLO config: {DATA_YAML}")
    print("Supported classes:")
    for index, brand in enumerate(BRANDS):
        print(f"  {index}: {brand}")


if __name__ == "__main__":
    main()

