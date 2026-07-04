# Cheon Jie Han Module: Visual Identity Analysis and Chrome Extension

This folder implements Student 2 scope only:

- Computer Vision logo detection
- Manifest V3 Chrome Extension
- Client-side webpage context extraction
- Screenshot + DOM payload submission to the FastAPI backend
- Popup and warning banner result display

It does not replace Yi Ler's NLP/BERT backend module. It adds the visual endpoint used by the extension.

## 1. Install Dependencies

Run from the inner project folder:

```powershell
cd D:\FYP\PhishGuard-Backend-main\PhishGuard-Backend-main
python -m pip install -r requirements.txt
```

If `python` is not recognised on Windows, use:

```powershell
py -3 -m pip install -r requirements.txt
```

Or run the helper:

```powershell
.\visual_identity\scripts\install_dependencies.ps1
```

The visual module uses `ultralytics` YOLOv8 and `Pillow`.
In this workspace, dependencies are installed into:

```text
D:\FYP\PhishGuard-Backend-main\PhishGuard-Backend-main\.venv
```

## 2. Prepare Dataset Folders

```powershell
python .\visual_identity\scripts\prepare_dataset.py
```

This creates the YOLOv8 dataset structure:

```text
visual_identity/
  data/
    raw/
      maybank/images
      cimb/images
      public_bank/images
      rhb/images
      hong_leong_bank/images
    yolo/
      images/train
      images/val
      images/test
      labels/train
      labels/val
      labels/test
      data.yaml
```

Supported logo classes:

```text
0 Maybank
1 CIMB
2 PublicBank
3 RHB
4 HongLeongBank
```

## 3. Import Raw Images

If your images are already sorted by brand folders, the script will try to infer the brand from folder names:

```powershell
python .\visual_identity\scripts\import_raw_images.py --source D:\Datasets\PhishPedia
```

If the script cannot infer the brand, import one brand at a time:

```powershell
python .\visual_identity\scripts\import_raw_images.py --source D:\Datasets\maybank_logos --brand Maybank
python .\visual_identity\scripts\import_raw_images.py --source D:\Datasets\cimb_logos --brand CIMB
```

If images already have YOLO `.txt` labels beside them, the labels are copied automatically.

## 4. Synthetic Dataset Generation

For FYP demonstration, you can provide a few clean official logo images for each bank, then generate many YOLO training images automatically.

The detector still has exactly five target bank classes. Optional negative
images contain no target logo and therefore use an empty YOLO label; they help
prevent ordinary webpage graphics from being mistaken for a supported bank.
Raw logo sources are assigned to separate train/val/test pools so newly
generated variants from one source do not leak across dataset splits.

Put clean logo images here:

```text
visual_identity/data/raw/maybank/images
visual_identity/data/raw/cimb/images
visual_identity/data/raw/public_bank/images
visual_identity/data/raw/rhb/images
visual_identity/data/raw/hong_leong_bank/images
```

Then run:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\generate_synthetic_dataset.py --per-class 300
```

To add 300 background-only negative samples without generating more positive
logo samples:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\generate_synthetic_dataset.py --per-class 0 --negative-count 300
```

After adding or regenerating samples, run YOLO training again and copy the new
`best.pt` into `visual_identity/models/best.pt`; dataset changes do not modify an
already trained model automatically.

Optional settings:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\generate_synthetic_dataset.py --per-class 300 --img-width 1280 --img-height 720 --train-ratio 0.7 --val-ratio 0.2 --test-ratio 0.1
```

The script creates webpage-like screenshots using:

- white backgrounds
- light grey backgrounds
- dark backgrounds
- simple fake login page layouts
- simple fake banking header layouts

It randomly changes:

- logo size
- logo position
- brightness
- contrast
- slight blur
- padding
- background layout

Because the script knows exactly where the logo was pasted, it automatically writes the YOLO bbox label.

Output folders:

```text
visual_identity/data/yolo/images/train
visual_identity/data/yolo/images/val
visual_identity/data/yolo/images/test
visual_identity/data/yolo/labels/train
visual_identity/data/yolo/labels/val
visual_identity/data/yolo/labels/test
```

Preview images with boxes:

```text
visual_identity/data/reports/previews/synthetic
```

Summary report:

```text
visual_identity/data/reports/synthetic_dataset_summary.json
visual_identity/data/reports/synthetic_dataset_summary.csv
```

By default, the script appends new `synthetic_...` images and labels without overwriting existing real dataset files. To replace the current YOLO dataset, run with:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\generate_synthetic_dataset.py --per-class 300 --overwrite
```

## 5. Split and Check Labels

Check the raw images before splitting:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\clean_images.py
```

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\split_dataset.py
.\.venv\Scripts\python.exe .\visual_identity\scripts\check_dataset.py
```

The checker writes manual review items here:

```text
visual_identity/data/reports/manual_review.csv
```

YOLO labels must be:

```text
class_id x_center y_center width height
```

All bbox values must be normalized from `0` to `1`.

## 6. Semi-Automatic Labelling Workflow

If labels are missing, use this helper only as a draft:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\create_draft_labels.py
.\.venv\Scripts\python.exe .\visual_identity\scripts\preview_labels.py --split all --limit 100
```

Preview images are generated in:

```text
visual_identity/data/reports/previews
```

Important: draft labels are not final. Manually check and correct every logo bounding box before training.

## 7. Train YOLOv8

Default lightweight training command:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\train_yolov8.py --model yolov8n.pt --epochs 50 --imgsz 640 --batch 8
```

After training, copy the best model to:

```text
visual_identity/models/best.pt
```

Example:

```powershell
copy .\visual_identity\runs\phishguard_logo_yolov8n\weights\best.pt .\visual_identity\models\best.pt
```

Or use the helper:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\copy_best_model.py
```

Optional export:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\export_model.py --weights .\visual_identity\models\best.pt --format onnx
```

## 7.1 Improving the Visual Model With Real Screenshots

The synthetic dataset is useful for bootstrapping, but the complete system should also include real website screenshots. Focus on cases where the current model is weakest:

- RHB official logo recall
- Maybank bounding boxes that are too large
- Public Bank / CIMB cross-brand confusion

Recommended workflow:

1. Capture real screenshots from official bank pages and controlled fake pages.
2. Label the exact logo area manually using a YOLO labelling tool such as LabelImg, Roboflow, or CVAT.
3. Save labelled screenshots directly into the YOLO dataset folders:

```text
visual_identity/data/yolo/images/train
visual_identity/data/yolo/images/val
visual_identity/data/yolo/images/test
visual_identity/data/yolo/labels/train
visual_identity/data/yolo/labels/val
visual_identity/data/yolo/labels/test
```

4. Keep the same class ids:

```text
0 Maybank
1 CIMB
2 Public Bank
3 RHB
4 Hong Leong Bank
```

5. Check labels and generate previews:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\check_dataset.py
.\.venv\Scripts\python.exe .\visual_identity\scripts\preview_labels.py --split all --limit 3000
```

6. Retrain and copy the new best model:

```powershell
.\.venv\Scripts\python.exe .\visual_identity\scripts\train_yolov8.py --model yolov8n.pt --epochs 80 --imgsz 640 --batch 8 --name phishguard_logo_real_v2
.\.venv\Scripts\python.exe .\visual_identity\scripts\copy_best_model.py --source .\visual_identity\runs\phishguard_logo_real_v2\weights\best.pt
```

Use the preview images to manually confirm that the bounding boxes are tight around the actual logo, not the whole banner or large webpage region.

## 8. Run FastAPI Backend

Normal backend:

```powershell
.\.venv\Scripts\uvicorn.exe main:app --host 127.0.0.1 --port 8000
```

If Yi Ler's BERT `model.safetensors` is still only a Git LFS pointer, run visual-only demo mode:

```powershell
$env:YOLO_CONFIG_DIR="D:\FYP\PhishGuard-Backend-main\PhishGuard-Backend-main\visual_identity\.ultralytics"
$env:PHISHGUARD_ENABLE_SEMANTIC="false"
.\.venv\Scripts\uvicorn.exe main:app --host 127.0.0.1 --port 8000 --reload
```

Visual endpoint:

```text
POST http://127.0.0.1:8000/api/visual/analyze
Authorization: Bearer phishguard_secret_key_2026
```

Input JSON:

```json
{
  "current_url": "https://example.com",
  "page_title": "Example Page",
  "visible_text": "Visible DOM text",
  "screenshot": "data:image/jpeg;base64,..."
}
```

Output JSON:

```json
{
  "detected_logos": [
    {
      "brand": "Maybank",
      "confidence": 0.95,
      "bbox": {
        "x1": 100,
        "y1": 80,
        "x2": 230,
        "y2": 160
      }
    }
  ],
  "risk_level": "dangerous",
    "reason": "Maybank logo detected but the URL domain 'fake-bank.example' does not match an authorised Maybank domain (maybank2u.com.my, maybank.com, maybank.com.my)."
}
```

## 9. Load Chrome Extension

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Enable `Developer mode`.
4. Click `Load unpacked`.
5. Select:

```text
D:\FYP\PhishGuard-Backend-main\PhishGuard-Backend-main\chrome_extension
```

When you edit extension files, press the extension reload button in `chrome://extensions`, then refresh the test webpage.

## 10. How Screenshot and DOM Extraction Works

The content script runs on HTTP/HTTPS pages and extracts:

- Current URL
- Page title
- Visible text using `document.body.innerText`
- DOM HTML using `document.documentElement.outerHTML`

The service worker captures the visible tab screenshot using:

```text
chrome.tabs.captureVisibleTab
```

Then it sends URL, title, visible text, DOM HTML, and screenshot to the backend.

Visual endpoint:

```text
/api/visual/analyze
```

Semantic + mule endpoint:

```text
/api/v1/analyse/semantics
```

The extension does not permanently store webpage text or screenshots. It only keeps the latest risk result for the active tab.

## 11. Combined Browser Verdict

The Chrome Extension now combines:

- Visual logo-domain mismatch result
- BERT semantic phishing result
- Mule account scanner result

Final verdict rules:

```text
Mule account detected -> BLOCK_RENDER
Visual dangerous -> BLOCK_RENDER
Visual suspicious -> warning
BERT malicious on non-official or visually mismatched domain -> BLOCK_RENDER
Official bank domain + visual safe -> SAFE, even if BERT has a false positive
All clear -> SAFE
```

The popup displays:

- Visual result
- BERT semantic result
- Mule account result
- Final verdict

If mule accounts are detected, the content script highlights the flagged account numbers on the webpage.

## 12. Logo-Domain Mismatch Detection

The backend checks detected logos against authorised domains:

```text
Maybank -> maybank2u.com.my, maybank.com, maybank.com.my
CIMB -> cimbclicks.com.my, cimb.com.my, cimbbank.com.my
Public Bank -> pbebank.com, pbebank.com.my, publicbank.com.my
RHB -> rhbgroup.com, rhbnow.com, rhbbank.com.my
Hong Leong Bank -> hlb.com.my
```

If a supported logo is detected on a non-authorised domain, the endpoint returns:

- `suspicious` for lower-confidence mismatch
- `dangerous` for high-confidence mismatch

For official bank domains, the visual endpoint uses the authorised domain as a guardrail. Low-confidence cross-brand detections on an official domain are treated as visual-model noise so that an official `pbebank.com` page is not blocked just because the YOLO model briefly mistakes part of the page for another bank logo.

The extension then injects a simple warning banner into the webpage.

## 12.1 Official Site Test Report

The latest official-site scan report is saved here:

```text
visual_identity/data/reports/official_site_scan_report.json
```

Screenshots captured during the official-site test are saved here:

```text
visual_identity/data/reports/official_site_scans
```

## 13. Connection to Yi Ler's Backend/NLP Module

Yi Ler's module handles:

- BERT semantic phishing detection
- Mule account scanner
- SQLite backend database
- `/api/v1/analyse/semantics`

Cheon's module adds:

- YOLOv8 visual logo detector
- `/api/visual/analyze`
- Chrome Extension screenshot and DOM extraction
- Popup result display
- Warning banner injection
- Combined browser-side verdict display using Yi Ler's existing semantic endpoint

Both modules share the same FastAPI backend and API token, but the visual endpoint is separate so Cheon's scope can be tested even while the BERT model is not ready.

## 14. Proposal Match

This implementation matches Cheon Jie Han's proposal role:

- Computer Vision modelling: YOLOv8 transfer learning for Malaysian bank logo detection
- Manifest V3 Extension Engineering: service worker, content script, popup UI
- Client-Side Interception Logic: URL, title, visible DOM text, and screenshot extraction
- Secure API integration: screenshot + DOM payload sent to FastAPI with Bearer token
- User warning: safe, suspicious, and dangerous result display
