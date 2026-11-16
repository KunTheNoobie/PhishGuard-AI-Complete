# PhishGuard-AI — Evaluation Artefacts (v3.2.0)

Every quantitative claim in the dissertation is traceable to a file in this folder.
All numbers below were produced on the development machine:

| Item | Value |
|---|---|
| CPU / RAM | AMD Ryzen 7 5700G (8 cores / 16 threads), 32 GB |
| GPU | none used for inference (PyTorch 2.12.1 CPU build, 8 intra-op threads) |
| OS / Python | Windows 11, Python 3.14.3 |
| Model | `bert-base-uncased` fine-tuned for 1 epoch (27,468 steps) on 439,476 URLs |
| Date of runs | 16 November 2026 |

## 1. BERT URL classifier — Kaggle hold-out (109,870 URLs)

Source: the Colab training run (`trainer_state.json`, epoch 1.0 evaluation).
`kaggle_holdout_metrics.py` reconstructs the confusion matrix that is uniquely
implied by the logged accuracy, precision, recall and F1.

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Actual legitimate** (78,670) | 78,293 (TN) | 377 (FP) |
| **Actual phishing** (31,200) | 982 (FN) | 30,218 (TP) |

Accuracy 98.76 %, precision 98.77 %, recall 96.85 %, F1 97.80 %, false-positive rate 0.48 %.
Training loss 0.0578, validation loss 0.0497. The run evaluated once (end of epoch); no
intermediate validation points and no ROC-AUC exist for this split.

```bash
python -m evaluation.kaggle_holdout_metrics
```

## 2. End-to-end pipeline — Malaysian benchmark (120 pages)

`datasets/malaysia_eval_v1.jsonl` is a hand-curated benchmark: 60 legitimate and 60
malicious pages in nine categories, split 50/50 into `dev` and `holdout`.

**Read the caveats in `build_dataset.py` before quoting these numbers.** The page text was
authored for this project (it is not scraped), malicious URLs are fictitious, mule samples
reference the seeded (simulated) registry, and the benchmark is small. The rule layer was
tuned on the `dev` split only; baseline errors on both splits were inspected when fixing
the whitelist. The results show that the pipeline behaves as designed on representative
Malaysian patterns; they are not an estimate of field accuracy.

| Configuration | Accuracy | Precision | Recall | F1 | False-positive rate | TP / FP / FN / TN |
|---|---|---|---|---|---|---|
| Baseline v3.0.0 (before fixes) | 57.50 % | 54.37 % | 93.33 % | 68.71 % | 78.33 % | 56 / 47 / 4 / 13 |
| **Final v3.2.0** | **97.50 %** | **100.00 %** | **95.00 %** | **97.44 %** | **0.00 %** | 57 / 0 / 3 / 60 |
| Final v3.2.0, `dev` split | 96.67 % | 100.00 % | 93.33 % | 96.55 % | 0.00 % | 28 / 0 / 2 / 30 |
| Final v3.2.0, `holdout` split | 98.33 % | 100.00 % | 96.67 % | 98.31 % | 0.00 % | 29 / 0 / 1 / 30 |
| Ablation: v3.2.0 without the BERT signal | 92.50 % | 100.00 % | 85.00 % | 91.89 % | 0.00 % | 51 / 0 / 9 / 60 |

BERT used alone on the same 120 pages (threshold 0.75), by input formulation:

| BERT input | Accuracy | Recall | False-positive rate | ROC-AUC |
|---|---|---|---|---|
| `URL: <url> \| <page text>` (v3.0.0 behaviour) | 50.00 % | 100.00 % | 100.00 % | 0.704 |
| URL as received (with scheme) | 53.33 % | 93.33 % | 86.67 % | 0.760 |
| URL without scheme / `www.` (v3.2.0, matches training data) | 72.50 % | 88.33 % | 43.33 % | 0.860 |

The three remaining false negatives are a sparse "Loading…" page on a neutral domain, an
investment-scam page with no credential request, and a phishing form hosted on Google Forms
(a whitelisted domain). They are documented as limitations.

In-process latency of the analysis endpoint (single client, CPU): BERT path mean 108 ms,
p95 115 ms; whitelist bypass mean 0.28 ms.

```bash
python -m evaluation.build_dataset
python -m evaluation.evaluate_pipeline --tag final_v3.2.0
python -m evaluation.evaluate_pipeline --tag ablation_no_bert_v3.2.0 --no-bert
```

## 3. Load test — Locust 2.44.4 (`results/locust/`)

Server: `uvicorn main:app --host 127.0.0.1 --port 8765`, one worker process, real BERT model
on CPU. Locust ran on the same machine, so client and server competed for the same cores.
Task mix per user (wait 1–3 s): 3× non-whitelisted page with a unique URL (forces a real
BERT forward pass), 2× whitelisted page, 1× phishing page (BERT result cached), 1× mule
page on a trusted host, 2× `/health`, 1× `/dashboard/stats`.

| Run | Rate limit | Users | Requests | Errors | Throughput | p50 | p95 | p99 | Max |
|---|---|---|---|---|---|---|---|---|---|
| `run_50u` (60 s) | lifted (`1000000/minute`) | 50 | 1,333 | 0 (0.00 %) | 22.39 req/s | 13 ms | 370 ms | 490 ms | 600 ms |
| `run_200u` (60 s) | lifted | 200 | 2,418 | 0 (0.00 %) | 40.40 req/s | 96 ms | 11,000 ms | 12,000 ms | 12,266 ms |
| `run_50u_default_limit` (45 s) | default `60/minute` | 50 | 1,014 | 646 (63.71 %), all HTTP 429 | 23.04 req/s | 3 ms | 17 ms | 230 ms | 584 ms |

BERT cache-miss path only: 50 users — median 190 ms, p95 450 ms, p99 560 ms (6.73 req/s);
200 users — median 9,700 ms, p95 12,000 ms (10.69 req/s). A single CPU worker therefore
sustains roughly 10–11 uncached BERT inferences per second; above that, requests queue.
No request failed in either lifted-limit run.

With the default limit, all 50 simulated users share one IP address, so the limiter admitted
60 analysis requests and rejected the other 646 with HTTP 429 — the intended behaviour.

```bash
PHISHGUARD_RATE_LIMIT=1000000/minute python -m uvicorn main:app --host 127.0.0.1 --port 8765
python -m locust -f tests/locustfile.py --host http://127.0.0.1:8765 --headless -u 50 -r 5 -t 60s --csv evaluation/results/locust/run_50u
```

## 4. Automated tests and coverage (`results/pytest/`, `results/coverage/`)

198 tests in 10 modules, 198 passed (12.76 s with coverage, 10.21 s without).
Statement + branch coverage measured with `pytest-cov`: **77 %** overall
(2,788 statements, 542 missed; 668 branches). The unit tests use a mocked BERT engine and
an in-memory SQLite database; the real model is exercised by section 2 above.

| Lowest-covered modules | Coverage | Reason |
|---|---|---|
| `services/webhook_notifier.py` | 27 % | outbound HTTP to Discord / Slack / Telegram is not called in tests |
| `services/visual_sandbox.py` | 37 % | requires a headless browser |
| `main.py` | 42 % | lifespan start-up, simulator loop and Swagger HTML are not run under the test client |
| `services/visual_detector.py` | 44 % | YOLO inference is mocked |
| `services/nlp_engine.py` | 56 % | real BERT forward pass is mocked in unit tests |

```bash
python -m pytest --cov --cov-report=term
```

## 5. Visual module — YOLOv8n logo detector (reference)

Training artefacts live in `visual_identity/runs/phishguard_logo_yolov8n/` (git-ignored).
Final epoch (46): precision 0.979, recall 0.996, mAP@0.5 0.991, mAP@0.5:0.95 0.979 on the
validation split (366 images). The dataset (1,286 train / 366 val / 187 test) was generated
synthetically from 39 source screenshots of five banks, so these figures describe
performance on synthetic compositions, not on live phishing pages.
