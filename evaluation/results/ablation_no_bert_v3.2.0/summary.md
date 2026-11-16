# Malaysian benchmark results — `ablation_no_bert_v3.2.0` (v3.2.0)

Samples: 120 (60 malicious, 60 legitimate). Device: cpu. BERT threshold: 0.75. BERT signal in pipeline: DISABLED (ablation).

## Pipeline verdict (BLOCK_RENDER vs SAFE)

| Split | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| overall | 120 | 51 | 0 | 9 | 60 | 0.9250 | 1.0000 | 0.8500 | 0.9189 | 0.0000 |
| dev | 60 | 25 | 0 | 5 | 30 | 0.9167 | 1.0000 | 0.8333 | 0.9091 | 0.0000 |
| holdout | 60 | 26 | 0 | 4 | 30 | 0.9333 | 1.0000 | 0.8667 | 0.9286 | 0.0000 |

## Pipeline accuracy per category

| Category | n | Correct | Blocked | Accuracy |
|---|---|---|---|---|
| L1_official_portal | 14 | 14 | 0 | 1.0000 |
| L2_benign_brand_mention | 20 | 20 | 0 | 1.0000 |
| L3_general_benign | 14 | 14 | 0 | 1.0000 |
| L4_benign_with_accounts | 12 | 12 | 0 | 1.0000 |
| P1_bank_lookalike | 14 | 14 | 14 | 1.0000 |
| P2_bm_manglish_lure | 14 | 12 | 12 | 0.8571 |
| P3_mule_account | 12 | 12 | 12 | 1.0000 |
| P4_ewallet_brand | 10 | 10 | 10 | 1.0000 |
| P5_evasive | 10 | 3 | 3 | 0.3000 |

## Rule that produced each BLOCK_RENDER

| Rule | Pages blocked |
|---|---|
| R1_MULE_REGISTRY | 12 |
| R2_BRAND_IN_HOSTNAME | 29 |
| R3_LOOKALIKE_DOMAIN | 5 |
| R4_BRAND_CLONE | 3 |
| R5_COERCIVE_CREDENTIAL_REQUEST | 2 |

## BERT-only (no rule layer)

| Input formulation | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| composite | 0.5000 | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 0.7037 |
| url_raw | 0.5333 | 0.5185 | 0.9333 | 0.6667 | 0.8667 | 0.7596 |
| url_stripped | 0.7250 | 0.6709 | 0.8833 | 0.7626 | 0.4333 | 0.8599 |

## In-process latency (ms)

- All requests: mean 0.28, p50 0.19, p95 0.58, max 1.99
- BERT path (n=102): mean 0.27, p50 0.19, p95 0.56
- Whitelist bypass (n=18): mean 0.32

## Misclassified samples (9)

- MY-083 (P2_bm_manglish_lure, false negative): http://mysejahtera-subsidi.buzz/claim
- MY-085 (P2_bm_manglish_lure, false negative): http://mahkamah-notis-rasmi.work/kes
- MY-111 (P5_evasive, false negative): https://secure-portal-update.com/my/auth
- MY-112 (P5_evasive, false negative): https://customer-care-desk.net/verify
- MY-116 (P5_evasive, false negative): https://docs.google.com/forms/d/e/1FAIpQLSfakeformid/viewform
- MY-117 (P5_evasive, false negative): http://form-submit-online.site/m2u
- MY-118 (P5_evasive, false negative): https://hr-payroll-notice.com/payslip
- MY-119 (P5_evasive, false negative): https://smart-invest-daily.com/join
- MY-120 (P5_evasive, false negative): https://parcel-redelivery-my.com/pay
