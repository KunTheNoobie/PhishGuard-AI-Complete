<!-- Generated from PhishGuard-AI_Project_1_&_2_Report_LiewYiLer.docx (v3.2.0, 16 November 2026). The Word document is the authoritative version; edit it, not this file. -->

# Appendix

## Appendix A: Captured API Responses (v3.2.0)

The following responses were captured from the application at version 3.2.0 with the real BERT model loaded (captured on 16 November 2026). They are reproduced without modification, apart from the omission of repeated fields where indicated.

**A.1 Blocked look-alike page — POST /api/v1/analyze/semantics (HTTP 200)**

```
{
  "meta": {
    "transaction_id": "b12c2998-ed8b-4185-83a5-da429cf43ffa",
    "processing_time_ms": 115.64
  },
  "data": {
    "semantic_analysis": {
      "label": "PHISHING",
      "confidence": 0.999911,
      "is_malicious": true,
      "sanitized_text_preview": "Maybank2u Your account access has been limited. Log in and enter the TAC sent to your phone to restore access."
    },
    "mule_scan": {
      "accounts_extracted": [],
      "flagged_accounts": [],
      "mule_detected": false
    }
  },
  "orchestration": "BLOCK_RENDER",
  "status": "success",
  "verdict": "BLOCK_RENDER",
  "risk_score": 0.97,
  "threat_indicators": [
    "Hostname embeds protected brand 'Maybank' (maybank) on a domain it does not own",
    "High-risk disposable TLD detected (.top)"
  ],
  "decision_rule": "R2_BRAND_IN_HOSTNAME",
  "signals": {
    "mule": false,
    "brand_host": true,
    "lookalike": false,
    "brand_mention": false,
    "bert": true,
    "heuristic": true,
    "heuristic_strong": true,
    "credential_form": true,
    "credential_text": true,
    "credential_request": true,
    "scam_language": false
  },
  "bert_score": 0.999911,
  "is_whitelisted": false,
  "brand_impersonation": {
    "target_brand": "Maybank",
    "is_impersonation": true,
    "is_official_domain": false,
    "brand_in_hostname": true,
    "lookalike_domain": false,
    "brand_mentioned": false,
    "impersonation_index": 0.98,
    "matched_brand_cues": [
      "maybank"
    ],
    "hostname": "maybank2u-secure-login.top"
  },
  "mule_accounts_flagged": [],
  "execution_time_ms": 115.64,
  "timestamp": "2026-11-16T01:29:35+08:00"
}
```
**A.2 Legitimate article that mentions a bank (HTTP 200, abridged)**

```
{
  "orchestration": "SAFE",
  "decision_rule": null,
  "risk_score": 0.1015,
  "threat_indicators": [
    "Mentions 'Maybank' (informational)"
  ],
  "bert_score": 0.985493,
  "is_whitelisted": false,
  "data": {
    "semantic_analysis": {
      "label": "LEGITIMATE",
      "confidence": 0.985493,
      "is_malicious": false,
      "sanitized_text_preview": "Maybank has revised its fixed deposit rates this month. Here is how the new rates compare with CIMB, Public Bank and RHB."
    }
  },
  "signals": {
    "mule": false,
    "brand_host": false,
    "lookalike": false,
    "brand_mention": true,
    "bert": false,
    "heuristic": false,
    "heuristic_strong": false,
    "credential_form": false,
    "credential_text": false,
    "credential_request": false,
    "scam_language": false
  }
}
```
**A.3 Page displaying a registered mule account (HTTP 200, abridged)**

```
{
  "orchestration": "BLOCK_RENDER",
  "decision_rule": "R1_MULE_REGISTRY",
  "risk_score": 0.99,
  "threat_indicators": [
    "Account found in mule registry: 112233445566"
  ],
  "data": {
    "mule_scan": {
      "accounts_extracted": [
        "112233445566"
      ],
      "flagged_accounts": [
        {
          "account_number": "112233445566",
          "bank_name": "Maybank",
          "report_count": 14
        }
      ],
      "mule_detected": true
    }
  }
}
```
**A.4 Error responses**

```
POST /api/v1/analyze/semantics without Authorization header  ->  HTTP 401
{"detail": "Not authenticated"}

POST /api/v1/analyze/semantics with whitespace-only content   ->  HTTP 422
{"detail": [{"type": "value_error", "loc": ["body"], "msg": "Value error, Payload must contain non-empty 'dom_content' or 'text_content'."}]}

GET /api/v1/dashboard/stats without credentials               ->  HTTP 401
{"detail": {"error": "DASHBOARD_AUTH_REQUIRED", "message": "Administrative authentication is required for SOC dashboard endpoints."}}

POST /api/v1/mule-reports (valid report)                      ->  HTTP 201
{"report_id": 1, "status": "PENDING", "already_registered": false}
```

## Appendix B: Corroborated Verdict Engine Implementation Excerpt

The following excerpt from services/verdict_engine.py (function decide) is the complete rule cascade described in Table 4.14. The dictionary s holds the signals of Table 4.13.

```
if is_trusted:
    notes = ["Domain is on the trusted whitelist"]
    if s["mule"]:
        notes.append("Registered mule account displayed on a trusted domain (reported, not blocked)")
    return Verdict(False, VERDICT_SAFE, 0.0, None, notes, s)

if s["mule"]:
    accounts = ", ".join(str(a.get("account_number")) for a in mule_result.get("flagged_accounts", []))
    return blocked("R1_MULE_REGISTRY", 0.99, f"Account found in mule registry: {accounts}")

if s["brand_host"] and (any_credential or s["scam_language"] or s["bert"] or s["heuristic"]):
    return blocked("R2_BRAND_IN_HOSTNAME", 0.97,
                   f"Hostname embeds protected brand '{brand}' ({cues}) on a domain it does not own")

if s["lookalike"] and (any_credential or s["bert"] or s["heuristic_strong"]):
    return blocked("R3_LOOKALIKE_DOMAIN", 0.95, f"Hostname is a {cues} ({brand})")

if s["brand_mention"] and s["credential_request"] and (s["bert"] or s["heuristic"] or s["scam_language"]):
    return blocked("R4_BRAND_CLONE", 0.93,
                   f"Page presents itself as '{brand}' and requests credentials on an unaffiliated domain")

if s["credential_request"] and s["scam_language"] and (s["bert"] or s["heuristic"]):
    return blocked("R5_COERCIVE_CREDENTIAL_REQUEST", 0.90,
                   "Coercive or urgent language combined with a credential request")

if s["heuristic_strong"] and s["bert"] and (any_credential or s["scam_language"] or s["brand_mention"]):
    return blocked("R6_EVASIVE_INFRASTRUCTURE", 0.90,
                   "Evasive hosting (raw IP, punycode or disposable TLD) with phishing content cues")
```

## Appendix C: Automated Test Suite Output Logs

The following terminal output is the unedited result of running python -m pytest --cov on 16 November 2026 (file evaluation/results/pytest/pytest_cov_output.txt; path prefixes and deprecation warnings omitted). All 198 tests pass; statement and branch coverage is 77%.

```
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
plugins: anyio-4.14.0, locust-2.44.4, asyncio-1.4.0, cov-7.1.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=function, asyncio_default_test_loop_scope=function
collected 198 items
tests\test_endpoints.py .........................                        [ 12%]
tests\test_enhancements.py ............................................. [ 35%]
tests\test_mule_reports.py ............                                  [ 41%]
tests\test_mule_scanner.py ..............                                [ 48%]
tests\test_nlp_engine.py .........                                       [ 53%]
tests\test_repository.py ........                                        [ 57%]
tests\test_sanitizer.py .............                                    [ 64%]
tests\test_security.py ....................                              [ 74%]
tests\test_verdict_engine.py ........................................... [ 95%]
tests\test_visual.py ........                                            [100%]
_______________ coverage: platform win32, python 3.14.3-final-0 _______________
Name                              Stmts   Miss Branch BrPart  Cover
-------------------------------------------------------------------
api\dashboard_endpoints.py          850    138    144     31    78%
api\endpoints.py                    113     16     22      6    84%
api\visual.py                        24      5      2      0    81%
core\config.py                       36      2      0      0    94%
core\rate_limit.py                    7      0      0      0   100%
core\security.py                     46      3     18      3    91%
database\init_db.py                  37      2      8      1    89%
database\repository.py               71      1     14      1    98%
main.py                             151     81     22      1    42%
schemas\payload.py                   30      0      8      1    97%
schemas\response.py                  48      0      0      0   100%
schemas\visual.py                    21      0      0      0   100%
services\batch_inspector.py          72      8     16      7    83%
services\brand_profiler.py           60      1     30      1    98%
services\cache_service.py            34      2      6      1    92%
services\db_maintenance.py           63     12     12      5    77%
services\domain_utils.py             40      4     14      2    89%
services\heuristic_engine.py         59      9     16      2    85%
services\mitre_mapper.py              9      0      2      0   100%
services\mule_scanner.py             69      4     32      5    91%
services\multi_vector_scorer.py      35      3      8      1    91%
services\nlp_engine.py               58     26      6      0    56%
services\nsrc_bridge.py              37     12      8      1    62%
services\playbook_engine.py          53     18     10      3    60%
services\qr_scanner.py               61      5     30      5    87%
services\quishing_scanner.py         66      8     24      8    82%
services\red_team_simulator.py       24      3      2      1    85%
services\sanitizer.py                19      2      4      0    91%
services\siem_exporter.py            60      4     18      0    95%
services\ssl_analyzer.py             50     19      8      2    60%
services\stix_exporter.py            31      4      4      1    86%
services\threat_feed_sync.py         29      4      8      1    76%
services\typosquat_engine.py         36      2     16      1    94%
services\verdict_engine.py           76      3     26      2    95%
services\visual_detector.py         151     82     56      4    44%
services\visual_sandbox.py           43     21     24      1    37%
services\webhook_notifier.py         47     33     12      2    27%
services\xai_engine.py               48      5     26      3    89%
services\yara_generator.py           24      0     12      2    94%
-------------------------------------------------------------------
TOTAL                              2788    542    668    105    77%
=== 198 passed, 3 warnings in 12.76s ===
```

## Appendix D: Evaluation Harness Output (Malaysian Benchmark and Load Test)

D.1 reproduces the summary written by python -m evaluation.evaluate_pipeline --tag final_v3.2.0, which runs the real fine-tuned model over the 120-page Malaysian benchmark. D.2 lists the aggregate rows of the three Locust runs from evaluation/results/locust/.

**D.1 Benchmark summary (evaluation/results/final_v3.2.0/summary.md)**

```
# Malaysian benchmark results — `final_v3.2.0` (v3.2.0)

Samples: 120 (60 malicious, 60 legitimate). Device: cpu. BERT threshold: 0.75. BERT signal in pipeline: enabled.

## Pipeline verdict (BLOCK_RENDER vs SAFE)

| Split | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| overall | 120 | 57 | 0 | 3 | 60 | 0.9750 | 1.0000 | 0.9500 | 0.9744 | 0.0000 |
| dev | 60 | 28 | 0 | 2 | 30 | 0.9667 | 1.0000 | 0.9333 | 0.9655 | 0.0000 |
| holdout | 60 | 29 | 0 | 1 | 30 | 0.9833 | 1.0000 | 0.9667 | 0.9831 | 0.0000 |

## Pipeline accuracy per category

| Category | n | Correct | Blocked | Accuracy |
|---|---|---|---|---|
| L1_official_portal | 14 | 14 | 0 | 1.0000 |
| L2_benign_brand_mention | 20 | 20 | 0 | 1.0000 |
| L3_general_benign | 14 | 14 | 0 | 1.0000 |
| L4_benign_with_accounts | 12 | 12 | 0 | 1.0000 |
| P1_bank_lookalike | 14 | 14 | 14 | 1.0000 |
| P2_bm_manglish_lure | 14 | 14 | 14 | 1.0000 |
| P3_mule_account | 12 | 12 | 12 | 1.0000 |
| P4_ewallet_brand | 10 | 10 | 10 | 1.0000 |
| P5_evasive | 10 | 7 | 7 | 0.7000 |

## Rule that produced each BLOCK_RENDER

| Rule | Pages blocked |
|---|---|
| R1_MULE_REGISTRY | 12 |
| R2_BRAND_IN_HOSTNAME | 29 |
| R3_LOOKALIKE_DOMAIN | 5 |
| R4_BRAND_CLONE | 7 |
| R5_COERCIVE_CREDENTIAL_REQUEST | 2 |
| R6_EVASIVE_INFRASTRUCTURE | 2 |

## BERT-only (no rule layer)

| Input formulation | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| composite | 0.5000 | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 0.7037 |
| url_raw | 0.5333 | 0.5185 | 0.9333 | 0.6667 | 0.8667 | 0.7596 |
| url_stripped | 0.7250 | 0.6709 | 0.8833 | 0.7626 | 0.4333 | 0.8599 |

## In-process latency (ms)

- All requests: mean 91.8, p50 104.4, p95 114.12, max 177.64
- BERT path (n=102): mean 107.95, p50 104.99, p95 115.01
- Whitelist bypass (n=18): mean 0.28

## Misclassified samples (3)

- MY-116 (P5_evasive, false negative): https://docs.google.com/forms/d/e/1FAIpQLSfakeformid/viewform
- MY-117 (P5_evasive, false negative): http://form-submit-online.site/m2u
- MY-119 (P5_evasive, false negative): https://smart-invest-daily.com/join
```
**D.2 Locust aggregate statistics**

```
run                      requests  failures  median_ms  avg_ms   p95_ms  p99_ms  max_ms  req/s
run_50u                      1333         0         13    79.5     370     490     600  22.39
run_200u                     2418         0         96  2298.1   11000   12000   12266  40.40
run_50u_default_limit        1014       646          3    11.4      17     230     584  23.04
```

## Appendix E: Threat Intelligence Monitoring Dashboard

The following architectural layout and telemetry schema document the Single-Page Application (SPA) monitoring dashboard served at /dashboard/.

*[Figure: see the Word report]*

## Appendix F: Reproducing the Results

Every figure and table in Chapter 5 can be regenerated from the repository (https://github.com/KunTheNoobie/PhishGuard-AI-Complete) with the commands below, run from the repository root inside the project's virtual environment. Result files are written to evaluation/results/ and figures to report/figures/.

```
python -m pytest --cov --cov-report=term                                   # 198 tests, coverage
python -m evaluation.build_dataset                                         # writes the 120-page benchmark
python -m evaluation.evaluate_pipeline --tag final_v3.2.0                  # pipeline + BERT-only metrics, ROC
python -m evaluation.evaluate_pipeline --tag ablation_no_bert_v3.2.0 --no-bert
python -m evaluation.kaggle_holdout_metrics                                # hold-out confusion matrix
python -m evaluation.make_report_figures                                   # report/figures/*.png

# load test (server in one terminal, Locust in another)
set PHISHGUARD_RATE_LIMIT=1000000/minute
python -m uvicorn main:app --host 127.0.0.1 --port 8765
python -m locust -f tests/locustfile.py --host http://127.0.0.1:8765 --headless -u 50 -r 5 -t 60s --csv evaluation/results/locust/run_50u
```
