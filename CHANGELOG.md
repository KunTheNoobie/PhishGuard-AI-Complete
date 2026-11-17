# Changelog

## v4.1.1 — 17 November 2026

- **Hosting moved to Render** (`https://phishguard-ai-backend.onrender.com`): `render.yaml` (free Docker web service), a new
  `Dockerfile` (CPU PyTorch, `libzbar0`, `libgl1`, LFS-pointer download step, int8 BERT build). Hugging Face Space files
  (`app.py`, `packages.txt`, `deploy/`) removed. The extension defaults to the Render URL with the local server as fallback.
- **Memory** — BERT served as an int8 TorchScript model (`scripts/quantize_bert.py`) on one thread under
  `torch.inference_mode()`, heap trimmed after loading; `evaluation/measure_memory.py` reports peak RAM.

## v4.1.0 — 17 November 2026

- **Dashboard and /docs** share one dark-slate design (palette, type, radii, elevation); `/docs` is Swagger re-skinned to match.
  Verdict filter restyled, no scrollbars (ten scans per page with Previous/Next), automatic refresh every 5 seconds with a
  "Live • Auto-Refresh" pill (click to pause).
- **QR Scanner** — payload-type badge (URL, DuitNow / EMVCo Merchant QR, Plain Text), raw payload box, "Try a sample QR" button.
- **URL Analyzer** — Quick Demo Presets (safe HTTPS, insecure HTTP, @-spoof, mule-account text) and a confidence bar per layer.
- **Mule Registry** — the "Reported via" box is empty with a placeholder instead of a pre-filled value.
- **Extension** — green "Verified Safe" corner notice (3.5 s) with a switch in the popup settings (`showSafeToast`,
  `chrome.storage.local`); popup resized to fit without a scrollbar; settings moved to their own view; pages are re-scanned
  when a single-page site changes address.
- **Demonstration dataset** — `database/demo_threat_intel.json` loads into an empty database (45 mule records, 30 scan rows built
  from real pipeline verdicts incl. OpenPhish feed URLs, 4 pending reports). `PHISHGUARD_SEED_DEMO=false` disables it;
  `python -m evaluation.build_demo_seed` rebuilds it.
- **Hugging Face Space** — Gradio-SDK entry point `app.py` (status card at `/hf`), `packages.txt`, Space card
  `deploy/hf_space_README.txt`, token-safe `deploy/deploy_hf_space.ps1`; `Content-Security-Policy: frame-ancestors` replaces
  `X-Frame-Options` so the Space page can embed the app; CPU PyTorch wheels via `requirements.txt`.
- **`setup.bat`** — one-click Git LFS pull, virtual environment, dependencies and `.env`.
- 138 tests pass (82% coverage); report chapters, figures and screenshots refreshed.

## v4.0.0 — 17 November 2026

A ground-up overhaul: protection for every website, explained verdicts, a strict HTTP/HTTPS policy, a new
dashboard and extension, and online HTTPS hosting.

### Detection
- **Web-wide protection** — the extension scans every `http://` and `https://` page; real BERT, page and logo
  analysis run on every non-trusted URL.
- **Single pipeline** — `services/analysis_pipeline.py` serves the extension, the dashboard analyzer and the QR
  scanner, so all three give the same answer.
- **URL canonicalisation** (`services/url_canonicalizer.py`) — userinfo, IDN/punycode, Unicode confusables,
  integer/hex/octal IPs, backslashes, case and default ports.
- **`@` spoofing fixed** — `https://maybank2u.com.my@evil-login.top` is blocked by the new rule R7 even without a
  password form.
- **Spaced and hyphenated mule accounts fixed** — `5142 7610 3388`, `5142-7610-3388` and `+60` forms are extracted;
  card numbers (Luhn) and amounts are ignored. Registry keys are stored as compact digits.
- **HTTP vs HTTPS** — HTTPS with no signals is `SAFE`; plain HTTP is a `WARNING` (H2); plain HTTP with a password,
  card or other sensitive form is `BLOCK_RENDER` (H1); certificate errors are a `WARNING` (W1).
- **New rules** — R8 bank logo on a foreign domain, R9 credential form on free hosting with corroboration, W2
  uncorroborated impersonation, W3 form on free hosting.
- **Brand registry** (`core/brands.py`) — 49 organisations and 110 official domains: every licensed Malaysian bank
  and digital bank, e-wallets and payment networks, and major global banks.
- **Explanations** — every response has a headline, a plain-language explanation, ordered reasons and the pipeline
  steps.
- **Safe page fetcher** — the dashboard and QR scanner download pages through an SSRF-safe fetcher.

### Interface
- **Dashboard rebuilt** with four tabs backed only by real data: Overview (scan counters, scan log, CSV/JSON
  export), Mule Registry (review queue and registry), QR Scanner and URL Analyzer.
- Removed: `sandbox.html`, `test_scam.html`, simulated threat feeds, radar, war room, automation, system monitor,
  demo mode, audio alerts, keyboard palette, the synthetic 24-hour baseline and the theme switcher.
- **Extension rebuilt** — dark-slate popup with server selection (automatic / online / local), Shadow-DOM block page
  and amber "Not secure" banner; online-first with local fallback.
- `/docs` is a clean Swagger page linking only to the Dashboard and the API docs.

### Platform
- `scan_log` replaces `threat_telemetry`; query strings are never stored.
- Dashboard API reduced to 13 operations; public API to `/analyze`, `/analyze/qr`, `/mule-reports` and `/health`.
- Removed unused services (STIX, SIEM, YARA, MITRE, NSRC bridge, webhooks, red-team simulator, typosquat engine and
  others) and their tests.
- Demonstration API and admin key is now `12345678` (replace it in any real deployment).
- `Dockerfile` and `deploy/deploy_hf_space.ps1` for HTTPS hosting on Hugging Face Spaces.
- `requirements.txt` holds runtime packages only; test and evaluation tools are in `requirements-dev.txt`.

### Evaluation
- 136 tests pass (81% coverage).
- Malaysian benchmark: 57/60 scams blocked, 0 false positives, F1 0.974, ROC-AUC 0.983.
- New `evaluation/compare_baselines.py` (padlock, lexical, BERT alone) and `evaluation/run_public_suite.py` (30 public
  URLs; 28 passed, two hosts unreachable from the test network).
- Report Chapters 1–6, diagrams and screenshots updated for v4.0.

## Cyber Neon restored — 17 November 2026

- **Dashboard** — `dashboard/apple.css` and the "Apple Light" option removed; Cyber Neon is the default theme again
  (Matrix Emerald and OLED Abyss stay selectable). The mule-report review queue and every other v3.2.0 feature are kept.
- **No overlapping controls** — the header toolbar wraps onto a second row instead of running off-screen at laptop
  widths; the **Sign out** control now sits in the toolbar rather than floating over page content; the review-queue
  hint has proper padding.
- **Extension popup** — the light layer is removed and the dark Cyber Neon styling restored; the missing
  `.status-pill.dangerous` style is added so the DANGEROUS badge renders as a red pill.
- **Block overlay** — dark Cyber Neon card (red border, slate background) keeping the multi-vector breakdown
  (verdict and rule, BERT probability, Semakmule registry, brand / visual check, risk score) and the **Report to SOC**
  button; badges and rows wrap so long values never overlap. Fetch timeouts are unchanged (8 s semantic, 12 s visual).
- **Report** — the seven UI figures were retaken live in Cyber Neon and the interface-design text and Table 4.8 updated.

## Apple-style interface — 17 November 2026

- **Dashboard** — new default theme `dashboard/apple.css` ("Apple Light"): #F5F5F7 surface, translucent white cards,
  system typography, 12–16 px radii, hairline borders, pill badges. The previous dark themes remain selectable.
- **Extension popup** — same light design language (`chrome_extension/popup/popup.css`); gauge colours use Apple
  system colours.
- **Block overlay** — redesigned card listing the verdict and rule, BERT probability, Semakmule registry result,
  brand / visual check and risk score; all dynamic values are HTML-escaped. New **Report to SOC** button sends the
  account to the review queue through a new `PHISHGUARD_REPORT_MULE` service-worker message.
- No API, authentication or schema change; 198 tests pass.

## Report figures and dashboard review queue — 17 November 2026

- **draw.io diagrams** — every architecture, UML, ERD, sequence, activity, deployment and workflow diagram of the
  dissertation is now a native draw.io file in `report/diagrams_drawio/` (21 diagrams), exported at 300 DPI.
  `evaluation/figures_diagrams.py` (matplotlib box diagrams) was removed; `evaluation/make_report_figures.py` now
  produces only the quantitative charts, restyled to the draw.io palette.
- **Live screenshots** — extension popup (SAFE and DANGEROUS), the BLOCK_RENDER interstitial, the authenticated SOC
  dashboard, the review queue, the quishing scanner, STIX/CEF exports and `/docs`, captured from the running service.
- **Dashboard: mule-report review queue** — new panel above the mule registry lists user reports by status with
  Approve / Reject actions, using the existing `GET /api/v1/dashboard/mule-reports` and
  `POST /api/v1/dashboard/mule-reports/{id}/review` endpoints. Previously the queue was reachable only through the API.
- Unused asset `dashboard/logo.png` removed earlier in this cycle; no other change to service behaviour.

## Documentation and report figures — 16 November 2026

No change to the behaviour of the service.

- **Figure generator** — `evaluation/figkit.py`, `evaluation/figures_diagrams.py` (since replaced by draw.io
  sources) and a rewritten `evaluation/make_report_figures.py` produced all 30 report figures (architecture, ERD, sequence, activity,
  use-case, class, security layers, deployment, methodology, threat model, evaluation charts) at 300 DPI
  from measured results. `evaluation/benchmark_components.py` measures per-detector latency and F1.
- **Removed** the PlantUML sources (`report/diagrams/`), the Markdown chapter exports under `report/`,
  the legacy image `report/image55_master.png`, the superseded `fig_*.png` charts and the outdated
  ad-hoc script `tests/validate_live.py`. The dissertation is maintained only as the Word document.
- `evaluation/README.md` merged into `README.md`; benchmark summaries are written as `summary.txt`.

## v3.2.0 — 16 November 2026

Supervisor: Dr. Ng Yen Phing. Backend / AI core: Liew Yi Ler (Module 1).
Chrome extension / visual module: Cheon Jie Han (Module 2).

### Why this release exists

A labelled benchmark of 120 Malaysian pages (`evaluation/`) was run against v3.0.0 with the
real BERT model. It blocked **47 of 60 legitimate pages** (false-positive rate 78 %). Root
causes: the BERT model is a *URL* classifier but was being fed page text; a brand name
anywhere in page text counted as impersonation; and credential keywords were matched as
substrings ("pin" in "shopping"). v3.2.0 fixes the decision logic and hardens the API.
On the same benchmark v3.2.0 scores 97.5 % accuracy with 0 false positives
(see the *Evaluation artefacts* section of `README.md` for the full method and caveats).

### Detection logic

- **New `services/verdict_engine.py`** — one corroboration engine used by both
  `/api/v1/analyze/semantics` and the dashboard quick-scan. No probabilistic signal blocks
  alone; rules R1–R6 require independent signals to agree. A mule-registry match (R1) is the
  only single-signal block.
- **BERT input aligned with training data** — the model now receives the scheme-stripped
  URL (`services/nlp_engine.build_model_input`), not `URL + page text`.
- **`services/brand_profiler.py` rewritten** — three evidence tiers: brand string in a
  foreign hostname, look-alike domain (homoglyph / edit distance), and text-only mention.
  A text mention is never impersonation on its own. Added GrabPay, ShopeePay, Boost, BSN and
  government / utility brands (LHDN, KWSP, PDRM, JPJ, BNM, TNB, Pos Malaysia).
- **Credential detection** — word-boundary regexes with request context for short tokens
  (TAC / OTP / PIN / PAC), plus detection of real `<input type="password">` / OTP / card
  fields in the DOM.
- **`services/heuristic_engine.py`** — subdomain depth is measured from the registrable
  domain, so `www.maybank2u.com.my` is no longer "excessively nested".
- **Whitelist** — added missing official hosts (`amonline.com.my`, `bankislam.biz`,
  `irakyat.com.my`, `mybsn.com.my`, `cimb.com`); removed shared-hosting suffixes
  (`web.app`, `firebaseapp.com`, `vercel.app`, `netlify.app`, `myshopify.com`,
  `wordpress.com`) under which anyone can publish.
- **Registry poisoning removed** — accounts merely displayed on a blocked page are no longer
  auto-inserted into `mule_registry`.

### Bug fixes

- `multi_vector_scorer.py` read keys the brand profiler never returned
  (`impersonation_detected`, `matched_brand`); the brand vector was a constant 1.0 / 10.
- `nlp_engine.predict_phishing_probability` read keys the heuristic engine never returned;
  it always fell back to 0.15 and used substring keyword matching.
- `repository.log_threat_telemetry` wrapped a synchronous function in
  `asyncio.create_task`, raising a swallowed `TypeError`, and each threat was broadcast twice.
- `dashboard/app.js` declared `initSseStream()` twice; the later declaration replaced the
  real one and subscribed to a non-existent `/telemetry/stream`, so the live feed never
  connected.

### Security

- **Dashboard authentication** — every `/api/v1/dashboard/*` route (62 previously open
  routes, including registry deletion and database backup) now requires the admin key as a
  bearer token or a server-side session (`POST /auth/login`, HttpOnly + SameSite=Strict
  cookie). New optional `PHISHGUARD_ADMIN_KEY`. Login is rate-limited to 5/minute per IP.
- **CORS** — explicit origin list plus `chrome-extension://` regex; no wildcard and
  `allow_credentials=False`.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`; `Cache-Control: no-store` on API responses.
- **`.env` is now actually loaded** (`python-dotenv`); a start-up warning is logged while the
  public development key is in use.
- **Rate limit** — one shared limiter (`core/rate_limit.py`); default unified to `60/minute`
  in code, `.env.example` and documentation.
- **New mule-report queue** — `POST /api/v1/mule-reports` (API key) stores a `PENDING`
  report in the new `mule_reports` table (foreign key to `mule_registry`); an analyst
  approves or rejects it via `/api/v1/dashboard/mule-reports/{id}/review`.

### Chrome extension — notes for Cheon Jie Han (Module 2)

These edits touch your module; please review them before the next demo.

| File | Change | Why |
|---|---|---|
| `manifest.json` | `version` → `3.2.0`; added explicit `content_security_policy.extension_pages` | Makes the MV3 policy explicit: scripts from the package only, no objects, no framing, `connect-src` limited to localhost and HTTPS backends. Inline `style` attributes are still allowed because the popup uses them. **A remote backend must now be served over HTTPS.** |
| `background/service-worker.js` | New `fetchWithTimeout()` (AbortController); semantic call times out at 8 s, visual call at 12 s | A stalled backend previously left the tab waiting indefinitely. On timeout the existing offline-heuristics fallback runs. |
| `background/service-worker.js` | Block reason now uses the backend's `threat_indicators` when present | Shows the user *why* a page was blocked instead of a bare BERT percentage. |
| `background/service-worker.js` | `OFFICIAL_BANK_DOMAINS`: added `amonline.com.my`, `bankislam.com`, BSN | Keeps the client list consistent with the backend whitelist. |
| `popup/popup.js` | "Escalate to NSRC" now calls `POST /api/v1/mule-reports` with the `Authorization` header | The old call posted to a GET-only route without a token, always failed, and still told the user the report was "Recorded Locally". Messages now state the real outcome. |
| `popup/popup.js` | `/health` ping and report call use a timeout | Popup no longer hangs when the backend is down. |

Not changed (suggested follow-ups in your module): `evaluateOfflineHeuristics()` still uses
substring keyword matching (`"tac"`, `"otp"`); `DEFAULT_API_TOKEN` is still embedded in the
service worker and popup; `host_permissions` is still `<all_urls>`.

**Backend response additions the extension can use:** `threat_indicators` (list of strings),
`decision_rule` (`R1_MULE_REGISTRY` … `R6_EVASIVE_INFRASTRUCTURE` or `null`), `signals`
(boolean map). `risk_score` is now the rule severity (0.90–0.99) or an advisory value
below 0.50 when the page is SAFE. Existing fields are unchanged.

**Behaviour change to expect in demos:** a page is no longer blocked just because BERT flags
it or because it mentions a bank. To trigger `BLOCK_RENDER`, a demo page needs corroboration
— for example a brand string in the hostname plus a password field, or a registry account.
The five sandbox scenarios and the dashboard demo samples were re-tested and still block.

### Tests and evaluation

- 198 tests (was 122): new `test_verdict_engine.py`, `test_security.py`,
  `test_mule_reports.py`; `pytest-cov` reports 77 % statement + branch coverage.
- New `evaluation/` package: benchmark builder, pipeline evaluation with ablation,
  Kaggle hold-out confusion-matrix reconstruction, and the Locust result CSVs.
