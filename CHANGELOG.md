# Changelog

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
