/*
 * PhishGuard-AI SOC Dashboard.
 *
 * Four tabs, each backed by /api/v1/dashboard routes (api/dashboard_endpoints.py):
 *   Overview       GET /overview, GET /scans, GET /scans/export
 *   Mule Registry  GET/POST /mules, DELETE /mules/{id}, GET /mule-reports, POST /mule-reports/{id}/review
 *   QR Scanner     POST /qr-scan
 *   URL Analyzer   POST /analyze
 *
 * Every value from the server is inserted with textContent (never innerHTML),
 * so a malicious URL or page title cannot inject script into the dashboard.
 */
"use strict";

const API = "/api/v1/dashboard";
const VERDICT_CLASS = { SAFE: "safe", WARNING: "warning", BLOCK_RENDER: "dangerous", UNKNOWN: "neutral" };
const VERDICT_LABEL = { SAFE: "Safe", WARNING: "Warning", BLOCK_RENDER: "Blocked", UNKNOWN: "Unknown" };
const BANKS = ["Maybank", "CIMB Bank", "Public Bank", "RHB Bank", "Hong Leong Bank", "AmBank", "Bank Islam",
  "Bank Rakyat", "BSN", "Alliance Bank", "Affin Bank", "UOB Malaysia", "OCBC Malaysia", "HSBC Malaysia",
  "Standard Chartered Malaysia", "Citibank Malaysia", "Agrobank", "Bank Muamalat", "MBSB Bank", "GXBank",
  "AEON Bank", "Boost Bank", "KAF Digital Bank", "Touch 'n Go eWallet", "DuitNow phone", "DuitNow ID (NRIC)"];
const EXAMPLES = ["https://example.com", "https://www.maybank2u.com.my", "https://www.cimbclicks.com.my",
  "http://neverssl.com", "http://httpforever.com", "http://testphp.vulnweb.com/login.php",
  "https://testsafebrowsing.appspot.com/s/phishing.html", "https://maybank2u.com.my@evil-login.top/login"];

const $ = (id) => document.getElementById(id);

/* ── Small DOM helper: el("td", {className: "x"}, "text", childNode) ── */
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  Object.entries(props || {}).forEach(([k, v]) => {
    if (k === "dataset") Object.assign(node.dataset, v);
    else if (k in node) node[k] = v;
    else node.setAttribute(k, v);
  });
  children.flat().forEach((c) => node.append(c instanceof Node ? c : document.createTextNode(c == null ? "" : String(c))));
  return node;
}

function toast(message, isError) {
  const t = $("toast");
  t.textContent = message;
  t.className = "toast" + (isError ? " error" : "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 3500);
}

function when(iso) {
  if (!iso) return "";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function pill(verdict, text) {
  return el("span", { className: "pill " + (VERDICT_CLASS[verdict] || "neutral") }, text || VERDICT_LABEL[verdict] || verdict);
}

/* ── API wrapper: same-origin session cookie; 401 opens the sign-in gate ── */
async function api(path, options = {}) {
  const res = await fetch(API + path, {
    credentials: "same-origin",
    headers: options.body ? { "Content-Type": "application/json" } : {},
    ...options,
  });
  if (res.status === 401) { showGate(); throw new Error("Please sign in."); }
  if (res.ok) markOnline();
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data.detail;
    const msg = (detail && (detail.message || (Array.isArray(detail) && detail[0] && detail[0].msg))) || `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

/* ── Sign-in gate ── */
function showGate() { $("gate").classList.remove("hidden"); $("gateKey").focus(); }
$("gateForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("gateError").textContent = "";
  try {
    await api("/auth/login", { method: "POST", body: JSON.stringify({ api_key: $("gateKey").value }) });
    $("gate").classList.add("hidden");
    $("gateKey").value = "";
    start();
  } catch (err) { $("gateError").textContent = err.message; }
});
$("signOut").addEventListener("click", async () => {
  await fetch(API + "/auth/logout", { method: "POST", credentials: "same-origin" });
  showGate();
});

/* ── Tabs ── */
function switchTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll("[role=tabpanel]").forEach((p) => p.classList.toggle("hidden", p.id !== "tab-" + name));
  try { localStorage.setItem("pg_tab", name); } catch (_e) { /* storage unavailable */ }
  if (name === "overview") loadOverview();
  if (name === "registry") { loadReports(); loadRegistry(); }
}
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

/* ── Health indicator: "Online" whenever any call succeeded recently, so a slow scan never shows a false offline badge ── */
let lastOk = 0;
function markOnline() {
  lastOk = Date.now();
  $("healthDot").className = "status-dot ok";
  if ($("healthText").textContent === "Connecting…" || $("healthText").textContent === "Backend unreachable") $("healthText").textContent = "Online";
}
async function loadHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const h = await (await fetch("/health", { signal: controller.signal })).json();
    const m = h.models || {};
    markOnline();
    $("healthText").textContent = `Online · v${h.version} · BERT ${m.bert_url_classifier ? "on" : "off"} · YOLO ${m.yolov8n_logo_detector ? "on" : "off"}`;
  } catch (_e) {
    if (Date.now() - lastOk > 60000) {   // no successful call for a minute: now it is really offline
      $("healthDot").className = "status-dot";
      $("healthText").textContent = "Backend unreachable";
    }
  } finally { clearTimeout(timer); }
}

/* ══ Tab 1 — Overview ══ */
function renderScans(rows) {
  const body = $("scanRows");
  body.replaceChildren();
  if (!rows.length) {
    body.append(el("tr", {}, el("td", { colSpan: 7, className: "empty" }, "No scans yet. Browse with the extension, or use the URL Analyzer or QR Scanner.")));
    return;
  }
  rows.forEach((r) => body.append(el("tr", {},
    el("td", { className: "nowrap muted" }, when(r.created_at)),
    el("td", {}, pill(r.verdict)),
    el("td", { className: "url mono", title: r.url }, r.url),
    el("td", { className: "mono muted" }, r.rule || "—"),
    el("td", { className: "nowrap" }, Number(r.risk_score).toFixed(2)),
    el("td", { className: "nowrap muted" }, r.bert_score == null ? "skipped" : Number(r.bert_score).toFixed(2)),
    el("td", { className: "muted" }, r.source),
  )));
}

const scans = { offset: 0, limit: 10, live: true };

async function loadOverview() {
  try {
    const filter = $("scanFilter").value;
    const data = await api("/overview?recent=1");
    const s = data.stats;
    $("statTotal").textContent = s.total_scans.toLocaleString();
    $("stat24h").textContent = `${s.last_24h.toLocaleString()} in the last 24 hours`;
    $("statBlocked").textContent = s.blocked.toLocaleString();
    $("statHttp").textContent = s.http_warnings.toLocaleString();
    $("statWarnAll").textContent = `${s.warnings.toLocaleString()} warnings in total`;
    $("statSafe").textContent = s.safe.toLocaleString();
    $("statRegistry").textContent = s.registry_accounts;
    $("statPending").textContent = s.pending_reports;
    const q = filter ? `&verdict=${encodeURIComponent(filter)}` : "";
    const rows = (await api(`/scans?limit=${scans.limit + 1}&offset=${scans.offset}${q}`)).items;
    const more = rows.length > scans.limit;
    renderScans(rows.slice(0, scans.limit));
    $("scanCount").textContent = rows.length ? `Scans ${scans.offset + 1}–${scans.offset + Math.min(rows.length, scans.limit)}` : "";
    $("scanPrev").disabled = scans.offset === 0;
    $("scanNext").disabled = !more;
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (err) { if (err.message !== "Please sign in.") toast(err.message, true); }
}
$("scanPrev").addEventListener("click", () => { scans.offset = Math.max(0, scans.offset - scans.limit); loadOverview(); });
$("scanNext").addEventListener("click", () => { scans.offset += scans.limit; loadOverview(); });
$("live").addEventListener("click", () => {
  scans.live = !scans.live;
  $("live").classList.toggle("off", !scans.live);
  $("liveText").textContent = scans.live ? "Live • Auto-Refresh" : "Paused";
});
$("scanFilter").addEventListener("change", () => {
  const v = $("scanFilter").value;
  const q = v ? `&verdict=${encodeURIComponent(v)}` : "";
  $("exportCsv").href = `${API}/scans/export?format=csv${q}`;
  $("exportJson").href = `${API}/scans/export?format=json${q}`;
  scans.offset = 0;
  loadOverview();
});

/* ══ Tab 2 — Mule registry and review queue ══ */
const registry = { offset: 0, limit: 15, total: 0 };

async function loadReports() {
  const body = $("reportRows");
  try {
    const data = await api(`/mule-reports?status=${encodeURIComponent($("reportStatus").value)}`);
    body.replaceChildren();
    if (!data.reports.length) {
      body.append(el("tr", {}, el("td", { colSpan: 7, className: "empty" }, "No reports in this list.")));
      return;
    }
    data.reports.forEach((r) => {
      const action = r.status === "PENDING"
        ? el("div", { className: "actions" },
            el("button", { className: "btn small approve", type: "button", onclick: () => review(r.report_id, "APPROVE") }, "Approve"),
            el("button", { className: "btn small reject", type: "button", onclick: () => review(r.report_id, "REJECT") }, "Reject"))
        : el("span", { className: "muted" }, r.reviewed_at ? "Reviewed " + when(r.reviewed_at) : "");
      body.append(el("tr", {},
        el("td", { className: "muted" }, r.report_id),
        el("td", { className: "mono" }, r.account_number),
        el("td", {}, r.bank_name),
        el("td", { className: "url mono", title: r.page_url || "" }, r.page_url || "—"),
        el("td", { className: "nowrap muted" }, when(r.created_at)),
        el("td", {}, el("span", { className: "pill " + r.status.toLowerCase() }, r.status)),
        el("td", {}, action)));
    });
  } catch (err) { toast(err.message, true); }
}

async function review(id, decision) {
  try {
    await api(`/mule-reports/${id}/review`, { method: "POST", body: JSON.stringify({ decision }) });
    toast(decision === "APPROVE" ? "Approved: the account is now in the registry." : "Report rejected.");
    loadReports(); loadRegistry();
  } catch (err) { toast(err.message, true); }
}
$("reportStatus").addEventListener("change", loadReports);

async function loadRegistry() {
  const body = $("registryRows");
  try {
    const q = encodeURIComponent($("registrySearch").value.trim());
    const data = await api(`/mules?search=${q}&limit=${registry.limit}&offset=${registry.offset}`);
    registry.total = data.total;
    $("registryTotal").textContent = `(${data.total})`;
    body.replaceChildren();
    if (!data.items.length) body.append(el("tr", {}, el("td", { colSpan: 6, className: "empty" }, "No matching accounts.")));
    data.items.forEach((m) => body.append(el("tr", {},
      el("td", { className: "mono" }, m.account_number),
      el("td", {}, m.bank_name),
      el("td", { className: "muted" }, m.platform_flagged),
      el("td", {}, m.report_count),
      el("td", { className: "nowrap muted" }, when(m.date_added)),
      el("td", {}, el("button", { className: "btn small delete", type: "button", onclick: () => removeMule(m) }, "Delete")))));
    const end = Math.min(registry.offset + registry.limit, data.total);
    $("registryPage").textContent = data.total ? `${registry.offset + 1}–${end} of ${data.total}` : "";
    $("regPrev").disabled = registry.offset === 0;
    $("regNext").disabled = end >= data.total;
  } catch (err) { toast(err.message, true); }
}

async function removeMule(m) {
  if (!confirm(`Remove ${m.account_number} (${m.bank_name}) from the registry? Pages showing it will no longer be blocked.`)) return;
  try { await api(`/mules/${m.id}`, { method: "DELETE" }); toast("Account removed."); loadRegistry(); }
  catch (err) { toast(err.message, true); }
}

let searchTimer;
$("registrySearch").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { registry.offset = 0; loadRegistry(); }, 250);
});
$("regPrev").addEventListener("click", () => { registry.offset = Math.max(0, registry.offset - registry.limit); loadRegistry(); });
$("regNext").addEventListener("click", () => { registry.offset += registry.limit; loadRegistry(); });
$("addMule").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const rec = await api("/mules", { method: "POST", body: JSON.stringify({
      account_number: $("muleAccount").value.trim(), bank_name: $("muleBank").value.trim(),
      platform_flagged: $("mulePlatform").value.trim() || "Manual entry" }) });
    toast(`Added ${rec.account_number} to the registry.`);
    $("muleAccount").value = "";
    registry.offset = 0; loadRegistry();
  } catch (err) { toast(err.message, true); }
});

/* ══ Shared verdict renderer (Tabs 3 and 4) ══ */
function renderResult(r) {
  const level = r.risk_level;
  const color = { safe: "var(--safe)", warning: "var(--warn)", dangerous: "var(--danger)" }[level];
  const meter = el("div", { className: "meter" }, el("span", {}));
  meter.firstChild.style.width = Math.round(r.risk_score * 100) + "%";
  meter.firstChild.style.background = color;

  const reasons = el("ul", { className: "reasons" },
    r.reasons.map((x) => el("li", {}, el("span", { className: "ic " + x.severity }), el("span", {}, x.text))));
  const steps = el("ol", { className: "steps" },
    r.steps.map((s) => el("li", {},
      el("span", { className: "st " + s.status }, s.status),
      el("div", {}, el("div", { className: "nm" }, s.name + (s.ms != null ? `  · ${s.ms} ms` : "")),
        el("div", { className: "dt" }, s.detail)))));

  const bert = r.bert || {};
  const brand = r.brand || {};
  const mule = r.mule || {};
  const sensitive = (r.page && r.page.sensitive_fields) || [];
  const layers = [
    ["AI URL model (BERT)", bert.skipped ? 0 : bert.phishing_probability, bert.skipped ? "skipped (trusted site)" : Math.round((bert.phishing_probability || 0) * 100) + "% phishing"],
    ["Brand impersonation", brand.is_impersonation ? 0.85 : 0, brand.is_impersonation ? "imitates " + brand.target_brand : brand.is_official_domain ? "official " + brand.target_brand : "none found"],
    ["Mule-account registry", (mule.flagged_accounts || []).length ? 1 : 0, (mule.flagged_accounts || []).length ? "registry match" : (mule.accounts_extracted || []).length + " checked, clear"],
    ["Connection", r.scheme === "https" ? 0 : 0.55, r.scheme === "https" ? "HTTPS (encrypted)" : "HTTP (not encrypted)"],
    ["Password / card fields", sensitive.length ? (r.scheme === "https" ? 0.35 : 0.9) : 0, sensitive.length ? sensitive.join(", ") : "none"],
    ["Overall risk", r.risk_score, Math.round(r.risk_score * 100) + "%"],
  ];
  const tone = (v) => (v >= 0.7 ? "var(--danger)" : v >= 0.35 ? "var(--warn)" : "var(--safe)");
  const layerBox = el("div", { className: "layers" }, layers.map(([name, v, text]) => {
    const bar = el("div", { className: "bar" }, el("span", {}));
    bar.firstChild.style.width = Math.round((v || 0) * 100) + "%";
    bar.firstChild.style.background = tone(v || 0);
    return el("div", { className: "layer" }, el("div", { className: "top" }, el("b", {}, name), el("span", {}, text)), bar);
  }));

  return el("div", { className: "result" },
    el("div", { className: "result-head " + level },
      el("div", { className: "titles" },
        pill(r.verdict, r.verdict === "BLOCK_RENDER" ? "Dangerous — blocked" : r.verdict === "WARNING" ? "Warning — not secure" : "Safe"),
        el("h3", {}, r.headline),
        el("p", {}, r.explanation),
        el("p", { className: "mono", style: "margin-top:6px" }, r.final_url + (r.rule ? "   ·   rule " + r.rule : ""))),
      el("div", { className: "score" },
        el("div", { className: "num", style: `color:${color}` }, Math.round(r.risk_score * 100) + "%"),
        el("div", { className: "cap" }, `risk score · ${r.processing_time_ms} ms`), meter)),
    el("div", { className: "result-body" },
      el("section", {}, el("h4", {}, "Why"), reasons),
      el("section", {}, el("h4", {}, "Confidence by layer"), layerBox, el("h4", { style: "margin-top:18px" }, "Step-by-step pipeline"), steps)),
    el("details", { className: "raw" }, el("summary", {}, "Raw API response (JSON)"), el("pre", {}, JSON.stringify(r, null, 2))));
}

/* ══ Tab 3 — QR scanner ══ */
let qrData = null;
function loadQrFile(file) {
  if (!file) return;
  if (!file.type.startsWith("image/")) { toast("Please choose an image file.", true); return; }
  if (file.size > 8 * 1024 * 1024) { toast("Image is larger than 8 MB.", true); return; }
  const reader = new FileReader();
  reader.onload = () => {
    qrData = reader.result;
    $("qrPreview").src = qrData;
    $("qrPreview").classList.remove("hidden");
    $("qrScan").disabled = false;
  };
  reader.readAsDataURL(file);
}
$("qrFile").addEventListener("change", (e) => loadQrFile(e.target.files[0]));
["dragenter", "dragover"].forEach((ev) => $("qrDrop").addEventListener(ev, (e) => { e.preventDefault(); $("qrDrop").classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => $("qrDrop").addEventListener(ev, (e) => { e.preventDefault(); $("qrDrop").classList.remove("over"); }));
$("qrDrop").addEventListener("drop", (e) => loadQrFile(e.dataTransfer.files[0]));
$("qrClear").addEventListener("click", () => {
  qrData = null; $("qrFile").value = ""; $("qrPreview").classList.add("hidden"); $("qrScan").disabled = true;
  $("qrResult").replaceChildren();
  $("qrSummary").replaceChildren(el("h2", {}, "Decoded content"), el("p", { className: "sub" }, "The result appears here after a scan."));
});
$("qrSample").addEventListener("click", async () => {
  try {
    const blob = await (await fetch("sample_qr.png")).blob();
    loadQrFile(new File([blob], "sample_qr.png", { type: "image/png" }));
    toast("Sample QR loaded: it points to a look-alike banking address. Press Scan.");
  } catch (_e) { toast("Sample QR unavailable.", true); }
});
$("qrScan").addEventListener("click", async () => {
  if (!qrData) return;
  $("qrScan").disabled = true; $("qrScan").textContent = "Scanning…";
  try {
    const r = await api("/qr-scan", { method: "POST", body: JSON.stringify({ image_base64: qrData }) });
    const rows = [["Verdict", pill(r.verdict)], ["Summary", r.headline]];
    if (r.decoded) {
      rows.push(["Payload type", el("span", { className: "badge" }, { url: "URL", payment: "DuitNow / EMVCo Merchant QR", text: "Plain Text" }[r.payload_type])]);
      rows.push(["Raw payload", el("div", { className: "payload" }, r.payload)]);
      if (r.accounts.length) rows.push(["Accounts in code", r.accounts.map((a) => a.account_number).join(", ")]);
      if (r.flagged_accounts.length) rows.push(["Registry match", r.flagged_accounts.map((a) => `${a.account_number} (${a.bank_name})`).join(", ")]);
    } else {
      rows.push(["Problem", r.error || "No QR code found."]);
    }
    $("qrSummary").replaceChildren(el("h2", {}, "Decoded content"),
      el("dl", { className: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])));
    $("qrResult").replaceChildren(r.analysis ? renderResult(r.analysis) : "");
  } catch (err) { toast(err.message, true); }
  finally { $("qrScan").disabled = false; $("qrScan").textContent = "Scan QR code"; }
});

/* ══ Tab 4 — URL analyzer ══ */
const PRESETS = [
  ["Safe HTTPS (example.com)", { url: "https://example.com" }],
  ["Insecure HTTP (neverssl.com)", { url: "http://neverssl.com" }],
  ["@-Spoof Bank URL", { url: "https://maybank2u.com.my@evil-login.top/login", fetch: false }],
  ["Mule Account Text", { url: "https://parcel-customs-pay.top/", fetch: false, account: "1122 3344 5566",
    text: "Your parcel is held. Pay the RM2.50 customs fee now to account 1122 3344 5566 (Maybank) to release it." }],
];
PRESETS.forEach(([label, p]) => $("presets").append(el("button", { className: "chip", type: "button", onclick: () => {
  $("anUrl").value = p.url; $("anText").value = p.text || ""; $("anAccount").value = p.account || "";
  $("anFetch").checked = p.fetch !== false;
  $("anShot").value = "";
  $("analyzeForm").requestSubmit();
} }, label)));
EXAMPLES.forEach((u) => $("examples").append(el("button", { className: "chip", type: "button", onclick: () => { $("anUrl").value = u; } }, u.replace(/^https?:\/\//, ""))));
function readScreenshot() {
  const file = $("anShot").files[0];
  if (!file) return Promise.resolve(null);
  if (file.size > 6 * 1024 * 1024) return Promise.reject(new Error("Screenshot is larger than 6 MB."));
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);   // data URL: base64 image
    reader.onerror = () => reject(new Error("Could not read the screenshot."));
    reader.readAsDataURL(file);
  });
}
$("analyzeForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("anSubmit");
  btn.disabled = true; $("anStatus").textContent = "Fetching the page and running the models…";
  try {
    const screenshot_b64 = await readScreenshot();
    const r = await api("/analyze", { method: "POST", body: JSON.stringify({
      screenshot_b64,
      url: $("anUrl").value.trim(),
      page_text: $("anText").value.trim() || null,
      account_number: $("anAccount").value.trim() || null,
      fetch_page: $("anFetch").checked }) });
    $("anResult").replaceChildren(renderResult(r));
    $("anStatus").textContent = "";
  } catch (err) { $("anStatus").textContent = ""; toast(err.message, true); }
  finally { btn.disabled = false; }
});

/* ── Start-up ── */
BANKS.forEach((b) => $("bankList").append(el("option", { value: b })));
let refreshTimer;
let started = false;
async function start() {
  if (started) { loadHealth(); switchTab("overview"); return; }
  started = true;
  loadHealth();
  let tab = "overview";
  try { tab = localStorage.getItem("pg_tab") || "overview"; } catch (_e) { /* storage unavailable */ }
  switchTab(document.getElementById("tab-" + tab) ? tab : "overview");
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    if (scans.live && scans.offset === 0 && !$("tab-overview").classList.contains("hidden") && $("gate").classList.contains("hidden")) loadOverview();
  }, 5000);
  setInterval(loadHealth, 30000);
}

(async () => {
  try {
    const s = await (await fetch(API + "/auth/session", { credentials: "same-origin" })).json();
    if (s.authenticated) start(); else showGate();
  } catch (_e) { showGate(); }
})();
