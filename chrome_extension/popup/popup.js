/*
 * PhishGuard-AI popup: shows the verdict the service worker stored for the
 * active tab, and lets the user re-scan, report an account, open the
 * dashboard or change the backend.  All text is inserted with textContent.
 */
"use strict";

const $ = (id) => document.getElementById(id);
const LEVEL = { SAFE: "safe", WARNING: "warning", BLOCK_RENDER: "dangerous" };
const LABEL = { SAFE: "Safe", WARNING: "Warning — not secure", BLOCK_RENDER: "Dangerous — blocked", UNAVAILABLE: "Not analysed" };
const COLOR = { safe: "#22c55e", warning: "#f59e0b", dangerous: "#ef4444" };
let activeTab = null;
let current = null;
let backendUrl = null;
let ownHost = "";

function setCheck(id, text, tone) {
  const node = $(id);
  node.textContent = text;
  node.className = tone || "";
}

/** Fixed states shown instead of a verdict: scanning, own dashboard, browser pages. */
function renderState(pill, headline, text, level) {
  render(null);
  $("verdict").className = "verdict " + (level || "neutral");
  $("pill").className = "pill " + (level || "neutral");
  $("pill").textContent = pill;
  $("headline").textContent = headline;
  $("explain").textContent = text;
  $("host").textContent = activeTab && /^https?:/.test(activeTab.url || "") ? new URL(activeTab.url).hostname : "";
  document.querySelector(".checks").hidden = true;
  document.querySelector(".score").hidden = true;
}

function render(r) {
  current = r;
  document.querySelector(".checks").hidden = false;
  document.querySelector(".score").hidden = false;
  const level = r ? LEVEL[r.verdict] || "neutral" : "neutral";
  $("verdict").className = "verdict " + level;
  $("pill").className = "pill " + level;
  $("pill").textContent = r ? LABEL[r.verdict] || r.verdict : "Waiting";
  $("headline").textContent = r ? r.headline : "No result for this tab yet";
  $("host").textContent = r ? (r.hostname || "") + (r.rule ? "  ·  " + r.rule : "") + (r.allowed_by_user ? "  ·  allowed by you" : "") : "";
  $("explain").textContent = r ? r.explanation : "Open or reload a website, or press Re-scan.";
  const score = r ? Math.round((r.risk_score || 0) * 100) : 0;
  $("bar").style.width = score + "%";
  $("bar").style.background = COLOR[level] || "#475569";
  $("score").textContent = r && !r.offline ? `risk ${score}%` : "";

  if (!r || r.offline) {
    ["cBert", "cMule", "cBrand", "cLogo", "cForm"].forEach((id) => setCheck(id, "—"));
    setCheck("cConn", r && r.final_url ? (r.final_url.startsWith("https:") ? "HTTPS" : "HTTP (not encrypted)") : "—",
      r && r.final_url && !r.final_url.startsWith("https:") ? "warn" : "");
  } else {
    setCheck("cConn", r.scheme === "https" ? "HTTPS (encrypted)" : "HTTP (not encrypted)", r.scheme === "https" ? "good" : "warn");
    const b = r.bert || {};
    setCheck("cBert", b.skipped ? "skipped (trusted)" : `${Math.round((b.phishing_probability || 0) * 100)}% phishing`,
      b.skipped ? "" : b.is_malicious ? "bad" : "good");
    const m = r.mule || {};
    setCheck("cMule", (m.flagged_accounts || []).length ? `match: ${m.flagged_accounts[0].account_number}`
      : `${(m.accounts_extracted || []).length} checked, clear`, (m.flagged_accounts || []).length ? "bad" : "good");
    const br = r.brand || {};
    setCheck("cBrand", br.is_official_domain ? `official ${br.target_brand}` : br.is_impersonation ? `imitates ${br.target_brand}` : "none found",
      br.is_impersonation ? "bad" : "good");
    const v = r.visual;
    setCheck("cLogo", !v ? "no screenshot" : v.status !== "ok" ? v.status
      : (v.detected_logos || []).length ? `${v.detected_logos.map((d) => d.brand).join(", ")} (${v.risk_level})` : "no bank logo",
      v && v.status === "ok" && v.risk_level !== "safe" ? "bad" : "");
    const f = (r.page && r.page.sensitive_fields) || [];
    setCheck("cForm", f.length ? f.join(", ") : "none", f.length ? (r.scheme === "https" ? "warn" : "bad") : "good");
  }

  const list = $("reasons");
  list.replaceChildren();
  const items = r && r.reasons && r.reasons.length ? r.reasons.slice(0, 3) : [];
  $("reasonsBox").hidden = !items.length;
  items.forEach((x) => {
    const li = document.createElement("li");
    li.className = x.severity;
    const text = document.createElement("span");
    text.textContent = x.text;
    li.append(document.createElement("i"), text);
    list.append(li);
  });
  const accounts = r && r.mule ? [...(r.mule.flagged_accounts || []).map((a) => a.account_number), ...(r.mule.accounts_extracted || [])] : [];
  $("report").disabled = !activeTab || !/^https?:/.test(activeTab.url || "");
  $("report").title = accounts.length ? `Report ${accounts[0]}` : "Report an account shown on this page";
}

const INTERNAL = /^(chrome|opera|edge|brave|vivaldi|about|chrome-error|chrome-extension|devtools|view-source|file):/i;
let pollTimer = null;

function isOwnPage(url) {
  try {
    const u = new URL(url);
    return u.hostname === ownHost || ((u.hostname === "localhost" || u.hostname === "127.0.0.1") && u.port === "8000");
  } catch (_e) { return false; }
}

async function refresh(tries = 0) {
  clearTimeout(pollTimer);
  const url = (activeTab && activeTab.url) || "";
  if (!url || INTERNAL.test(url)) {
    renderState("Not scanned", "Browser internal / unreachable page (not scanned)",
      "PhishGuard checks websites that start with http:// or https://. Browser pages and error pages are not scanned.");
    return;
  }
  if (isOwnPage(url)) {
    renderState("Own Dashboard (Skipped)", "Own Dashboard (Skipped)", "This is PhishGuard's own dashboard, so it is not scanned.", "safe");
    $("backend").querySelector(".dot").className = "dot online";
    return;
  }
  const result = await chrome.runtime.sendMessage({ type: "PG_GET_RESULT", tabId: activeTab.id, url });
  if (result) { render(result); return; }
  renderState("Scanning…", "Scanning current page...", "The page is being checked. This takes a few seconds; the first check after a quiet period can take up to a minute.");
  if (tries < 40) pollTimer = setTimeout(() => refresh(tries + 1), 1500);
}

async function loadSettings() {
  const { settings, backend, ownHost: own } = await chrome.runtime.sendMessage({ type: "PG_GET_SETTINGS" });
  ownHost = own || "";
  $("mode").value = settings.mode;
  $("onlineUrl").value = settings.onlineUrl;
  $("localUrl").value = settings.localUrl;
  $("apiKey").value = settings.apiKey;
  $("safeToast").checked = settings.showSafeToast !== false;
  showBackend(backend);
}

function showBackend(b) {
  backendUrl = b.url;
  const label = $("backend");
  label.replaceChildren();
  const dot = document.createElement("i");
  dot.className = "dot " + b.label;
  label.append(dot, b.url ? ` ${b.label === "online" ? "Online" : "Local"} server · ${new URL(b.url).host}` : " Server offline");
  $("dashboard").disabled = !b.url;
}

$("rescan").addEventListener("click", async () => {
  $("rescan").disabled = true;
  $("rescan").textContent = "Scanning…";
  try {
    await chrome.runtime.sendMessage({ type: "PG_RESCAN", tabId: activeTab.id });
    setTimeout(async () => { await refresh(); $("rescan").disabled = false; $("rescan").textContent = "Re-scan"; }, 2500);
  } catch (_e) {
    $("rescan").disabled = false;
    $("rescan").textContent = "Re-scan";
  }
});

$("report").addEventListener("click", async () => {
  const m = (current && current.mule) || {};
  const suggested = ((m.flagged_accounts || [])[0] || {}).account_number || (m.accounts_extracted || [])[0] || "";
  const account = window.prompt("Bank account or DuitNow number to report:", suggested);
  if (!account) return;
  const res = await chrome.runtime.sendMessage({ type: "PG_REPORT_MULE", accountNumber: account, pageUrl: activeTab.url });
  $("report").textContent = res && res.ok ? "Reported ✓" : "Report failed";
});

$("dashboard").addEventListener("click", () => { if (backendUrl) chrome.tabs.create({ url: `${backendUrl}/dashboard/` }); });

$("safeToast").addEventListener("change", () => chrome.storage.local.set({ showSafeToast: $("safeToast").checked }));
function showView(settings) { $("mainView").hidden = settings; $("settingsView").hidden = !settings; }
$("openSettings").addEventListener("click", () => showView(true));
$("closeSettings").addEventListener("click", () => showView(false));

$("save").addEventListener("click", async () => {
  $("saveMsg").textContent = "Testing…";
  const settings = { mode: $("mode").value, onlineUrl: $("onlineUrl").value.trim(), localUrl: $("localUrl").value.trim(), apiKey: $("apiKey").value };
  const { backend } = await chrome.runtime.sendMessage({ type: "PG_SAVE_SETTINGS", settings });
  showBackend(backend);
  $("saveMsg").textContent = backend.url ? "Connected." : "No server reachable.";
});

(async () => {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  await loadSettings();
  if (activeTab) await refresh();
})();
