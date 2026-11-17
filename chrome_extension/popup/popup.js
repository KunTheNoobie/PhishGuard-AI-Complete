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

function setCheck(id, text, tone) {
  const node = $(id);
  node.textContent = text;
  node.className = tone || "";
}

function render(r) {
  current = r;
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
  const items = r && r.reasons && r.reasons.length ? r.reasons.slice(0, 6) : [];
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = r && r.offline ? "The PhishGuard server could not be reached." : "No reasons yet.";
    list.append(li);
  }
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

async function refresh() {
  const result = await chrome.runtime.sendMessage({ type: "PG_GET_RESULT", tabId: activeTab.id });
  render(result);
}

async function loadSettings() {
  const { settings, backend } = await chrome.runtime.sendMessage({ type: "PG_GET_SETTINGS" });
  $("mode").value = settings.mode;
  $("onlineUrl").value = settings.onlineUrl;
  $("localUrl").value = settings.localUrl;
  $("apiKey").value = settings.apiKey;
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
