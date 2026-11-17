/*
 * PhishGuard-AI — background service worker (Manifest V3).
 *
 * Flow for every page:
 *   content.js  --PG_PAGE{url, html, text}-->  this worker
 *   this worker --POST /api/v1/analyze {url, dom_content, text_content, screenshot}--> backend
 *   backend     --{verdict, headline, explanation, reasons, steps ...}--> this worker
 *   this worker --PG_SHOW{result}--> content.js  (red overlay / amber banner / nothing)
 *
 * The backend makes every decision.  The only logic kept here is:
 *   - choosing the backend (online HTTPS server first, local server as fallback);
 *   - the user's "Proceed anyway" allow-list;
 *   - a minimal offline rule: a plain-HTTP page is never shown as safe.
 */
"use strict";

const ONLINE_URL = "https://phishguard-ai-backend.onrender.com";
const LOCAL_URL = "http://127.0.0.1:8000";
const DEFAULT_API_KEY = "12345678";
const TEXT_TIMEOUT_MS = 8000;      // page analysis without a screenshot
const VISUAL_TIMEOUT_MS = 12000;   // with a screenshot (adds the YOLOv8n logo check)
const HEALTH_TIMEOUT_MS = 3000;
const BACKEND_CACHE_MS = 60000;
const ALLOW_HOURS = 24;

const DEFAULTS = { mode: "auto", onlineUrl: ONLINE_URL, localUrl: LOCAL_URL, apiKey: DEFAULT_API_KEY, showSafeToast: true };
let backendCache = { url: null, label: "offline", at: 0 };

/* ── Storage helpers ── */
const getSettings = () => chrome.storage.local.get(DEFAULTS);
const tabKey = (tabId) => `tab_${tabId}`;

async function saveResult(tabId, result) {
  await chrome.storage.session.set({ [tabKey(tabId)]: result });
  const badge = { SAFE: ["", "#16a34a"], WARNING: ["!", "#d97706"], BLOCK_RENDER: ["X", "#dc2626"] }[result.verdict]
    || ["?", "#64748b"];
  chrome.action.setBadgeText({ tabId, text: badge[0] });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge[1] });
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/* ── Backend selection: online HTTPS server, else local server ── */
async function isHealthy(base) {
  try {
    const res = await fetchWithTimeout(`${base.replace(/\/$/, "")}/health`, {}, HEALTH_TIMEOUT_MS);
    return res.ok;
  } catch (_e) {
    return false;
  }
}

async function resolveBackend(force = false) {
  const s = await getSettings();
  if (!force && backendCache.url && Date.now() - backendCache.at < BACKEND_CACHE_MS) return backendCache;
  const candidates = s.mode === "online" ? [[s.onlineUrl, "online"]]
    : s.mode === "local" ? [[s.localUrl, "local"]]
    : [[s.onlineUrl, "online"], [s.localUrl, "local"]];
  for (const [url, label] of candidates) {
    if (await isHealthy(url)) {
      backendCache = { url: url.replace(/\/$/, ""), label, at: Date.now() };
      return backendCache;
    }
  }
  backendCache = { url: null, label: "offline", at: Date.now() };
  return backendCache;
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (_e) { return ""; }
}

/* ── "Proceed anyway" allow-list (per host, 24 hours) ── */
async function isAllowedByUser(host) {
  const { allowList = {} } = await chrome.storage.local.get("allowList");
  return Boolean(allowList[host] && allowList[host] > Date.now());
}

async function allowSite(host) {
  const { allowList = {} } = await chrome.storage.local.get("allowList");
  allowList[host] = Date.now() + ALLOW_HOURS * 3600 * 1000;
  await chrome.storage.local.set({ allowList });
}

/* ── Screenshot of the visible tab for the logo check ── */
async function captureScreenshot(tab) {
  if (!tab || !tab.active) return null;
  try {
    return await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 70 });
  } catch (_e) {
    return null; // e.g. the window is minimised
  }
}

/* ── Offline result: never call plain HTTP safe ── */
function offlineResult(url, error) {
  const insecure = url.startsWith("http://");
  return {
    verdict: insecure ? "WARNING" : "UNAVAILABLE",
    risk_level: insecure ? "warning" : "unknown",
    rule: insecure ? "H2_INSECURE_HTTP" : null,
    headline: insecure ? "Not secure: unencrypted connection (HTTP)" : "PhishGuard backend unreachable",
    explanation: insecure
      ? "The PhishGuard server could not be reached, but this page uses plain HTTP, so anything you type can be read by others on the network."
      : `The page could not be analysed (${error}). Check the backend setting in the PhishGuard popup.`,
    reasons: [],
    steps: [],
    offline: true,
    final_url: url,
    hostname: hostOf(url),
    risk_score: insecure ? 0.55 : 0,
  };
}

async function analyzePage(tab, page) {
  const host = hostOf(page.url);
  const backend = await resolveBackend();

  // Never analyse PhishGuard's own dashboard and API pages.
  if (backend.url && host === hostOf(backend.url)) return null;

  let result;
  if (!backend.url) {
    result = offlineResult(page.url, "no backend online");
  } else {
    const s = await getSettings();
    const screenshot = await captureScreenshot(tab);
    try {
      const res = await fetchWithTimeout(`${backend.url}/api/v1/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${s.apiKey}` },
        body: JSON.stringify({ url: page.url, dom_content: page.html, text_content: page.text, screenshot }),
      }, screenshot ? VISUAL_TIMEOUT_MS : TEXT_TIMEOUT_MS);
      if (!res.ok) throw new Error(res.status === 401 ? "API key rejected" : `HTTP ${res.status}`);
      result = await res.json();
      result.backend = backend.label;
    } catch (err) {
      backendCache.at = 0; // re-probe next time
      result = offlineResult(page.url, err.name === "AbortError" ? "timed out" : err.message);
    }
  }

  result.page_title = page.title || "";
  if (result.verdict !== "SAFE" && await isAllowedByUser(host)) {
    result.allowed_by_user = true;
  }
  await saveResult(tab.id, result);
  chrome.tabs.sendMessage(tab.id, { type: "PG_SHOW", result }).catch(() => {});
  return result;
}

/* ── Messages from content.js and the popup ── */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const reply = (promise) => { promise.then(sendResponse, (e) => sendResponse({ ok: false, error: e.message })); return true; };

  switch (msg.type) {
    case "PG_PAGE":
      if (sender.tab) return reply(analyzePage(sender.tab, msg.page).then(() => ({ ok: true })));
      return false;

    case "PG_GET_RESULT":
      return reply(chrome.storage.session.get(tabKey(msg.tabId)).then((o) => o[tabKey(msg.tabId)] || null));

    case "PG_RESCAN":
      return reply((async () => {
        await chrome.scripting.executeScript({ target: { tabId: msg.tabId }, files: ["content/content.js"] });
        return { ok: true };
      })());

    case "PG_ALLOW_SITE":
      return reply(allowSite(msg.host).then(() => ({ ok: true })));

    case "PG_REPORT_MULE":
      return reply((async () => {
        const backend = await resolveBackend();
        if (!backend.url) return { ok: false, error: "Backend offline" };
        const s = await getSettings();
        const res = await fetchWithTimeout(`${backend.url}/api/v1/mule-reports`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${s.apiKey}` },
          body: JSON.stringify({ account_number: msg.accountNumber, bank_name: msg.bankName || "Unknown", page_url: msg.pageUrl }),
        }, TEXT_TIMEOUT_MS);
        const data = await res.json().catch(() => ({}));
        return { ok: res.ok, ...data };
      })());

    case "PG_GET_SETTINGS":
      return reply((async () => ({ settings: await getSettings(), backend: await resolveBackend() }))());

    case "PG_SAVE_SETTINGS":
      return reply((async () => {
        await chrome.storage.local.set(msg.settings);
        return { backend: await resolveBackend(true) };
      })());

    default:
      return false;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(tabKey(tabId)));
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(Object.keys(DEFAULTS));
  await chrome.storage.local.set({ ...DEFAULTS, ...current });
});
