/*
 * PhishGuard-AI — background service worker (Manifest V3).
 *
 * Flow for every page:
 *   1. webNavigation.onBeforeNavigate  keeps the RAW address (an "@" disguise such as
 *      https://maybank2u.com.my@evil.top is still intact here; the page's own location hides it).
 *   2. tabs.onUpdated (loading)        fast address-only pre-scan, so a dangerous page is blocked early.
 *   3. content.js --PG_PAGE-->         full scan with the page's HTML, text and a screenshot.
 *   4. webNavigation.onErrorOccurred   remembers net::ERR_CERT_* errors, so the amber warning still shows
 *                                      after the user clicks "Proceed" on the browser's own warning.
 * Results are stored per tab AND per address: a tab never shows another tab's (or page's) verdict.
 * The backend makes every decision; this file only chooses the server and the user's allow-list.
 */
"use strict";

const ONLINE_URL = "https://phishguard-ai-backend-j74v.onrender.com";
const LOCAL_URL = "http://127.0.0.1:8000";
const DEFAULT_API_KEY = "12345678";
const TEXT_TIMEOUT_MS = 20000;     // Render's free tier can need a moment after sleeping
const VISUAL_TIMEOUT_MS = 25000;
const PRESCAN_TIMEOUT_MS = 20000;
const HEALTH_TIMEOUT_MS = 8000;
const BACKEND_CACHE_MS = 60000;
const ALLOW_HOURS = 24;
const SIGNAL_TTL_MS = 10 * 60 * 1000;
const TLS_TTL_MS = 15 * 60 * 1000;  // a certificate error is remembered per host for 15 minutes

const DEFAULTS = { mode: "auto", onlineUrl: ONLINE_URL, localUrl: LOCAL_URL, apiKey: DEFAULT_API_KEY, showSafeToast: true };
let backendCache = { url: null, label: "offline", at: 0 };

/* ── helpers ── */
const getSettings = () => chrome.storage.local.get(DEFAULTS);
const tabKey = (id) => `tab_${id}`;
const signalKey = (kind, id) => `${kind}_${id}`;

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (_e) { return ""; }
}

/** Address without user name, password and fragment: the key a result is stored under. */
function normalize(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}${u.search}`;
  } catch (_e) { return url || ""; }
}

const hasUserinfo = (url) => { try { const u = new URL(url); return Boolean(u.username || u.password); } catch (_e) { return false; } };
const isWeb = (url) => /^https?:\/\//i.test(url || "");

function isOwnHost(url) {
  const h = hostOf(url);
  let port = "";
  try { port = new URL(url).port; } catch (_e) { /* ignore */ }
  return h === hostOf(ONLINE_URL) || ((h === "localhost" || h === "127.0.0.1") && port === "8000");
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { return await fetch(url, { ...options, signal: controller.signal }); } finally { clearTimeout(timer); }
}

/* ── per-tab storage ── */
async function storeResult(tabId, url, result) {
  const entry = { nurl: normalize(url), result, at: Date.now() };
  await chrome.storage.session.set({ [tabKey(tabId)]: entry });
  const badge = { SAFE: ["", "#16a34a"], WARNING: ["!", "#d97706"], BLOCK_RENDER: ["X", "#dc2626"] }[result.verdict] || ["?", "#64748b"];
  chrome.action.setBadgeText({ tabId, text: badge[0] }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge[1] }).catch(() => {});
}

async function clearTab(tabId) {
  await chrome.storage.session.remove([tabKey(tabId), signalKey("pending", tabId)]);
  chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
}

/* ── certificate errors: one map keyed by host name in chrome.storage.local, so they survive the reload that follows
   "Proceed" and a restart of the extension (the server also re-checks the certificate itself) ── */
async function rememberTlsError(url, error) {
  const host = hostOf(url);
  if (!host) return;
  const { tlsErrors = {} } = await chrome.storage.local.get("tlsErrors");
  const now = Date.now();
  for (const h of Object.keys(tlsErrors)) if (now - tlsErrors[h].at > TLS_TTL_MS) delete tlsErrors[h];
  tlsErrors[host] = { error, at: now };
  await chrome.storage.local.set({ tlsErrors });
}

async function tlsErrorFor(url) {
  const { tlsErrors = {} } = await chrome.storage.local.get("tlsErrors");
  const rec = tlsErrors[hostOf(url)];
  return rec && Date.now() - rec.at <= TLS_TTL_MS ? rec : null;
}

/* ── backend selection: online HTTPS server first, local server as fallback ── */
async function isHealthy(base) {
  try { return (await fetchWithTimeout(`${base.replace(/\/$/, "")}/health`, {}, HEALTH_TIMEOUT_MS)).ok; } catch (_e) { return false; }
}

async function resolveBackend(force = false) {
  const s = await getSettings();
  if (!force && backendCache.url && Date.now() - backendCache.at < BACKEND_CACHE_MS) return backendCache;
  const candidates = s.mode === "online" ? [[s.onlineUrl, "online"]]
    : s.mode === "local" ? [[s.localUrl, "local"]]
    : [[s.onlineUrl, "online"], [s.localUrl, "local"]];
  for (const [url, label] of candidates) {
    if (await isHealthy(url)) { backendCache = { url: url.replace(/\/$/, ""), label, at: Date.now() }; return backendCache; }
  }
  backendCache = { url: null, label: "offline", at: Date.now() };
  return backendCache;
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

async function captureScreenshot(tab) {
  if (!tab || !tab.active) return null;
  try { return await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 70 }); } catch (_e) { return null; }
}

/* ── offline result: plain HTTP is never shown as safe ── */
function offlineResult(url, error) {
  const insecure = url.startsWith("http://");
  return {
    verdict: insecure ? "WARNING" : "UNAVAILABLE", risk_level: insecure ? "warning" : "unknown",
    rule: insecure ? "H2_INSECURE_HTTP" : null,
    headline: insecure ? "Not secure: unencrypted connection (HTTP)" : "PhishGuard server unreachable",
    explanation: insecure
      ? "The PhishGuard server could not be reached, but this page uses plain HTTP, so anything you type can be read by others on the network."
      : `The page could not be analysed (${error}). Check the server setting in the PhishGuard popup.`,
    reasons: [], steps: [], offline: true, final_url: url, hostname: hostOf(url), risk_score: insecure ? 0.55 : 0,
  };
}

/** One request to /api/v1/analyze. `fullScan` adds the page content and a screenshot. */
async function callBackend(tab, url, page, fullScan) {
  const backend = await resolveBackend();
  if (!backend.url) return offlineResult(url, "no server online");
  const s = await getSettings();
  const tls = await tlsErrorFor(url);
  const body = { url };
  if (fullScan && page) {
    body.dom_content = page.html;
    body.text_content = page.text;
    body.screenshot = await captureScreenshot(tab);
  }
  if (tls) body.tls_error = tls.error;
  try {
    const res = await fetchWithTimeout(`${backend.url}/api/v1/analyze`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${s.apiKey}` },
      body: JSON.stringify(body),
    }, fullScan ? (body.screenshot ? VISUAL_TIMEOUT_MS : TEXT_TIMEOUT_MS) : PRESCAN_TIMEOUT_MS);
    if (!res.ok) throw new Error(res.status === 401 ? "API key rejected" : `HTTP ${res.status}`);
    const result = await res.json();
    result.backend = backend.label;
    if (tls) result.tls_error = tls.error;
    return result;
  } catch (err) {
    backendCache.at = 0;
    return offlineResult(url, err.name === "AbortError" ? "timed out" : err.message);
  }
}

async function currentTab(tabId) { try { return await chrome.tabs.get(tabId); } catch (_e) { return null; } }
function show(tabId, result) { chrome.tabs.sendMessage(tabId, { type: "PG_SHOW", result }).catch(() => {}); }

/** Analyse one page state; the answer is kept only if the tab is still on that address. */
async function analyze(tab, url, page, fullScan) {
  if (!tab || !isWeb(url) || isOwnHost(url)) return null;
  const result = await callBackend(tab, url, page, fullScan);
  const now = await currentTab(tab.id);
  if (!now || normalize(now.url) !== normalize(url)) return null;   // the tab moved on: drop the answer
  result.page_title = (page && page.title) || "";
  if (result.verdict !== "SAFE" && await isAllowedByUser(hostOf(url))) result.allowed_by_user = true;
  await storeResult(tab.id, url, result);
  if (fullScan) show(tab.id, result);
  else if (result.verdict !== "SAFE") show(tab.id, result);           // early block / warning
  return result;
}

/* ── navigation events ── */
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || !isWeb(d.url)) return;
  await clearTab(d.tabId);
  // Keep the raw address; an "@" disguise is analysed at once, before the page loads.
  await chrome.storage.session.set({ [signalKey("raw", d.tabId)]: { url: d.url, at: Date.now() } });
  if (hasUserinfo(d.url)) {
    const result = await callBackend({ id: d.tabId, active: false }, d.url, null, false);
    if (result.verdict !== "SAFE") {
      await chrome.storage.session.set({ [signalKey("pending", d.tabId)]: { nurl: normalize(d.url), result } });
    }
  }
});

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || !isWeb(d.url)) return;
  // Deliver a block / warning found by the pre-scan as soon as the page exists.
  const key = signalKey("pending", d.tabId);
  const pending = (await chrome.storage.session.get(key))[key];
  if (pending && hostOf(pending.nurl) === hostOf(d.url)) {
    try { await chrome.scripting.executeScript({ target: { tabId: d.tabId }, files: ["content/content.js"] }); } catch (_e) { /* not scriptable */ }
    await storeResult(d.tabId, d.url, pending.result);
    show(d.tabId, pending.result);
    setTimeout(() => show(d.tabId, pending.result), 1200);
  }
});

chrome.webNavigation.onErrorOccurred.addListener(async (d) => {
  if (d.frameId !== 0 || !/^net::ERR_(CERT|SSL)_/.test(d.error || "")) return;
  await rememberTlsError(d.url, d.error);
  // The popup shows the certificate warning at once, even while the browser's own warning page is open.
  analyze(await currentTab(d.tabId), d.url, null, false);
});

chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
  if (change.status !== "loading" || !tab.url || !isWeb(tab.url)) return;
  const rawKey = signalKey("raw", tabId);
  const raw = (await chrome.storage.session.get(rawKey))[rawKey];
  const url = raw && Date.now() - raw.at < 30000 && normalize(raw.url) === normalize(tab.url) ? raw.url : tab.url;
  const existing = (await chrome.storage.session.get(tabKey(tabId)))[tabKey(tabId)];
  if (existing && existing.nurl === normalize(url)) return;          // already known
  analyze(tab, url, null, false);                                     // fast address-only pre-scan
});

/* ── messages from content.js and the popup ── */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const reply = (promise) => { promise.then(sendResponse, (e) => sendResponse({ ok: false, error: e.message })); return true; };

  switch (msg.type) {
    case "PG_PAGE":
      if (!sender.tab) return false;
      return reply((async () => {
        const rawKey = signalKey("raw", sender.tab.id);
        const raw = (await chrome.storage.session.get(rawKey))[rawKey];
        const url = raw && hasUserinfo(raw.url) && normalize(raw.url) === normalize(msg.page.url) ? raw.url : msg.page.url;
        await analyze(sender.tab, url, msg.page, true);
        return { ok: true };
      })());

    case "PG_GET_RESULT":   // the popup passes its tab's address; a result stored for another address is ignored
      return reply(chrome.storage.session.get(tabKey(msg.tabId)).then((o) => {
        const entry = o[tabKey(msg.tabId)];
        return entry && entry.nurl === normalize(msg.url) ? entry.result : null;
      }));

    case "PG_RESCAN":
      return reply((async () => {
        await chrome.storage.session.remove(tabKey(msg.tabId));
        await chrome.scripting.executeScript({ target: { tabId: msg.tabId }, files: ["content/content.js"] });
        return { ok: true };
      })());

    case "PG_ALLOW_SITE":
      return reply(allowSite(msg.host).then(() => ({ ok: true })));

    case "PG_REPORT_MULE":
      return reply((async () => {
        const backend = await resolveBackend();
        if (!backend.url) return { ok: false, error: "Server offline" };
        const s = await getSettings();
        const res = await fetchWithTimeout(`${backend.url}/api/v1/mule-reports`, {
          method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${s.apiKey}` },
          body: JSON.stringify({ account_number: msg.accountNumber, bank_name: msg.bankName || "Unknown", page_url: msg.pageUrl }),
        }, TEXT_TIMEOUT_MS);
        return { ok: res.ok, ...(await res.json().catch(() => ({}))) };
      })());

    case "PG_GET_SETTINGS":
      return reply((async () => ({ settings: await getSettings(), backend: await resolveBackend(), ownHost: hostOf(ONLINE_URL) }))());

    case "PG_SAVE_SETTINGS":
      return reply((async () => { await chrome.storage.local.set(msg.settings); return { backend: await resolveBackend(true) }; })());

    default:
      return false;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([tabKey(tabId), signalKey("raw", tabId), signalKey("pending", tabId)]);
});
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(Object.keys(DEFAULTS));
  await chrome.storage.local.set({ ...DEFAULTS, ...current });
});

// A changed server setting takes effect at once (the chosen server is otherwise cached for 60 s).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && ("mode" in changes || "onlineUrl" in changes || "localUrl" in changes)) backendCache = { url: null, label: "offline", at: 0 };
});
