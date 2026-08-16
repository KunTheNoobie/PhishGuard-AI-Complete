const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_API_TOKEN = "phishguard_secret_key_2026";
const TEXT_LIMIT = 30000;
const DOM_LIMIT = 3000000;

const memoryResults = new Map();
const OFFICIAL_BANK_DOMAINS = {
  // Malaysian Financial Infrastructure
  "Maybank": ["maybank2u.com.my", "maybank.com", "maybank.com.my"],
  "CIMB": ["cimbclicks.com.my", "cimb.com.my", "cimbbank.com.my"],
  "Public Bank": ["pbebank.com", "pbebank.com.my", "publicbank.com.my"],
  "RHB": ["rhbgroup.com", "rhbnow.com", "rhbbank.com.my"],
  "Hong Leong Bank": ["hlb.com.my", "hongleongconnect.my"],
  "AmBank": ["ambank.com.my", "ambankgroup.com"],
  "Bank Islam": ["bankislam.com.my", "bankislam.biz"],
  "Bank Rakyat": ["bankrakyat.com.my", "irakyat.com.my"],
  "DuitNow / PayNet": ["duitnow.my", "paynet.my"],
  "Touch 'n Go": ["touchngo.com.my", "tngdigital.com.my"],
  // Global Tech & Cloud
  "Google": ["google.com", "google.com.my", "googleapis.com", "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com", "gmail.com"],
  "Microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "github.com"],
  "Apple": ["apple.com", "icloud.com", "itunes.apple.com"],
  "Amazon": ["amazon.com", "amazon.com.my", "aws.amazon.com", "primevideo.com"],
  "Meta": ["whatsapp.com", "web.whatsapp.com", "facebook.com", "instagram.com", "meta.com"],
  // Global Fintech & Banking
  "PayPal": ["paypal.com", "paypal.me"],
  "Netflix": ["netflix.com"],
  "Stripe": ["stripe.com"],
  "Chase": ["chase.com"],
  "Bank of America": ["bankofamerica.com"],
  "Wells Fargo": ["wellsfargo.com"],
  "Citi": ["citi.com", "citibank.com"],
  "HSBC": ["hsbc.com", "hsbc.com.my", "hsbc.co.uk"],
  "Standard Chartered": ["sc.com", "standardchartered.com"],
  "Barclays": ["barclays.co.uk", "barclays.com"],
  "DBS / POSB": ["dbs.com", "dbs.com.sg", "posb.com.sg"],
  "OCBC": ["ocbc.com", "ocbc.com.sg"],
  "UOB": ["uob.com", "uob.com.sg"],
  "Binance": ["binance.com"],
  "Coinbase": ["coinbase.com"],
  "MetaMask": ["metamask.io"]
};

// Recognized global safe platform domains
const GLOBAL_SAFE_DOMAINS_SET = new Set([
  "google.com", "youtube.com", "youtu.be", "whatsapp.com", "facebook.com", "messenger.com", "instagram.com", "threads.net", "meta.com",
  "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "github.com", "linkedin.com", "apple.com", "icloud.com",
  "amazon.com", "aws.amazon.com", "twitter.com", "x.com", "reddit.com", "wikipedia.org", "spotify.com", "netflix.com", "discord.com", "telegram.org",
  "tiktok.com", "zoom.us", "zoom.com", "slack.com", "paypal.com", "stripe.com", "wise.com", "revolut.com", "shopee.com.my", "lazada.com.my",
  "cloudflare.com", "openai.com", "chatgpt.com", "claude.ai", "anthropic.com", "bing.com", "yahoo.com", "duckduckgo.com"
]);

function storageGet(defaults) {
  return new Promise((resolve) => {
    chrome.storage.sync.get(defaults, (items) => resolve(items));
  });
}

function storageSet(values) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(values, () => resolve());
  });
}

function sessionSet(values) {
  return new Promise((resolve) => {
    if (!chrome.storage.session) {
      resolve();
      return;
    }
    chrome.storage.session.set(values, () => resolve());
  });
}

function sessionGet(keys) {
  return new Promise((resolve) => {
    if (!chrome.storage.session) {
      resolve({});
      return;
    }
    chrome.storage.session.get(keys, (items) => resolve(items));
  });
}

async function getCustomTrustedDomains() {
  const data = await storageGet({ custom_trusted_domains: {} });
  const now = Date.now();
  const valid = {};
  for (const [domain, expiry] of Object.entries(data.custom_trusted_domains || {})) {
    if (typeof expiry === "number" && expiry > now) {
      valid[domain] = expiry;
    }
  }
  return valid;
}

async function getSettings() {
  const settings = await storageGet({
    apiBaseUrl: DEFAULT_API_BASE_URL,
    apiToken: DEFAULT_API_TOKEN
  });

  return {
    apiBaseUrl: String(settings.apiBaseUrl || DEFAULT_API_BASE_URL).replace(/\/$/, ""),
    apiToken: String(settings.apiToken || DEFAULT_API_TOKEN)
  };
}

function captureVisibleTab(windowId) {
  return new Promise((resolve) => {
    try {
      chrome.tabs.captureVisibleTab(
        windowId,
        { format: "jpeg", quality: 70 },
        (dataUrl) => {
          if (chrome.runtime.lastError || !dataUrl) {
            resolve("");
            return;
          }
          resolve(dataUrl);
        }
      );
    } catch (_e) {
      resolve("");
    }
  });
}

function updateActionBadge(tabId, result) {
  if (!chrome.action) return;
  const isBlock = result.final_verdict === "BLOCK_RENDER" || result.risk_level === "dangerous" || (result.mule_scan && result.mule_scan.mule_detected);
  const isSuspicious = result.risk_level === "suspicious";

  const text = isBlock ? "!" : (isSuspicious ? "?" : "OK");
  const color = isBlock ? "#ef4444" : (isSuspicious ? "#f59e0b" : "#10b981");

  if (tabId && typeof tabId === "number") {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  }
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

async function saveResult(tabId, result) {
  const payload = {
    ...result,
    analyzed_at: new Date().toISOString()
  };
  if (tabId && typeof tabId === "number") {
    memoryResults.set(tabId, payload);
    await sessionSet({ [`phishguard_result_${tabId}`]: payload });
    updateActionBadge(tabId, payload);
  } else {
    updateActionBadge(null, payload);
  }
  return payload;
}


async function getResult(tabId) {
  if (memoryResults.has(tabId)) {
    return memoryResults.get(tabId);
  }
  const stored = await sessionGet([`phishguard_result_${tabId}`]);
  return stored[`phishguard_result_${tabId}`] || null;
}

function sendWarningToTab(tabId, result) {
  if (result.risk_level === "suspicious" || result.risk_level === "dangerous") {
    try {
      chrome.tabs.sendMessage(tabId, {
        type: "PHISHGUARD_SHOW_WARNING",
        result
      });
    } catch (_e) {}
    return;
  }

  try {
    chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_CLEAR_WARNING" });
  } catch (_e) {}
}

async function postJson(settings, path, body) {
  const response = await fetch(`${settings.apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${settings.apiToken}`
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    throw new Error(await backendErrorMessage(response, path));
  }

  return response.json();
}

async function backendErrorMessage(response, path) {
  const text = await response.text();
  try {
    const payload = JSON.parse(text);
    const detail = payload && payload.detail;
    if (detail && typeof detail.message === "string") {
      return `${path}: ${detail.message}`;
    }
    if (typeof detail === "string") {
      return `${path}: ${detail}`;
    }
  } catch (_error) {
    // Fall back
  }
  return `${path} returned ${response.status}: ${text.slice(0, 180)}`;
}

async function callVisualBackend(settings, payload, screenshot) {
  if (!screenshot) {
    return { risk_level: "unavailable", detected_logos: [] };
  }
  return postJson(settings, "/api/visual/analyze", {
    current_url: payload.url,
    page_title: payload.title || "",
    visible_text: String(payload.visibleText || "").slice(0, TEXT_LIMIT),
    screenshot
  });
}

async function callSemanticBackend(settings, payload) {
  const domContent = String(
    payload.domContent || payload.visibleText || "<html><body>empty page content</body></html>"
  ).slice(0, DOM_LIMIT);

  const response = await fetch(`${settings.apiBaseUrl}/api/v1/analyse/semantics`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${settings.apiToken}`
    },
    body: JSON.stringify({
      url: payload.url,
      dom_content: domContent
    })
  });

  if (!response.ok) {
    throw new Error(await backendErrorMessage(response, "/api/v1/analyse/semantics"));
  }

  return response.json();
}

function normalizeSettledResult(settled) {
  if (settled.status === "fulfilled") {
    return { data: settled.value, error: null };
  }

  return {
    data: null,
    error: settled.reason && settled.reason.message ? settled.reason.message : String(settled.reason)
  };
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_error) {
    return "";
  }
}

function isOfficialBankDomain(host) {
  if (!host) return false;
  const cleanHost = host.replace(/^www\./, "").toLowerCase();

  // Check global safe platforms
  for (const safe of GLOBAL_SAFE_DOMAINS_SET) {
    if (cleanHost === safe || cleanHost.endsWith(`.${safe}`)) {
      return true;
    }
  }

  // Check official financial/tech brand domains
  for (const [, domains] of Object.entries(OFFICIAL_BANK_DOMAINS)) {
    for (const official of domains) {
      if (cleanHost === official || cleanHost.endsWith(`.${official}`)) {
        return true;
      }
    }
  }
  return false;
}

function hasOfficialVisualMatch(visualResult, pageUrl) {
  if (!pageUrl) return false;
  const host = hostFromUrl(pageUrl);
  if (!host) return false;

  if (isOfficialBankDomain(host)) {
    return true;
  }

  if (visualResult && Array.isArray(visualResult.detected_logos)) {
    for (const logo of visualResult.detected_logos) {
      const allowedDomains = OFFICIAL_BANK_DOMAINS[logo.brand] || [];
      for (const allowed of allowedDomains) {
        if (host === allowed || host.endsWith(`.${allowed}`)) {
          return true;
        }
      }
    }
  }

  return false;
}

function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function detectTypoSquatting(host) {
  if (!host) return null;
  const cleanHost = host.replace(/^www\./, "").toLowerCase();

  for (const [brand, domains] of Object.entries(OFFICIAL_BANK_DOMAINS)) {
    for (const official of domains) {
      if (cleanHost === official || cleanHost.endsWith(`.${official}`)) {
        return null; // Official domain
      }

      const baseOfficial = official.split(".")[0];
      const baseHost = cleanHost.split(".")[0];

      const dist = levenshteinDistance(baseHost, baseOfficial);
      if (dist >= 1 && dist <= 2) {
        return { brand, official, reason: `Lookalike domain detected targeting ${brand} (edit distance ${dist} from ${official})` };
      }

      if (cleanHost.includes(baseOfficial) && (cleanHost.includes("login") || cleanHost.includes("verify") || cleanHost.includes("secure") || cleanHost.includes("auth"))) {
        return { brand, official, reason: `Deceptive keyword subdomain detected targeting ${brand}` };
      }
    }
  }
  return null;
}

function sendNativeNotification(title, message) {
  try {
    if (chrome.notifications && chrome.notifications.create) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: title || "PhishGuard-AI Alert",
        message: message || "Potential phishing threat detected.",
        priority: 2
      });
    }
  } catch (_e) {}
}

function combineResults(visualResult, semanticResult, errors, pageUrl, pageText) {
  const host = hostFromUrl(pageUrl);
  const isOfficial = isOfficialBankDomain(host);
  const typosquat = detectTypoSquatting(host);

  const semanticAnalysis = semanticResult && semanticResult.data
    ? semanticResult.data.semantic_analysis
    : null;
  const muleScan = semanticResult && semanticResult.data
    ? semanticResult.data.mule_scan
    : null;

  const visualRisk = visualResult ? visualResult.risk_level : "unavailable";
  const visualThreat = visualRisk === "suspicious" || visualRisk === "dangerous";
  const officialVisualMatch = hasOfficialVisualMatch(visualResult, pageUrl);
  const muleThreat = Boolean(muleScan && muleScan.mule_detected);
  const semanticThreat = Boolean(
    semanticResult && (
      semanticResult.orchestration === "BLOCK_RENDER" ||
      (semanticAnalysis && semanticAnalysis.is_malicious) ||
      muleThreat
    )
  );

  let riskLevel = "safe";
  if (typosquat) {
    riskLevel = "dangerous";
  } else if (muleThreat) {
    riskLevel = "dangerous";
  } else if (isOfficial) {
    riskLevel = "safe";
  } else if (visualRisk === "dangerous" || (semanticThreat && !officialVisualMatch)) {
    riskLevel = "dangerous";
  } else if (visualRisk === "suspicious") {
    riskLevel = "suspicious";
  }

  const reasons = [];
  if (typosquat) {
    reasons.push(`CRITICAL: ${typosquat.reason}.`);
  }
  if (muleThreat) {
    const accounts = (muleScan.flagged_accounts || [])
      .map((account) => account.account_number)
      .join(", ");
    reasons.push(`Known mule account detected: ${accounts || "flagged in national registry"}.`);
  }

  if (riskLevel === "safe") {
    if (isOfficial || officialVisualMatch) {
      reasons.push(
        "Official authentic domain verified. No logo-domain mismatch or mule account detected."
      );
    } else {
      reasons.push(
        "Page looks safe. No suspicious keywords or known mule accounts detected."
      );
    }
  } else if (riskLevel !== "safe" && !reasons.length) {
    if (visualThreat && visualResult.reason) {
      reasons.push(visualResult.reason);
    }
    if (semanticAnalysis && semanticAnalysis.is_malicious) {
      reasons.push(
        `BERT classified page as ${semanticAnalysis.label} with ${Math.round(semanticAnalysis.confidence * 100)}% confidence.`
      );
    }
  }

  let finalVerdict = "SAFE";
  if (riskLevel === "dangerous") {
    finalVerdict = "BLOCK_RENDER";
  } else if (riskLevel === "suspicious") {
    finalVerdict = "REVIEW";
  }

  return {
    risk_level: riskLevel,
    final_verdict: finalVerdict,
    reason: reasons.join(" ") || "Analysis completed.",
    detected_logos: visualResult ? visualResult.detected_logos || [] : [],
    visual: visualResult,
    semantic: semanticResult,
    semantic_analysis: semanticAnalysis,
    mule_scan: muleScan,
    official_visual_match: officialVisualMatch,
    errors
  };
}

function evaluateOfflineHeuristics(pagePayload) {
  const host = hostFromUrl(pagePayload.url);
  const cleanHost = host.replace(/^www\./, "").toLowerCase();
  const text = (pagePayload.visibleText || "").toLowerCase();
  const isOfficial = isOfficialBankDomain(host);
  const typosquat = detectTypoSquatting(host);

  const scamKeywords = [
    "tac", "otp", "password", "kata laluan", "nric", "no kad pengenalan",
    "bantuan tunai", "kemaskini akaun", "akaun disekat", "saman pdrm",
    "duitnow", "pinjaman segera", "tuntutan", "security alert"
  ];
  const matchedKeywords = scamKeywords.filter(k => text.includes(k));

  if (isOfficial) {
    return {
      risk_level: "safe",
      final_verdict: "SAFE",
      reason: `Offline Protection Active: Verified Official Domain (${host})`,
      detected_logos: [],
      visual: { risk_level: "safe", detected_logos: [] },
      semantic: null,
      semantic_analysis: null,
      mule_scan: null,
      official_visual_match: true,
      errors: ["Backend offline (Autonomous Heuristics Active)"]
    };
  }

  if (typosquat) {
    return {
      risk_level: "dangerous",
      final_verdict: "BLOCK_RENDER",
      reason: `Offline Emergency Alert: ${typosquat.reason}`,
      detected_logos: [{ brand: typosquat.brand, confidence: 0.95, bounding_box: [] }],
      visual: { risk_level: "dangerous", detected_logos: [] },
      semantic: null,
      semantic_analysis: { is_malicious: true, confidence: 0.95, label: "PHISHING" },
      mule_scan: null,
      official_visual_match: false,
      errors: ["Backend offline (Autonomous Heuristics Active)"]
    };
  }

  if (matchedKeywords.length >= 2 && (cleanHost.includes(".top") || cleanHost.includes(".xyz") || cleanHost.includes("-") || cleanHost.includes("auth") || cleanHost.includes("login") || cleanHost.includes("verify"))) {
    return {
      risk_level: "dangerous",
      final_verdict: "BLOCK_RENDER",
      reason: `Offline Emergency Alert: Credential harvesting vector detected targeting Malaysian banking (${matchedKeywords.slice(0, 3).join(", ")})`,
      detected_logos: [],
      visual: { risk_level: "dangerous", detected_logos: [] },
      semantic: null,
      semantic_analysis: { is_malicious: true, confidence: 0.88, label: "PHISHING" },
      mule_scan: null,
      official_visual_match: false,
      errors: ["Backend offline (Autonomous Heuristics Active)"]
    };
  }

  return {
    risk_level: "neutral",
    final_verdict: "SAFE",
    reason: "Offline Protection Active: Standard web domain. Backend AI offline.",
    detected_logos: [],
    visual: null,
    semantic: null,
    semantic_analysis: null,
    mule_scan: null,
    official_visual_match: false,
    errors: ["Backend offline (Autonomous Heuristics Active)"]
  };
}

async function analyzePage(tab, pagePayload) {
  let targetTabId = tab && typeof tab.id === "number" ? tab.id : null;
  let targetWindowId = tab && typeof tab.windowId === "number" ? tab.windowId : undefined;

  if (!targetTabId) {
    const activeTabs = await new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, resolve);
    });
    if (activeTabs && activeTabs[0]) {
      targetTabId = activeTabs[0].id;
      targetWindowId = activeTabs[0].windowId;
    }
  }

  const host = hostFromUrl(pagePayload.url);
  const customTrusted = await getCustomTrustedDomains();

  if (host && customTrusted[host]) {
    const result = {
      risk_level: "safe",
      final_verdict: "SAFE",
      reason: `Domain '${host}' is currently in your 24h Custom Trusted Whitelist.`,
      detected_logos: [],
      visual: { risk_level: "safe", detected_logos: [] },
      semantic: null,
      semantic_analysis: null,
      mule_scan: null,
      official_visual_match: true,
      custom_trusted: true,
      errors: []
    };
    result.page_url = pagePayload.url;
    result.page_title = pagePayload.title || "";
    result.page_host = host;
    if (targetTabId) {
      const saved = await saveResult(targetTabId, result);
      sendWarningToTab(targetTabId, saved);
      return saved;
    }
    updateActionBadge(null, result);
    return result;
  }

  const screenshot = await captureVisibleTab(targetWindowId);
  const settings = await getSettings();
  const [visualSettled, semanticSettled] = await Promise.allSettled([
    callVisualBackend(settings, pagePayload, screenshot),
    callSemanticBackend(settings, pagePayload)
  ]);
  const visual = normalizeSettledResult(visualSettled);
  const semantic = normalizeSettledResult(semanticSettled);
  const errors = [];
  if (visual.error) {
    errors.push(`Visual: ${visual.error}`);
  }
  if (semantic.error) {
    errors.push(`Semantic: ${semantic.error}`);
  }

  let result;
  if (visual.error && semantic.error) {
    // Both endpoints offline — engage Autonomous Offline Heuristic Engine
    result = evaluateOfflineHeuristics(pagePayload);
  } else {
    result = combineResults(visual.data, semantic.data, errors, pagePayload.url, pagePayload.visibleText);
  }

  result.page_url = pagePayload.url;
  result.page_title = pagePayload.title || "";
  result.page_host = hostFromUrl(pagePayload.url);

  if (targetTabId) {
    const saved = await saveResult(targetTabId, result);
    sendWarningToTab(targetTabId, saved);
    if (saved.risk_level === "dangerous" || saved.final_verdict === "BLOCK_RENDER") {
      sendNativeNotification(
        "PhishGuard-AI Threat Intercepted",
        `High-risk phishing activity blocked on ${result.page_host || "webpage"}.`
      );
    }
    return saved;
  }

  updateActionBadge(null, result);
  return result;
}


async function saveError(tabId, error) {
  return saveResult(tabId, {
    detected_logos: [],
    errors: [error.message || "Analysis is unavailable."],
    risk_level: "unavailable",
    reason: error.message || "Analysis is unavailable."
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await storageGet(["apiBaseUrl", "apiToken"]);
  const defaults = {};
  if (!existing.apiBaseUrl) {
    defaults.apiBaseUrl = DEFAULT_API_BASE_URL;
  }
  if (!existing.apiToken) {
    defaults.apiToken = DEFAULT_API_TOKEN;
  }
  if (Object.keys(defaults).length) {
    await storageSet(defaults);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PHISHGUARD_ANALYZE_PAGE") {
    analyzePage(sender.tab, message.payload)
      .then((result) => sendResponse({ ok: true, result }))
      .catch(async (error) => {
        if (sender.tab && typeof sender.tab.id === "number") {
          await saveError(sender.tab.id, error);
        }
        sendResponse({ ok: false, error: error.message });
      });
    return true;
  }

  if (message.type === "PHISHGUARD_RESCAN_ACTIVE_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const activeTab = tabs && tabs[0];
      if (!activeTab || !activeTab.id) {
        sendResponse({ ok: false, error: "No active tab found" });
        return;
      }
      try {
        const injected = await chrome.scripting.executeScript({
          target: { tabId: activeTab.id },
          func: () => ({
            url: location.href,
            title: document.title || "",
            visibleText: document.body ? document.body.innerText.slice(0, 30000) : "",
            domContent: document.documentElement.outerHTML.slice(0, 3000000)
          })
        });
        const pageData = injected && injected[0] && injected[0].result;
        if (pageData) {
          const res = await analyzePage(activeTab, pageData);
          sendResponse({ ok: true, result: res });
        } else {
          sendResponse({ ok: false, error: "Could not read page context" });
        }
      } catch (err) {
        sendResponse({ ok: false, error: err.message });
      }
    });
    return true;
  }

  if (message.type === "PHISHGUARD_GET_LATEST_RESULT") {
    getResult(message.tabId).then((result) => {
      sendResponse({ ok: true, result });
    });
    return true;
  }

  if (message.type === "PHISHGUARD_GET_SETTINGS") {
    getSettings().then((settings) => {
      sendResponse({ ok: true, settings });
    });
    return true;
  }

  if (message.type === "PHISHGUARD_SAVE_SETTINGS") {
    storageSet({
      apiBaseUrl: message.settings.apiBaseUrl || DEFAULT_API_BASE_URL,
      apiToken: message.settings.apiToken || DEFAULT_API_TOKEN
    }).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "PHISHGUARD_TRUST_DOMAIN") {
    getCustomTrustedDomains().then(async (current) => {
      const durationMs = (message.hours || 24) * 60 * 60 * 1000;
      current[message.domain] = Date.now() + durationMs;
      await storageSet({ custom_trusted_domains: current });
      sendResponse({ ok: true, trusted: current });
    });
    return true;
  }

  if (message.type === "PHISHGUARD_GET_TRUSTED_DOMAINS") {
    getCustomTrustedDomains().then((trusted) => {
      sendResponse({ ok: true, trusted });
    });
    return true;
  }

  return false;
});

// Update badge whenever user switches active tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const result = await getResult(activeInfo.tabId);
  if (result) {
    updateActionBadge(activeInfo.tabId, result);
  } else {
    chrome.action.setBadgeText({ tabId: activeInfo.tabId, text: "" });
  }
});

// Autonomous background scan whenever user navigates or reloads any tab
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab && tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://") || tab.url.startsWith("file://"))) {
    try {
      const injected = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => ({
          url: location.href,
          title: document.title || "",
          visibleText: document.body ? document.body.innerText.slice(0, 30000) : "",
          domContent: document.documentElement ? document.documentElement.outerHTML.slice(0, 3000000) : ""
        })
      });
      const pageData = injected && injected[0] && injected[0].result;
      if (pageData && pageData.url) {
        const result = await analyzePage(tab, pageData);
        sendWarningToTab(tabId, result);
      }
    } catch (_e) {
      // Content script autoScanOnPageLoad will handle execution
    }
  }
});

