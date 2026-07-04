const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_API_TOKEN = "phishguard_secret_key_2026";
const TEXT_LIMIT = 30000;
const DOM_LIMIT = 3000000;

const memoryResults = new Map();
const OFFICIAL_BANK_DOMAINS = {
  "Maybank": ["maybank2u.com.my", "maybank.com", "maybank.com.my"],
  "CIMB": ["cimbclicks.com.my", "cimb.com.my", "cimbbank.com.my"],
  "Public Bank": ["pbebank.com", "pbebank.com.my", "publicbank.com.my"],
  "RHB": ["rhbgroup.com", "rhbnow.com", "rhbbank.com.my"],
  "Hong Leong Bank": ["hlb.com.my"]
};

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
  return new Promise((resolve, reject) => {
    chrome.tabs.captureVisibleTab(
      windowId,
      { format: "jpeg", quality: 70 },
      (dataUrl) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(dataUrl);
      }
    );
  });
}

async function saveResult(tabId, result) {
  const payload = {
    ...result,
    analyzed_at: new Date().toISOString()
  };
  memoryResults.set(tabId, payload);
  await sessionSet({ [`phishguard_result_${tabId}`]: payload });
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
    chrome.tabs.sendMessage(tabId, {
      type: "PHISHGUARD_SHOW_WARNING",
      result
    });
    return;
  }

  chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_CLEAR_WARNING" });
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
    // Fall back to the truncated response body below.
  }
  return `${path} returned ${response.status}: ${text.slice(0, 180)}`;
}

async function callVisualBackend(settings, payload, screenshot) {
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

function domainMatches(host, domains) {
  return domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function officialBankForHost(host) {
  return Object.entries(OFFICIAL_BANK_DOMAINS).find(([_brand, domains]) => {
    return domainMatches(host, domains);
  });
}

function hasOfficialVisualMatch(visualResult, pageUrl) {
  const host = hostFromUrl(pageUrl);
  const officialDomain = officialBankForHost(host);
  if (officialDomain && visualResult && visualResult.risk_level === "safe") {
    return true;
  }

  const logos = visualResult && Array.isArray(visualResult.detected_logos)
    ? visualResult.detected_logos
    : [];

  return logos.some((logo) => {
    const domains = OFFICIAL_BANK_DOMAINS[logo.brand] || [];
    return domainMatches(host, domains);
  });
}

function combineResults(visualResult, semanticResult, errors, pageUrl) {
  const semanticAnalysis = semanticResult && semanticResult.data
    ? semanticResult.data.semantic_analysis
    : null;
  const muleScan = semanticResult && semanticResult.data
    ? semanticResult.data.mule_scan
    : null;

  const visualRisk = visualResult ? visualResult.risk_level : "unavailable";
  const visualThreat = visualRisk === "suspicious" || visualRisk === "dangerous";
  const officialVisualMatch = hasOfficialVisualMatch(visualResult, pageUrl);
  const semanticThreat = Boolean(
    semanticResult && (
      semanticResult.orchestration === "BLOCK_RENDER" ||
      (semanticAnalysis && semanticAnalysis.is_malicious) ||
      (muleScan && muleScan.mule_detected)
    )
  );
  const muleThreat = Boolean(muleScan && muleScan.mule_detected);
  const hasErrors = errors.length > 0;
  const bothUnavailable = !visualResult && !semanticResult;

  let riskLevel = "safe";
  if (muleThreat || visualRisk === "dangerous" || (semanticThreat && !officialVisualMatch)) {
    riskLevel = "dangerous";
  } else if (visualRisk === "suspicious") {
    riskLevel = "suspicious";
  } else if (bothUnavailable || hasErrors) {
    riskLevel = "unavailable";
  }

  const reasons = [];
  if (riskLevel === "safe") {
    if (officialVisualMatch) {
      reasons.push(
        "Final verdict is SAFE because the visual identity and domain check passed, and no mule account was detected."
      );
    } else if (visualResult && visualResult.risk_level === "safe" && visualResult.reason) {
      reasons.push(visualResult.reason);
    } else {
      reasons.push(
        "Final verdict is SAFE. No logo-domain mismatch or mule account was detected."
      );
    }
  } else {
    if (visualThreat && visualResult.reason) {
      reasons.push(visualResult.reason);
    }
    if (semanticAnalysis && semanticAnalysis.is_malicious) {
      reasons.push(
        `BERT classified this page as ${semanticAnalysis.label} with ${Math.round(semanticAnalysis.confidence * 100)}% confidence.`
      );
    }
    if (muleThreat) {
      const accounts = (muleScan.flagged_accounts || [])
        .map((account) => account.account_number)
        .join(", ");
      reasons.push(`Known mule account detected${accounts ? `: ${accounts}` : "."}`);
    }
    if (!reasons.length && hasErrors) {
      reasons.push(`Scan incomplete: ${errors.join(" | ")}`);
    }
    if (!reasons.length) {
      reasons.push("No logo-domain mismatch, phishing semantic signal, or mule account was detected.");
    }
  }

  let finalVerdict = "SAFE";
  if (riskLevel === "dangerous") {
    finalVerdict = "BLOCK_RENDER";
  } else if (riskLevel === "suspicious") {
    finalVerdict = "REVIEW";
  } else if (riskLevel === "unavailable") {
    finalVerdict = "Unavailable";
  }

  return {
    risk_level: riskLevel,
    final_verdict: finalVerdict,
    reason: reasons.join(" "),
    detected_logos: visualResult ? visualResult.detected_logos || [] : [],
    visual: visualResult,
    semantic: semanticResult,
    semantic_analysis: semanticAnalysis,
    mule_scan: muleScan,
    official_visual_match: officialVisualMatch,
    errors
  };
}

async function analyzePage(tab, pagePayload) {
  if (!tab || typeof tab.id !== "number" || typeof tab.windowId !== "number") {
    throw new Error("Missing active tab information.");
  }

  const screenshot = await captureVisibleTab(tab.windowId);
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

  const result = combineResults(visual.data, semantic.data, errors, pagePayload.url);
  result.page_url = pagePayload.url;
  result.page_title = pagePayload.title || "";
  result.page_host = hostFromUrl(pagePayload.url);
  const saved = await saveResult(tab.id, result);
  sendWarningToTab(tab.id, saved);
  return saved;
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

  return false;
});
