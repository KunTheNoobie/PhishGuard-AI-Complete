const statusPill = document.getElementById("statusPill");
const resultPanel = document.getElementById("resultPanel");
const currentDomain = document.getElementById("currentDomain");
const scanTime = document.getElementById("scanTime");
const statusTitle = document.getElementById("statusTitle");
const reasonText = document.getElementById("reasonText");
const logoList = document.getElementById("logoList");
const visualStatus = document.getElementById("visualStatus");
const semanticStatus = document.getElementById("semanticStatus");
const muleStatus = document.getElementById("muleStatus");
const finalVerdict = document.getElementById("finalVerdict");
const scanButton = document.getElementById("scanButton");
const apiBaseUrl = document.getElementById("apiBaseUrl");
const apiToken = document.getElementById("apiToken");
const saveSettingsButton = document.getElementById("saveSettingsButton");
const trustSiteBtn = document.getElementById("trustSiteBtn");

// Tabs & History DOM
const tabScannerBtn = document.getElementById("tabScannerBtn");
const tabHistoryBtn = document.getElementById("tabHistoryBtn");
const scannerView = document.getElementById("scannerView");
const historyView = document.getElementById("historyView");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

let activeScanResult = null;

const STATUS_TITLES = {
  safe: "Page looks safe",
  suspicious: "Suspicious page",
  dangerous: "Potential phishing page",
  unavailable: "Backend unavailable",
  neutral: "No page result yet"
};

function sendRuntimeMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

function queryActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0] || null);
    });
  });
}

function sendTabMessage(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch (_error) {
    return "";
  }
}

function toTitleCase(str) {
  if (!str) return "";
  return str.toLowerCase().replace(/\b\w/g, s => s.toUpperCase());
}

function formatTime(value) {
  if (!value) return "Not scanned";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Just scanned";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function friendlyReason(result) {
  const reason = result && result.reason ? result.reason : "No reason provided.";
  if (!result || result.risk_level !== "unavailable") return reason;

  if (
    reason.includes("Failed to fetch") ||
    reason.includes("Could not establish connection") ||
    reason.includes("The message port closed") ||
    reason.includes("Receiving end does not exist")
  ) {
    return "Backend is not reachable. Start FastAPI at http://127.0.0.1:8000 and scan again.";
  }
  return reason;
}

function setPanelState(risk) {
  const normalized = risk || "neutral";
  statusPill.className = `status-pill ${normalized}`;
  resultPanel.className = `result-panel ${normalized}`;
  statusPill.textContent = normalized === "neutral" ? "Waiting" : normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function setBadge(element, text, status) {
  element.textContent = text;
  element.className = `module-value ${status || "neutral"}`;
}

function riskForSemantic(semanticAnalysis) {
  if (!semanticAnalysis) return "unavailable";
  return semanticAnalysis.is_malicious ? "dangerous" : "safe";
}

function riskForMule(muleScan) {
  if (!muleScan) return "unavailable";
  return muleScan.mule_detected ? "dangerous" : "safe";
}

function riskForVerdict(result) {
  if (!result || result.risk_level === "unavailable") return "unavailable";
  if (result.final_verdict === "BLOCK_RENDER") return "dangerous";
  if (result.final_verdict === "REVIEW") return "suspicious";
  return "safe";
}

function renderEmptyState() {
  setPanelState("neutral");
  currentDomain.textContent = "No domain";
  scanTime.textContent = "Not scanned";
  statusTitle.textContent = STATUS_TITLES.neutral;
  reasonText.textContent = "Open an HTTP or HTTPS page and scan it.";
  logoList.innerHTML = "";
  trustSiteBtn.classList.add("hidden");
  setBadge(visualStatus, "Waiting", "neutral");
  setBadge(semanticStatus, "Waiting", "neutral");
  setBadge(muleStatus, "Waiting", "neutral");
  setBadge(finalVerdict, "Waiting", "neutral");
}

function renderScanning(tab) {
  setPanelState("neutral");
  currentDomain.textContent = tab && tab.url ? hostFromUrl(tab.url) || "Current page" : "Current page";
  scanTime.textContent = "Scanning";
  statusTitle.textContent = "Scanning page";
  reasonText.textContent = "Please wait while this page is checked.";
  logoList.innerHTML = "";
  trustSiteBtn.classList.add("hidden");
  setBadge(visualStatus, "Scanning", "neutral");
  setBadge(semanticStatus, "Scanning", "neutral");
  setBadge(muleStatus, "Scanning", "neutral");
  setBadge(finalVerdict, "Pending", "neutral");
}

function renderResult(result) {
  activeScanResult = result;
  if (!result) {
    renderEmptyState();
    return;
  }

  const risk = result.risk_level || "neutral";
  setPanelState(risk);

  const domain = result.page_host || hostFromUrl(result.page_url) || "Unknown domain";
  currentDomain.textContent = domain;
  scanTime.textContent = formatTime(result.analyzed_at);
  statusTitle.textContent = STATUS_TITLES[risk] || STATUS_TITLES.neutral;
  reasonText.textContent = friendlyReason(result);

  logoList.innerHTML = "";

  const visualResult = result.visual || result;
  const semanticAnalysis = result.semantic_analysis ||
    (result.semantic && result.semantic.data ? result.semantic.data.semantic_analysis : null);
  const muleScan = result.mule_scan ||
    (result.semantic && result.semantic.data ? result.semantic.data.mule_scan : null);
  const logos = result.detected_logos || (visualResult ? visualResult.detected_logos : []) || [];

  const visualRisk = visualResult && visualResult.risk_level ? visualResult.risk_level : "unavailable";
  setBadge(visualStatus, visualRisk.charAt(0).toUpperCase() + visualRisk.slice(1), visualRisk);

  if (semanticAnalysis) {
    setBadge(
      semanticStatus,
      `${toTitleCase(semanticAnalysis.label)} ${Math.round(semanticAnalysis.confidence * 100)}%`,
      riskForSemantic(semanticAnalysis)
    );
  } else {
    setBadge(semanticStatus, "Unavailable", "unavailable");
  }

  if (muleScan) {
    const count = (muleScan.flagged_accounts || []).length;
    setBadge(
      muleStatus,
      muleScan.mule_detected ? `Detected ${count}` : "Clear",
      riskForMule(muleScan)
    );
  } else {
    setBadge(muleStatus, "Unavailable", "unavailable");
  }

  setBadge(
    finalVerdict,
    result.final_verdict === "BLOCK_RENDER" ? "Dangerous" : (result.final_verdict === "REVIEW" ? "Suspicious" : (result.final_verdict || (risk === "dangerous" ? "Dangerous" : "Safe"))),
    riskForVerdict(result)
  );

  for (const logo of logos) {
    const item = document.createElement("li");
    const brand = document.createElement("span");
    const confidence = document.createElement("strong");
    brand.textContent = logo.brand;
    confidence.textContent = `${Math.round(logo.confidence * 100)}%`;
    item.append(brand, confidence);
    logoList.appendChild(item);
  }

  // Trust Domain Button
  if (domain && domain !== "No domain" && domain !== "Unknown domain") {
    trustSiteBtn.classList.remove("hidden");
    if (result.custom_trusted) {
      trustSiteBtn.classList.add("trusted");
      trustSiteBtn.textContent = `✓ Trusted (${domain})`;
      trustSiteBtn.disabled = true;
    } else {
      trustSiteBtn.classList.remove("trusted");
      trustSiteBtn.textContent = `+ Trust Domain (24h)`;
      trustSiteBtn.disabled = false;
    }
  } else {
    trustSiteBtn.classList.add("hidden");
  }
}

// ═══════════════════════════════════════════════════════════════════
// SCAN HISTORY
// ═══════════════════════════════════════════════════════════════════

async function saveToScanHistory(result) {
  if (!result || !result.page_url) return;

  chrome.storage.local.get({ phishguard_history: [] }, (items) => {
    let history = items.phishguard_history || [];
    const entry = {
      url: result.page_url,
      domain: result.page_host || hostFromUrl(result.page_url),
      risk_level: result.risk_level || "neutral",
      final_verdict: result.final_verdict || "SAFE",
      timestamp: result.analyzed_at || new Date().toISOString()
    };

    // Prepend and keep max 10
    history = [entry, ...history.filter(h => h.url !== entry.url)].slice(0, 10);
    chrome.storage.local.set({ phishguard_history: history }, () => {
      renderHistory();
    });
  });
}

function renderHistory() {
  chrome.storage.local.get({ phishguard_history: [] }, (items) => {
    const history = items.phishguard_history || [];
    if (!history.length) {
      historyList.innerHTML = '<div class="history-empty">No scan history recorded yet.</div>';
      return;
    }

    historyList.innerHTML = history.map(item => `
      <div class="history-item">
        <div class="history-item-left">
          <span class="history-domain" title="${item.url}">${item.domain || item.url}</span>
          <span class="history-time">${formatTime(item.timestamp)}</span>
        </div>
        <span class="history-badge ${item.risk_level}">${item.risk_level}</span>
      </div>
    `).join("");
  });
}

function clearHistory() {
  chrome.storage.local.set({ phishguard_history: [] }, () => {
    renderHistory();
  });
}

// ═══════════════════════════════════════════════════════════════════
// TRUST DOMAIN ACTION
// ═══════════════════════════════════════════════════════════════════

async function handleTrustDomain() {
  if (!activeScanResult) return;
  const domain = activeScanResult.page_host || hostFromUrl(activeScanResult.page_url);
  if (!domain) return;

  await sendRuntimeMessage({
    type: "PHISHGUARD_TRUST_DOMAIN",
    domain: domain,
    hours: 24
  });

  trustSiteBtn.classList.add("trusted");
  trustSiteBtn.textContent = `✓ Trusted (${domain})`;
  trustSiteBtn.disabled = true;

  // Re-scan with trusted state
  scanActivePage();
}

// ═══════════════════════════════════════════════════════════════════
// TABS SWITCHING
// ═══════════════════════════════════════════════════════════════════

function showTab(tab) {
  if (tab === "scanner") {
    tabScannerBtn.classList.add("active");
    tabHistoryBtn.classList.remove("active");
    scannerView.classList.add("active");
    historyView.classList.remove("active");
  } else {
    tabScannerBtn.classList.remove("active");
    tabHistoryBtn.classList.add("active");
    scannerView.classList.remove("active");
    historyView.classList.add("active");
    renderHistory();
  }
}

// ═══════════════════════════════════════════════════════════════════
// MAIN SCAN LOGIC
// ═══════════════════════════════════════════════════════════════════

async function refreshResult() {
  const tab = await queryActiveTab();
  if (!tab || typeof tab.id !== "number") {
    renderEmptyState();
    return;
  }

  const response = await sendRuntimeMessage({
    type: "PHISHGUARD_GET_LATEST_RESULT",
    tabId: tab.id
  });
  renderResult(response && response.result ? response.result : null);
}

async function scanActivePage() {
  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";

  try {
    const tab = await queryActiveTab();
    if (!tab || typeof tab.id !== "number") {
      throw new Error("No active tab found.");
    }

    renderScanning(tab);
    const response = await sendTabMessage(tab.id, { type: "PHISHGUARD_RUN_SCAN" });
    if (response && response.ok && response.result) {
      renderResult(response.result);
      saveToScanHistory(response.result);
      return;
    }
    if (response && response.error) {
      throw new Error(response.error);
    }
    await refreshResult();
  } catch (error) {
    renderResult({
      detected_logos: [],
      risk_level: "unavailable",
      reason: error.message
    });
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Scan Page";
  }
}

async function loadSettings() {
  const response = await sendRuntimeMessage({ type: "PHISHGUARD_GET_SETTINGS" });
  if (!response || !response.settings) return;
  apiBaseUrl.value = response.settings.apiBaseUrl;
  apiToken.value = response.settings.apiToken;
}

async function saveSettings() {
  await sendRuntimeMessage({
    type: "PHISHGUARD_SAVE_SETTINGS",
    settings: {
      apiBaseUrl: apiBaseUrl.value.trim(),
      apiToken: apiToken.value.trim()
    }
  });
  saveSettingsButton.textContent = "Saved";
  window.setTimeout(() => {
    saveSettingsButton.textContent = "Save";
  }, 1000);
}

// Event Listeners
tabScannerBtn.addEventListener("click", () => showTab("scanner"));
tabHistoryBtn.addEventListener("click", () => showTab("history"));
clearHistoryBtn.addEventListener("click", clearHistory);
trustSiteBtn.addEventListener("click", handleTrustDomain);
scanButton.addEventListener("click", scanActivePage);
saveSettingsButton.addEventListener("click", saveSettings);

loadSettings();
refreshResult();
renderHistory();
