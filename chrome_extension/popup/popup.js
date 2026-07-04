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

function formatTime(value) {
  if (!value) {
    return "Not scanned";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Just scanned";
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  });
}

function friendlyReason(result) {
  const reason = result && result.reason ? result.reason : "No reason provided.";
  if (!result || result.risk_level !== "unavailable") {
    return reason;
  }

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
  statusPill.textContent = normalized === "neutral" ? "WAITING" : normalized.toUpperCase();
}

function setBadge(element, text, status) {
  element.textContent = text;
  element.className = `module-value ${status || "neutral"}`;
}

function riskForSemantic(semanticAnalysis) {
  if (!semanticAnalysis) {
    return "unavailable";
  }
  return semanticAnalysis.is_malicious ? "dangerous" : "safe";
}

function riskForMule(muleScan) {
  if (!muleScan) {
    return "unavailable";
  }
  return muleScan.mule_detected ? "dangerous" : "safe";
}

function riskForVerdict(result) {
  if (!result || result.risk_level === "unavailable") {
    return "unavailable";
  }
  if (result.final_verdict === "BLOCK_RENDER") {
    return "dangerous";
  }
  if (result.final_verdict === "REVIEW") {
    return "suspicious";
  }
  return "safe";
}

function renderEmptyState() {
  setPanelState("neutral");
  currentDomain.textContent = "No domain";
  scanTime.textContent = "Not scanned";
  statusTitle.textContent = STATUS_TITLES.neutral;
  reasonText.textContent = "Open an HTTP or HTTPS page and scan it.";
  logoList.innerHTML = "";
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
  setBadge(visualStatus, "Scanning", "neutral");
  setBadge(semanticStatus, "Scanning", "neutral");
  setBadge(muleStatus, "Scanning", "neutral");
  setBadge(finalVerdict, "Pending", "neutral");
}

function renderResult(result) {
  if (!result) {
    renderEmptyState();
    return;
  }

  const risk = result.risk_level || "neutral";
  setPanelState(risk);

  currentDomain.textContent = result.page_host || hostFromUrl(result.page_url) || "Unknown domain";
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

  const visualRisk = visualResult && visualResult.risk_level
    ? visualResult.risk_level
    : "unavailable";
  setBadge(visualStatus, visualRisk.toUpperCase(), visualRisk);

  if (semanticAnalysis) {
    setBadge(
      semanticStatus,
      `${semanticAnalysis.label} ${Math.round(semanticAnalysis.confidence * 100)}%`,
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
    result.final_verdict || (risk === "dangerous" ? "BLOCK_RENDER" : "SAFE"),
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
}

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
    scanButton.textContent = "Scan page";
  }
}

async function loadSettings() {
  const response = await sendRuntimeMessage({ type: "PHISHGUARD_GET_SETTINGS" });
  if (!response || !response.settings) {
    return;
  }
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

scanButton.addEventListener("click", scanActivePage);
saveSettingsButton.addEventListener("click", saveSettings);

loadSettings();
refreshResult();
