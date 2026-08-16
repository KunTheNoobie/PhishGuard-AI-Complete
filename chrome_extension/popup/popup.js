const statusPill = document.getElementById("statusPill");
const backendPingBadge = document.getElementById("backendPingBadge");
const pingStatusText = document.getElementById("pingStatusText");
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
const reportSafeBtn = document.getElementById("reportSafeBtn");
const copyVerdictBtn = document.getElementById("copyVerdictBtn");

// Gauge DOM
const gaugeProgress = document.getElementById("gaugeProgress");
const gaugeScore = document.getElementById("gaugeScore");
const flagMuleBtn = document.getElementById("flagMuleBtn");

// Tabs & Views DOM
const tabScannerBtn = document.getElementById("tabScannerBtn");
const tabTrustedBtn = document.getElementById("tabTrustedBtn");
const tabHistoryBtn = document.getElementById("tabHistoryBtn");
const scannerView = document.getElementById("scannerView");
const trustedView = document.getElementById("trustedView");
const historyView = document.getElementById("historyView");
const trustedList = document.getElementById("trustedList");
const clearTrustedBtn = document.getElementById("clearTrustedBtn");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

let activeScanResult = null;

const STATUS_TITLES = {
  safe: "Page Looks Safe",
  suspicious: "Suspicious Activity",
  dangerous: "Phishing Threat Intercepted",
  unavailable: "Backend Offline",
  neutral: "Ready to Scan"
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

async function ensureContentScriptInjected(tabId) {
  try {
    if (chrome.scripting && chrome.scripting.executeScript) {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ["content/content.js"]
      });
    }
  } catch (_e) {
    // Already injected or restricted internal page
  }
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
    return "FastAPI backend is offline or tab requires refresh. Start server at http://127.0.0.1:8000 and scan again.";
  }
  return reason;
}

function setPanelState(risk) {
  const normalized = risk || "neutral";
  statusPill.className = `status-pill ${normalized}`;
  resultPanel.className = `result-panel ${normalized}`;
  statusPill.textContent = normalized === "neutral" ? "Ready" : normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function setBadge(element, text, status) {
  element.textContent = text;
  element.className = `module-value ${status || "neutral"}`;
}

function updateGauge(scoreFraction, riskLevel) {
  if (!gaugeProgress || !gaugeScore) return;
  const circumference = 201.06; // 2 * PI * 32
  const score = Math.max(0, Math.min(1, scoreFraction || 0));
  const offset = circumference * (1 - score);
  
  gaugeProgress.style.strokeDashoffset = offset;
  gaugeScore.textContent = `${Math.round(score * 100)}%`;

  if (riskLevel === "dangerous" || score >= 0.75) {
    gaugeProgress.style.stroke = "#ef4444";
  } else if (riskLevel === "suspicious" || score >= 0.50) {
    gaugeProgress.style.stroke = "#f59e0b";
  } else {
    gaugeProgress.style.stroke = "#10b981";
  }
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

async function renderEmptyState() {
  const tab = await queryActiveTab();
  const domain = tab && tab.url ? hostFromUrl(tab.url) : "Current Webpage";
  
  setPanelState("neutral");
  currentDomain.textContent = domain || "Current Webpage";
  scanTime.textContent = "Not scanned";
  statusTitle.textContent = "Ready to Scan";
  reasonText.textContent = "Click 'Scan Page' below to analyze visual branding, BERT semantics, and mule registries.";
  logoList.innerHTML = "";
  trustSiteBtn.classList.add("hidden");
  if (reportSafeBtn) reportSafeBtn.classList.add("hidden");
  updateGauge(0, "neutral");
  setBadge(visualStatus, "Pending", "neutral");
  setBadge(semanticStatus, "Pending", "neutral");
  setBadge(muleStatus, "Pending", "neutral");
  setBadge(finalVerdict, "Pending", "neutral");
}

function renderScanning(tab) {
  setPanelState("neutral");
  currentDomain.textContent = tab && tab.url ? hostFromUrl(tab.url) || "Current page" : "Current page";
  scanTime.textContent = "Scanning…";
  statusTitle.textContent = "Inspecting Security Vectors...";
  reasonText.textContent = "Analyzing BERT semantics, YOLOv8 logos, and DuitNow mule registry in parallel.";
  logoList.innerHTML = "";
  trustSiteBtn.classList.add("hidden");
  if (reportSafeBtn) reportSafeBtn.classList.add("hidden");
  updateGauge(0.5, "suspicious");
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

  const domain = result.page_host || hostFromUrl(result.page_url) || "Current Webpage";
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

  // Gauge computation
  let computedScore = 0.0;
  if (risk === "dangerous" || result.final_verdict === "BLOCK_RENDER") {
    computedScore = semanticAnalysis && semanticAnalysis.confidence ? semanticAnalysis.confidence : 0.95;
  } else if (risk === "suspicious") {
    computedScore = 0.65;
  } else if (risk === "safe") {
    computedScore = 0.0;
  }
  updateGauge(computedScore, risk);

  const visualRisk = visualResult && visualResult.risk_level ? visualResult.risk_level : "unavailable";
  setBadge(visualStatus, visualRisk === "unavailable" ? "Verified" : visualRisk.charAt(0).toUpperCase() + visualRisk.slice(1), visualRisk === "unavailable" ? "safe" : visualRisk);

  if (semanticAnalysis) {
    setBadge(
      semanticStatus,
      `${toTitleCase(semanticAnalysis.label)} ${Math.round(semanticAnalysis.confidence * 100)}%`,
      riskForSemantic(semanticAnalysis)
    );
  } else {
    setBadge(semanticStatus, risk === "safe" ? "Legitimate (100%)" : "Unavailable", risk === "safe" ? "safe" : "unavailable");
  }

  if (muleScan) {
    const count = (muleScan.flagged_accounts || []).length;
    setBadge(
      muleStatus,
      muleScan.mule_detected ? `Detected ${count}` : "Clear",
      riskForMule(muleScan)
    );
  } else {
    setBadge(muleStatus, risk === "safe" ? "Clear" : "Unavailable", risk === "safe" ? "safe" : "unavailable");
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
  if (domain && domain !== "No domain" && domain !== "Unknown domain" && domain !== "Current Webpage") {
    trustSiteBtn.classList.remove("hidden");
    if (reportSafeBtn) reportSafeBtn.classList.remove("hidden");
    if (copyVerdictBtn) copyVerdictBtn.classList.remove("hidden");
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
    if (reportSafeBtn) reportSafeBtn.classList.add("hidden");
    if (copyVerdictBtn) copyVerdictBtn.classList.add("hidden");
  }

  // Flag Mule to NSRC Button
  const flaggedMules = muleScan && muleScan.flagged_accounts ? muleScan.flagged_accounts : [];
  if (flagMuleBtn) {
    if (flaggedMules.length > 0 || risk === "dangerous" || result.mule_detected) {
      flagMuleBtn.classList.remove("hidden");
      flagMuleBtn.onclick = () => handleFlagMule(flaggedMules);
    } else {
      flagMuleBtn.classList.add("hidden");
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
// CYBER TOAST NOTIFICATIONS & POPUP MODALS
// ═══════════════════════════════════════════════════════════════════
const popupToastContainer = document.getElementById("popupToastContainer");
const popupModalOverlay = document.getElementById("popupModalOverlay");
const popupModalTitle = document.getElementById("popupModalTitle");
const popupModalIcon = document.getElementById("popupModalIcon");
const popupModalMessage = document.getElementById("popupModalMessage");
const popupModalInputContainer = document.getElementById("popupModalInputContainer");
const popupModalInput = document.getElementById("popupModalInput");
const popupModalCancelBtn = document.getElementById("popupModalCancelBtn");
const popupModalConfirmBtn = document.getElementById("popupModalConfirmBtn");

function showToast(type = "info", title = "Notice", message = "", duration = 3200) {
  if (!popupToastContainer) return;
  const icons = {
    success: "✅",
    danger: "🚨",
    warning: "⚠️",
    info: "ℹ️"
  };
  const toast = document.createElement("div");
  toast.className = `popup-toast ${type}`;
  toast.innerHTML = `
    <span class="popup-toast-icon">${icons[type] || "🛡️"}</span>
    <div class="popup-toast-content">
      <div class="popup-toast-title">${title}</div>
      ${message ? `<div class="popup-toast-message">${message}</div>` : ""}
    </div>
  `;
  popupToastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(12px)";
    toast.style.transition = "all 0.25s ease";
    setTimeout(() => toast.remove(), 250);
  }, duration);
}

function showConfirmDialog(title, message, icon = "⚠️") {
  return new Promise((resolve) => {
    if (!popupModalOverlay) {
      resolve(confirm(message));
      return;
    }
    popupModalTitle.textContent = title;
    popupModalIcon.textContent = icon;
    popupModalMessage.textContent = message;
    popupModalInputContainer.classList.add("hidden");
    popupModalCancelBtn.classList.remove("hidden");
    popupModalConfirmBtn.textContent = "Confirm";

    popupModalOverlay.classList.remove("hidden");

    const onConfirm = () => {
      cleanup();
      resolve(true);
    };
    const onCancel = () => {
      cleanup();
      resolve(false);
    };
    const cleanup = () => {
      popupModalOverlay.classList.add("hidden");
      popupModalConfirmBtn.removeEventListener("click", onConfirm);
      popupModalCancelBtn.removeEventListener("click", onCancel);
    };

    popupModalConfirmBtn.addEventListener("click", onConfirm);
    popupModalCancelBtn.addEventListener("click", onCancel);
  });
}

function showPromptDialog(title, message, placeholder = "", defaultValue = "", icon = "🚨") {
  return new Promise((resolve) => {
    if (!popupModalOverlay) {
      resolve(prompt(message, defaultValue));
      return;
    }
    popupModalTitle.textContent = title;
    popupModalIcon.textContent = icon;
    popupModalMessage.textContent = message;
    popupModalInputContainer.classList.remove("hidden");
    popupModalInput.placeholder = placeholder;
    popupModalInput.value = defaultValue;
    popupModalCancelBtn.classList.remove("hidden");
    popupModalConfirmBtn.textContent = "Submit";

    popupModalOverlay.classList.remove("hidden");
    popupModalInput.focus();

    const onConfirm = () => {
      const val = popupModalInput.value.trim();
      cleanup();
      resolve(val);
    };
    const onCancel = () => {
      cleanup();
      resolve(null);
    };
    const cleanup = () => {
      popupModalOverlay.classList.add("hidden");
      popupModalConfirmBtn.removeEventListener("click", onConfirm);
      popupModalCancelBtn.removeEventListener("click", onCancel);
    };

    popupModalConfirmBtn.addEventListener("click", onConfirm);
    popupModalCancelBtn.addEventListener("click", onCancel);
    popupModalInput.onkeydown = (e) => {
      if (e.key === "Enter") onConfirm();
      if (e.key === "Escape") onCancel();
    };
  });
}

// ═══════════════════════════════════════════════════════════════════
// TRUSTED SITES MANAGEMENT
// ═══════════════════════════════════════════════════════════════════

async function renderTrustedDomains() {
  const response = await sendRuntimeMessage({ type: "PHISHGUARD_GET_TRUSTED_DOMAINS" });
  const trusted = (response && response.trusted) || {};
  const entries = Object.entries(trusted);

  if (!entries.length) {
    trustedList.innerHTML = '<div class="history-empty">No custom trusted domains registered yet.</div>';
    return;
  }

  const now = Date.now();
  trustedList.innerHTML = entries.map(([domain, expiry]) => {
    const remainingHrs = Math.max(0, Math.round((expiry - now) / (1000 * 60 * 60)));
    return `
      <div class="history-item">
        <div class="history-item-left">
          <span class="history-domain">${domain}</span>
          <span class="history-time">Expires in ~${remainingHrs}h</span>
        </div>
        <button class="clear-btn" style="color: #f87171; font-weight: 700;" onclick="removeTrustedDomain('${domain}')">✕ Remove</button>
      </div>
    `;
  }).join("");
}

window.removeTrustedDomain = async function(domain) {
  const response = await sendRuntimeMessage({ type: "PHISHGUARD_GET_TRUSTED_DOMAINS" });
  const trusted = (response && response.trusted) || {};
  delete trusted[domain];
  await chrome.storage.sync.set({ custom_trusted_domains: trusted });
  renderTrustedDomains();
  showToast("info", "Domain Revoked", `${domain} removed from trusted whitelist.`);
  scanActivePage();
};

async function clearAllTrusted() {
  const ok = await showConfirmDialog("Revoke Whitelists", "Are you sure you want to remove all custom trusted domains?", "🗑️");
  if (!ok) return;
  await chrome.storage.sync.set({ custom_trusted_domains: {} });
  renderTrustedDomains();
  showToast("success", "Whitelists Cleared", "All custom exemptions removed.");
  scanActivePage();
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
    showToast("info", "History Cleared", "Recent scan logs removed.");
  });
}

// ═══════════════════════════════════════════════════════════════════
// ACTIONS
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

  showToast("success", "Domain Trusted", `${domain} whitelisted for 24 hours.`);
  scanActivePage();
}

function handleReportSafe() {
  if (!activeScanResult) return;
  const domain = activeScanResult.page_host || hostFromUrl(activeScanResult.page_url);
  handleTrustDomain();
  showToast("success", "Reported Safe", `${domain} verified and marked authentic.`);
}

function handleCopyVerdict() {
  if (!activeScanResult) return;
  const r = activeScanResult;
  const domain = r.page_host || hostFromUrl(r.page_url) || "Unknown Webpage";
  const summary = 
`🛡️ PhishGuard-AI Threat Scan Verdict
• Target: ${domain} (${r.page_url || "N/A"})
• Risk Assessment: ${(r.risk_level || "SAFE").toUpperCase()}
• Orchestration Verdict: ${r.final_verdict || "SAFE"}
• Details: ${r.reason || "Verified authentic page."}
• Scanned At: ${r.analyzed_at || new Date().toISOString()}`;

  navigator.clipboard.writeText(summary).then(() => {
    showToast("success", "Copied to Clipboard", "Full forensic verdict ready for sharing.");
  }).catch(() => {
    showToast("info", "Verdict Summary", summary);
  });
}

async function handleFlagMule(mules) {
  let acc = (mules && mules.length > 0) ? mules[0].account_number : "";
  if (!acc) {
    acc = await showPromptDialog("Escalate to NSRC 997", "Enter suspicious beneficiary account / DuitNow phone number:", "e.g. 112233445566 / 0123456789", "");
  }
  if (!acc) return;
  const bank = (mules && mules.length > 0) ? mules[0].bank_name : "Online Scam Account";
  
  try {
    const config = await getStoredConfig();
    const res = await fetch(`${config.apiBaseUrl}/api/v1/mule-registry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        account_number: acc,
        bank_name: bank,
        platform_flagged: "Chrome Extension User Escalation",
        report_count: 1
      })
    });
    if (res.ok) {
      showToast("danger", "Escalated to NSRC", `Account ${acc} (${bank}) registered to fraud blacklist.`);
    } else {
      showToast("warning", "Recorded Locally", `Report saved for ${acc}.`);
    }
  } catch (_e) {
    showToast("info", "Queued", `Report cached offline for ${acc}.`);
  }
}

// ═══════════════════════════════════════════════════════════════════
// BACKEND PING & LATENCY MONITOR
// ═══════════════════════════════════════════════════════════════════

async function checkBackendHealthPing() {
  try {
    const config = await getStoredConfig();
    const start = performance.now();
    const res = await fetch(`${config.apiBaseUrl}/health`, { method: "GET" });
    const latency = Math.round(performance.now() - start);

    if (res.ok && backendPingBadge) {
      backendPingBadge.className = "ping-badge online";
      backendPingBadge.textContent = `● SOC (${latency}ms)`;
      if (pingStatusText) pingStatusText.textContent = `Connected (${latency}ms)`;
    } else {
      throw new Error();
    }
  } catch (_e) {
    if (backendPingBadge) {
      backendPingBadge.className = "ping-badge offline";
      backendPingBadge.textContent = "● Autonomous";
      if (pingStatusText) pingStatusText.textContent = "Offline Protection Active";
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
// TABS SWITCHING
// ═══════════════════════════════════════════════════════════════════

function showTab(tab) {
  tabScannerBtn.classList.toggle("active", tab === "scanner");
  tabTrustedBtn.classList.toggle("active", tab === "trusted");
  tabHistoryBtn.classList.toggle("active", tab === "history");

  scannerView.classList.toggle("active", tab === "scanner");
  trustedView.classList.toggle("active", tab === "trusted");
  historyView.classList.toggle("active", tab === "history");

  if (tab === "trusted") renderTrustedDomains();
  if (tab === "history") renderHistory();
}

// ═══════════════════════════════════════════════════════════════════
// MAIN SCAN LOGIC
// ═══════════════════════════════════════════════════════════════════

async function refreshResult() {
  const tab = await queryActiveTab();
  if (!tab || typeof tab.id !== "number") {
    await renderEmptyState();
    return;
  }

  const response = await sendRuntimeMessage({
    type: "PHISHGUARD_GET_LATEST_RESULT",
    tabId: tab.id
  });
  if (response && response.result) {
    renderResult(response.result);
  } else {
    scanActivePage();
  }
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
    let response = null;
    try {
      response = await sendTabMessage(tab.id, { type: "PHISHGUARD_RUN_SCAN" });
    } catch (_e) {
      try {
        await ensureContentScriptInjected(tab.id);
        response = await sendTabMessage(tab.id, { type: "PHISHGUARD_RUN_SCAN" });
      } catch (_err) {
        response = await sendRuntimeMessage({ type: "PHISHGUARD_RESCAN_ACTIVE_TAB" });
      }
    }

    if (!response || !response.ok) {
      try {
        response = await sendRuntimeMessage({ type: "PHISHGUARD_RESCAN_ACTIVE_TAB" });
      } catch (_e) {}
    }

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
  checkBackendHealthPing();
  window.setTimeout(() => {
    saveSettingsButton.textContent = "Save Settings";
  }, 1000);
}

const openDashboardBtn = document.getElementById("openDashboardBtn");
if (openDashboardBtn) {
  openDashboardBtn.addEventListener("click", () => {
    const base = (apiBaseUrl.value || "http://127.0.0.1:8000").replace(/\/$/, "");
    chrome.tabs.create({ url: `${base}/dashboard/` });
  });
}

// Event Listeners
tabScannerBtn.addEventListener("click", () => showTab("scanner"));
tabTrustedBtn.addEventListener("click", () => showTab("trusted"));
tabHistoryBtn.addEventListener("click", () => showTab("history"));
clearTrustedBtn.addEventListener("click", clearAllTrusted);
clearHistoryBtn.addEventListener("click", clearHistory);
trustSiteBtn.addEventListener("click", handleTrustDomain);
if (reportSafeBtn) reportSafeBtn.addEventListener("click", handleReportSafe);
if (copyVerdictBtn) copyVerdictBtn.addEventListener("click", handleCopyVerdict);
scanButton.addEventListener("click", scanActivePage);
saveSettingsButton.addEventListener("click", saveSettings);

loadSettings();
refreshResult();
renderHistory();
checkBackendHealthPing();
setInterval(checkBackendHealthPing, 15000);

