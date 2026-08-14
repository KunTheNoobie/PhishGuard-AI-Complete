const PHISHGUARD_TEXT_LIMIT = 30000;
const PHISHGUARD_DOM_LIMIT = 3000000;
const PHISHGUARD_BANNER_ID = "phishguard-ai-warning-banner";
const PHISHGUARD_HIGHLIGHT_CLASS = "phishguard-ai-mule-highlight";

function isSupportedPage() {
  return location.protocol === "http:" || location.protocol === "https:" || location.protocol === "file:";
}

function getVisibleText() {
  const text = document.body ? document.body.innerText : "";
  return text.replace(/\s+/g, " ").trim().slice(0, PHISHGUARD_TEXT_LIMIT);
}

function collectPageContext() {
  return {
    url: location.href,
    title: document.title || "",
    visibleText: getVisibleText(),
    domContent: document.documentElement.outerHTML.slice(0, PHISHGUARD_DOM_LIMIT)
  };
}

function requestVisualAnalysis() {
  if (!isSupportedPage()) {
    return Promise.resolve({
      ok: false,
      error: "Only HTTP and HTTPS pages can be scanned."
    });
  }

  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({
      type: "PHISHGUARD_ANALYZE_PAGE",
      payload: collectPageContext()
    }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

function warningTextForRisk(result) {
  if (result.risk_level === "dangerous") {
    return "Potential phishing page detected. Do not enter login credentials or banking information.";
  }

  return "This page may be suspicious. A financial logo was detected but the domain does not match the official domain.";
}

const PHISHGUARD_BLOCK_SCREEN_ID = "phishguard-ai-fullscreen-block";

function showFullScreenBlockScreen(result) {
  clearWarningBanner();
  highlightMuleAccounts(result);
  highlightScamKeywords();

  const existingBlock = document.getElementById(PHISHGUARD_BLOCK_SCREEN_ID);
  if (existingBlock) existingBlock.remove();

  const overlay = document.createElement("div");
  overlay.id = PHISHGUARD_BLOCK_SCREEN_ID;
  overlay.setAttribute("role", "alertdialog");

  const muleScan = result && result.mule_scan;
  const semantic = result && result.semantic_analysis;
  const accounts = (muleScan && muleScan.flagged_accounts) ? muleScan.flagged_accounts.map(a => a.account_number).join(", ") : "";

  overlay.innerHTML = `
    <div style="max-width: 580px; width: 90%; background: #0f172a; color: #f8fafc; border: 2px solid #ef4444; border-radius: 12px; padding: 32px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); text-align: left; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
      <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 20px;">
        <div style="background: #ef4444; color: white; width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold;">!</div>
        <div>
          <h2 style="margin: 0; font-size: 20px; color: #f87171; font-weight: 800;">Dangerous Phishing Page Blocked</h2>
          <span style="font-size: 13px; color: #94a3b8;">Protected by PhishGuard-AI Multi-Modal Engine</span>
        </div>
      </div>
      <p style="font-size: 14px; line-height: 1.6; color: #cbd5e1; margin-bottom: 18px;">
        PhishGuard-AI has intercepted and blocked access to this page (<strong>${location.hostname}</strong>). It exhibits high-confidence financial phishing patterns designed to steal credentials or funds.
      </p>
      <div style="background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin-bottom: 24px; font-size: 13px;">
        ${semantic ? `<div>• <strong>BERT Semantic Confidence:</strong> ${(semantic.confidence * 100).toFixed(1)}% (${semantic.label})</div>` : ''}
        ${accounts ? `<div>• <strong>Flagged Mule Bank Account(s):</strong> ${accounts}</div>` : ''}
        <div>• <strong>Verdict:</strong> BLOCK_RENDER (Automated Safety Enforcement)</div>
      </div>
      <div style="display: flex; gap: 12px; align-items: center; justify-content: flex-end; flex-wrap: wrap;">
        <button id="phishguard-proceed-btn" style="background: transparent; border: 1px solid #475569; color: #94a3b8; padding: 9px 16px; border-radius: 6px; font-size: 13px; cursor: pointer; font-weight: 600;">
          Proceed Anyway (Unsafe)
        </button>
        <button id="phishguard-safety-btn" style="background: #ef4444; border: none; color: white; padding: 10px 20px; border-radius: 6px; font-size: 14px; font-weight: 700; cursor: pointer; box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);">
          Back to Safety
        </button>
      </div>
    </div>
  `;

  Object.assign(overlay.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100vw",
    height: "100vh",
    backgroundColor: "rgba(2, 6, 23, 0.95)",
    backdropFilter: "blur(8px)",
    zIndex: "2147483647",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    boxSizing: "border-box"
  });

  document.documentElement.appendChild(overlay);

  document.getElementById("phishguard-safety-btn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  });

  document.getElementById("phishguard-proceed-btn").addEventListener("click", () => {
    overlay.remove();
    showTopBanner(result);
  });
}

function showWarningBanner(result) {
  if (result.risk_level === "dangerous" || result.final_verdict === "BLOCK_RENDER") {
    showFullScreenBlockScreen(result);
    return;
  }
  showTopBanner(result);
}

function showTopBanner(result) {
  clearWarningBanner();
  highlightMuleAccounts(result);
  highlightScamKeywords();

  const banner = document.createElement("div");
  banner.id = PHISHGUARD_BANNER_ID;
  banner.setAttribute("role", "alert");
  const isDangerous = result.risk_level === "dangerous";

  const label = document.createElement("strong");
  label.textContent = "PhishGuard-AI";

  const message = document.createElement("span");
  message.textContent = warningTextForRisk(result);

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.setAttribute("aria-label", "Close warning");
  closeButton.textContent = "X";
  closeButton.addEventListener("click", clearWarningBanner);

  banner.append(label, message, closeButton);

  Object.assign(banner.style, {
    position: "fixed",
    top: "0",
    left: "0",
    right: "0",
    zIndex: "2147483647",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "14px",
    padding: "10px 16px",
    background: isDangerous ? "#b91c1c" : "#f59e0b",
    color: isDangerous ? "#ffffff" : "#111827",
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
    fontSize: "15px",
    fontWeight: "700",
    lineHeight: "1.4",
    textAlign: "center",
    boxShadow: "0 4px 14px rgba(0, 0, 0, 0.25)"
  });

  Object.assign(label.style, {
    flex: "0 0 auto",
    letterSpacing: "0",
    fontWeight: "800"
  });

  Object.assign(message.style, {
    maxWidth: "900px"
  });

  Object.assign(closeButton.style, {
    flex: "0 0 auto",
    width: "26px",
    height: "26px",
    border: "1px solid rgba(255, 255, 255, 0.65)",
    borderRadius: "6px",
    background: isDangerous ? "rgba(255, 255, 255, 0.14)" : "rgba(17, 24, 39, 0.1)",
    color: "inherit",
    cursor: "pointer",
    fontWeight: "800",
    lineHeight: "1"
  });

  document.documentElement.appendChild(banner);
}

const PHISHGUARD_KEYWORD_CLASS = "phishguard-ai-keyword-highlight";
const PHISHGUARD_CRED_WARN_ID = "phishguard-ai-cred-warning";

const SUSPICIOUS_KEYWORDS = [
  // English
  "urgent verification", "immediate verification", "account suspension", "account suspended",
  "flagged for suspicious", "pdrm verification", "authorized pdrm", "transfer verification",
  "avoid account closure", "avoid suspension", "verify account now", "update login details",
  "unauthorized login", "security alert", "temporary freeze", "reactivate account",
  "transfer deposit", "security deposit", "verify immediately", "claim e-wallet credit",
  // Bahasa Melayu & Manglish
  "akaun digantung", "akaun disekat", "tindakan segera", "pengesahan keselamatan",
  "saman tertunggak", "pdrm saman", "tuntutan bantuan tunai", "bantuan e-wallet",
  "kemaskini maklumat", "tukar kata laluan", "bayaran deposit", "cukai lhdn tertunggak",
  "sekat kad debit", "log masuk tidak sah", "pengesahan maybank", "pengesahan cimb",
  "kemaskini perbankan", "tebus hadiah", "akaun anda dibekukan"
];

// Proactive Password & OTP/TAC Credential Interceptor
function initCredentialInterceptor() {
  const host = location.hostname.toLowerCase().replace(/^www\./, "");
  const officialDomains = [
    "maybank2u.com.my", "maybank.com", "cimbclicks.com.my", "cimb.com.my",
    "pbebank.com", "pbebank.com.my", "rhbgroup.com", "rhbnow.com", "hlb.com.my"
  ];
  const isOfficial = officialDomains.some(d => host === d || host.endsWith("." + d));
  if (isOfficial) return; // Legitimate bank domain

  const credInputs = document.querySelectorAll(
    'input[type="password"], input[name*="pass" i], input[name*="pin" i], input[name*="tac" i], input[name*="otp" i], input[placeholder*="TAC" i], input[placeholder*="OTP" i], input[placeholder*="PIN" i]'
  );

  credInputs.forEach(input => {
    input.addEventListener("focus", () => {
      let warn = document.getElementById(PHISHGUARD_CRED_WARN_ID);
      if (!warn) {
        warn = document.createElement("div");
        warn.id = PHISHGUARD_CRED_WARN_ID;
        warn.innerHTML = "⚠️ <strong>PhishGuard Warning:</strong> Unverified Domain. Never enter online banking passwords or TAC/OTP codes on third-party pages.";
        Object.assign(warn.style, {
          position: "absolute",
          background: "#1e1b4b",
          color: "#f87171",
          border: "1px solid #ef4444",
          borderRadius: "6px",
          padding: "6px 12px",
          fontSize: "12px",
          fontFamily: "-apple-system, sans-serif",
          boxShadow: "0 8px 16px rgba(0,0,0,0.5)",
          zIndex: "2147483646",
          pointerEvents: "none",
          transition: "opacity 0.2s ease"
        });
        document.body.appendChild(warn);
      }
      const rect = input.getBoundingClientRect();
      warn.style.top = `${window.scrollY + rect.top - 38}px`;
      warn.style.left = `${window.scrollX + rect.left}px`;
      warn.style.display = "block";
      warn.style.opacity = "1";
    });

    input.addEventListener("blur", () => {
      const warn = document.getElementById(PHISHGUARD_CRED_WARN_ID);
      if (warn) {
        warn.style.opacity = "0";
        setTimeout(() => { if (warn) warn.style.display = "none"; }, 200);
      }
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initCredentialInterceptor);
} else {
  initCredentialInterceptor();
}


function clearKeywordHighlights() {
  const highlights = document.querySelectorAll(`span.${PHISHGUARD_KEYWORD_CLASS}`);
  for (const highlight of highlights) {
    const text = document.createTextNode(highlight.textContent || "");
    highlight.replaceWith(text);
  }
}

function highlightScamKeywords() {
  clearKeywordHighlights();
  if (!document.body) return;

  const escaped = SUSPICIOUS_KEYWORDS.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(`(${escaped.join("|")})`, "gi");
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];

  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!shouldSkipTextNode(node) && pattern.test(node.nodeValue || "")) {
      nodes.push(node);
    }
    pattern.lastIndex = 0;
  }

  for (const node of nodes) {
    const text = node.nodeValue || "";
    const fragment = document.createDocumentFragment();
    let lastIndex = 0;
    pattern.lastIndex = 0;
    let match = pattern.exec(text);

    while (match) {
      if (match.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }

      const span = document.createElement("span");
      span.className = PHISHGUARD_KEYWORD_CLASS;
      span.textContent = match[0];
      span.title = "PhishGuard AI: High-risk Social Engineering Phrasing Detected";
      Object.assign(span.style, {
        background: "rgba(239, 68, 68, 0.18)",
        color: "#b91c1c",
        borderBottom: "2px wavy #ef4444",
        padding: "0 2px",
        fontWeight: "600",
        cursor: "help"
      });
      fragment.appendChild(span);
      lastIndex = match.index + match[0].length;
      match = pattern.exec(text);
    }

    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    node.replaceWith(fragment);
  }
}

function clearWarningBanner() {
  const existing = document.getElementById(PHISHGUARD_BANNER_ID);
  if (existing) existing.remove();
  const existingBlock = document.getElementById(PHISHGUARD_BLOCK_SCREEN_ID);
  if (existingBlock) existingBlock.remove();
  clearMuleHighlights();
  clearKeywordHighlights();
}

function getFlaggedAccountNumbers(result) {
  const muleScan = result && result.mule_scan;
  if (!muleScan || !Array.isArray(muleScan.flagged_accounts)) {
    return [];
  }
  return muleScan.flagged_accounts
    .map((account) => String(account.account_number || "").trim())
    .filter(Boolean);
}

function clearMuleHighlights() {
  const highlights = document.querySelectorAll(`span.${PHISHGUARD_HIGHLIGHT_CLASS}`);
  for (const highlight of highlights) {
    const text = document.createTextNode(highlight.textContent || "");
    highlight.replaceWith(text);
  }
}

function shouldSkipTextNode(node) {
  const parent = node.parentElement;
  if (!parent) {
    return true;
  }
  const tag = parent.tagName.toLowerCase();
  return ["script", "style", "textarea", "input", "select", "option"].includes(tag) ||
    parent.closest(`#${PHISHGUARD_BANNER_ID}`) ||
    parent.closest(`.${PHISHGUARD_HIGHLIGHT_CLASS}`);
}

function highlightMuleAccounts(result) {
  clearMuleHighlights();
  const accounts = getFlaggedAccountNumbers(result);
  if (!accounts.length || !document.body) {
    return;
  }

  const escaped = accounts
    .sort((a, b) => b.length - a.length)
    .map((account) => account.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(`\\b(${escaped.join("|")})\\b`, "g");
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];

  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!shouldSkipTextNode(node) && pattern.test(node.nodeValue || "")) {
      nodes.push(node);
    }
    pattern.lastIndex = 0;
  }

  for (const node of nodes) {
    const text = node.nodeValue || "";
    const fragment = document.createDocumentFragment();
    let lastIndex = 0;
    pattern.lastIndex = 0;
    let match = pattern.exec(text);

    while (match) {
      if (match.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }

      const span = document.createElement("span");
      span.className = PHISHGUARD_HIGHLIGHT_CLASS;
      span.textContent = match[0];
      Object.assign(span.style, {
        background: "#fde68a",
        color: "#7f1d1d",
        border: "2px solid #dc2626",
        borderRadius: "4px",
        padding: "1px 3px",
        fontWeight: "700"
      });
      fragment.appendChild(span);
      lastIndex = match.index + match[0].length;
      match = pattern.exec(text);
    }

    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    node.replaceWith(fragment);
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "PHISHGUARD_RUN_SCAN") {
    requestVisualAnalysis()
      .then((response) => {
        sendResponse(response || {
          ok: false,
          error: "No scan response was returned."
        });
      })
      .catch((error) => {
        sendResponse({
          ok: false,
          error: error.message || "Scan failed."
        });
      });
    return true;
  }

  if (message.type === "PHISHGUARD_SHOW_WARNING") {
    showWarningBanner(message.result);
    return false;
  }

  if (message.type === "PHISHGUARD_CLEAR_WARNING") {
    clearWarningBanner();
    return false;
  }

  return false;
});

// Screenshot capture needs the activeTab grant, so scan only after user action.
