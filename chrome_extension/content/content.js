const PHISHGUARD_TEXT_LIMIT = 30000;
const PHISHGUARD_DOM_LIMIT = 3000000;
const PHISHGUARD_BANNER_ID = "phishguard-ai-warning-banner";
const PHISHGUARD_HIGHLIGHT_CLASS = "phishguard-ai-mule-highlight";

function isSupportedPage() {
  return location.protocol === "http:" || location.protocol === "https:";
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

function showWarningBanner(result) {
  clearWarningBanner();
  highlightMuleAccounts(result);

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

function clearWarningBanner() {
  const existing = document.getElementById(PHISHGUARD_BANNER_ID);
  if (existing) {
    existing.remove();
  }
  clearMuleHighlights();
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
