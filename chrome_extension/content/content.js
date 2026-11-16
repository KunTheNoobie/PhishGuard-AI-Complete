const PHISHGUARD_TEXT_LIMIT = 30000;
const PHISHGUARD_DOM_LIMIT = 3000000;
const PHISHGUARD_BANNER_ID = "phishguard-ai-warning-banner";
const PHISHGUARD_HIGHLIGHT_CLASS = "phishguard-ai-mule-highlight";

function isSupportedPage() {
  return location.protocol === "http:" || location.protocol === "https:" || location.protocol === "file:";
}

function extractDeepText(rootNode, visited = new Set()) {
  if (!rootNode || visited.has(rootNode)) return "";
  visited.add(rootNode);

  const textParts = [];
  try {
    const walker = document.createTreeWalker(
      rootNode,
      NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    while ((node = walker.nextNode())) {
      if (node.nodeType === Node.TEXT_NODE) {
        const val = (node.nodeValue || "").trim();
        if (val) textParts.push(val);
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        const el = node;
        // Extract input placeholders, values, and accessibility labels
        if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") {
          if (el.placeholder) textParts.push(el.placeholder);
          if (el.value && el.type !== "password") textParts.push(el.value);
          if (el.getAttribute("aria-label")) textParts.push(el.getAttribute("aria-label"));
        } else if (el.tagName === "BUTTON") {
          if (el.innerText) textParts.push(el.innerText.trim());
        } else if (el.tagName === "IMG") {
          if (el.alt) textParts.push(el.alt);
        }

        // Recursively traverse open Shadow DOM roots (used in modern SPAs & Web Components)
        if (el.shadowRoot) {
          textParts.push(extractDeepText(el.shadowRoot, visited));
        }

        // Traverse accessible same-origin iframe documents
        if (el.tagName === "IFRAME") {
          try {
            if (el.contentDocument && el.contentDocument.body) {
              textParts.push(extractDeepText(el.contentDocument.body, visited));
            }
          } catch (_e) {}
        }
      }
    }
  } catch (_e) {}

  return textParts.join(" ");
}

function getVisibleText() {
  if (!document.body) return "";
  try {
    const deepText = extractDeepText(document.body);
    const standardText = document.body.innerText || "";
    const combined = `${standardText} ${deepText}`;
    return combined.replace(/\s+/g, " ").trim().slice(0, PHISHGUARD_TEXT_LIMIT);
  } catch (_e) {
    const fallback = document.body ? document.body.innerText : "";
    return fallback.replace(/\s+/g, " ").trim().slice(0, PHISHGUARD_TEXT_LIMIT);
  }
}

function collectPageContext() {
  const metaDesc = document.querySelector("meta[name='description']")?.getAttribute("content") || "";
  const ogTitle = document.querySelector("meta[property='og:title']")?.getAttribute("content") || "";
  const pageTitle = document.title || ogTitle || "";

  let domStr = "";
  try {
    domStr = document.documentElement ? document.documentElement.outerHTML.slice(0, PHISHGUARD_DOM_LIMIT) : "";
  } catch (_e) {
    domStr = document.body ? document.body.innerHTML : "";
  }

  return {
    url: location.href,
    title: pageTitle,
    metaDescription: metaDesc,
    visibleText: `${pageTitle} ${metaDesc} ${getVisibleText()}`.trim().slice(0, PHISHGUARD_TEXT_LIMIT),
    domContent: domStr
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

  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const muleScan = result && result.mule_scan;
  const semantic = result && result.semantic_analysis;
  const backend = (result && result.semantic) || {};
  const visual = (result && result.visual) || null;
  const flagged = (muleScan && Array.isArray(muleScan.flagged_accounts)) ? muleScan.flagged_accounts : [];
  const accounts = flagged.map((a) => a.account_number).join(", ");
  const rule = backend.decision_rule ? String(backend.decision_rule).replace(/_/g, " ") : "";
  const indicators = Array.isArray(backend.threat_indicators) ? backend.threat_indicators.slice(0, 3) : [];
  const logos = visual && Array.isArray(visual.detected_logos) ? visual.detected_logos : [];
  const visualText = logos.length
    ? logos.map((l) => esc(l.brand || l.label || l.class_name || "logo")).join(", ") + (visual.risk_level ? ` · ${esc(visual.risk_level)}` : "")
    : (visual && visual.risk_level ? esc(visual.risk_level) : "No brand logo detected");

  const pill = (text, tone) => {
    const tones = { red: ["rgba(255,59,48,0.12)", "#D70015"], green: ["rgba(52,199,89,0.14)", "#248A3D"],
                    amber: ["rgba(255,159,10,0.16)", "#B25000"], grey: ["rgba(118,118,128,0.12)", "#3A3A3C"] };
    const [bg, fg] = tones[tone] || tones.grey;
    return `<span style="display:inline-block;padding:4px 11px;border-radius:999px;background:${bg};color:${fg};font-size:12px;font-weight:600;white-space:nowrap;">${text}</span>`;
  };
  const row = (label, value) => `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:16px;padding:11px 0;border-bottom:1px solid rgba(0,0,0,0.06);">
          <span style="font-size:13px;color:#3A3A3C;">${label}</span><span style="text-align:right;">${value}</span>
        </div>`;
  const bertPct = semantic ? `${(semantic.confidence * 100).toFixed(1)}% ${esc(semantic.label)}` : "Not available";

  overlay.innerHTML = `
    <div style="max-width: 560px; width: 92%; background: rgba(255,255,255,0.86); color: #1D1D1F; border: 1px solid rgba(0,0,0,0.08); border-radius: 20px; padding: 28px 28px 22px; box-shadow: 0 30px 80px rgba(0,0,0,0.22); text-align: left; font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', 'Segoe UI', Arial, sans-serif; backdrop-filter: saturate(180%) blur(30px); -webkit-backdrop-filter: saturate(180%) blur(30px); letter-spacing: -0.01em;">
      <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 14px;">
        <div style="width: 46px; height: 46px; border-radius: 14px; background: rgba(255,59,48,0.12); display: flex; align-items: center; justify-content: center;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#FF3B30" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l9 4v6c0 5-3.8 9.3-9 10-5.2-.7-9-5-9-10V6l9-4z"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16.5" r="0.6" fill="#FF3B30"/></svg>
        </div>
        <div>
          <h2 style="margin: 0; font-size: 21px; font-weight: 700; color: #1D1D1F; letter-spacing: -0.02em;">Deceptive site blocked</h2>
          <span style="font-size: 13px; color: #6E6E73;">PhishGuard-AI stopped this page before it loaded</span>
        </div>
      </div>
      <p style="font-size: 14px; line-height: 1.55; color: #3A3A3C; margin: 0 0 14px;">
        <strong style="color:#1D1D1F;">${esc(location.hostname)}</strong> shows signs of a financial phishing or mule-account scam. Do not enter passwords, TAC codes or card details, and do not transfer money.
      </p>
      <div style="background: #FFFFFF; border: 1px solid rgba(0,0,0,0.08); border-radius: 14px; padding: 2px 16px; margin-bottom: 14px;">
        ${row("Verdict", pill("BLOCK_RENDER", "red") + (rule ? " " + pill(esc(rule), "grey") : ""))}
        ${row("BERT URL model", pill(bertPct, semantic && semantic.is_malicious ? "red" : "green"))}
        ${row("Semakmule registry", accounts ? pill("Match: " + esc(accounts), "red") : pill("No registered account", "green"))}
        ${row("Brand / visual check", pill(visualText, logos.length ? "amber" : "grey"))}
        ${row("Risk score", pill(backend.risk_score != null ? Number(backend.risk_score).toFixed(2) : "—", "red"))}
      </div>
      ${indicators.length ? `<ul style="margin: 0 0 16px; padding-left: 18px; font-size: 12.5px; line-height: 1.55; color: #6E6E73;">${indicators.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` : ""}
      <div style="display: flex; gap: 10px; align-items: center; justify-content: flex-end; flex-wrap: wrap;">
        <button id="phishguard-report-btn" style="background: #FFFFFF; border: 1px solid rgba(0,0,0,0.12); color: #0071E3; padding: 9px 16px; border-radius: 999px; font-size: 13px; cursor: pointer; font-weight: 600;">
          Report to SOC
        </button>
        <button id="phishguard-proceed-btn" style="background: transparent; border: none; color: #6E6E73; padding: 9px 12px; border-radius: 999px; font-size: 13px; cursor: pointer; font-weight: 500;">
          Proceed anyway
        </button>
        <button id="phishguard-safety-btn" style="background: #0071E3; border: none; color: #FFFFFF; padding: 10px 22px; border-radius: 999px; font-size: 14px; font-weight: 600; cursor: pointer; box-shadow: 0 1px 2px rgba(0,0,0,0.1);">
          Back to safety
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
    backgroundColor: "rgba(245, 245, 247, 0.92)",
    backdropFilter: "blur(18px)",
    zIndex: "2147483647",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    boxSizing: "border-box"
  });

  const targetParent = document.body || document.documentElement;
  if (targetParent) {
    targetParent.appendChild(overlay);
  }

  const safetyBtn = document.getElementById("phishguard-safety-btn");
  if (safetyBtn) {
    safetyBtn.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "about:blank";
      }
    });
  }

  const reportBtn = document.getElementById("phishguard-report-btn");
  if (reportBtn) {
    reportBtn.addEventListener("click", () => {
      const acct = flagged.length ? flagged[0].account_number : window.prompt("Account number or DuitNow ID shown on this page:", "");
      if (!acct) return;
      reportBtn.disabled = true;
      reportBtn.textContent = "Sending…";
      try {
        chrome.runtime.sendMessage({
          type: "PHISHGUARD_REPORT_MULE",
          accountNumber: acct,
          bankName: flagged.length ? flagged[0].bank_name : "Unknown",
          pageUrl: location.href
        }, (resp) => {
          reportBtn.textContent = resp && resp.ok ? "Reported for review" : "Report failed";
        });
      } catch (_e) {
        reportBtn.textContent = "Report failed";
      }
    });
  }

  const proceedBtn = document.getElementById("phishguard-proceed-btn");
  if (proceedBtn) {
    proceedBtn.addEventListener("click", () => {
      try {
        chrome.runtime.sendMessage({
          type: "PHISHGUARD_TRUST_DOMAIN",
          domain: location.hostname,
          hours: 168
        });
      } catch (_e) {}
      overlay.remove();
      clearWarningBanner();
    });
  }
}

function showWarningBanner(result) {
  if (!result) return;
  const isBlock = result.risk_level === "dangerous" || result.final_verdict === "BLOCK_RENDER" || (result.mule_scan && result.mule_scan.mule_detected);
  if (isBlock) {
    showFullScreenBlockScreen(result);
    return;
  }
  if (result.risk_level === "suspicious") {
    showTopBanner(result);
  }
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

  const parent = document.body || document.documentElement;
  if (parent) {
    parent.appendChild(banner);
  }
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

// ═══════════════════════════════════════════════════════════════════
// AUTONOMOUS REAL-TIME BACKGROUND AUTO-SCAN ON PAGE LOAD
// ═══════════════════════════════════════════════════════════════════
function autoScanOnPageLoad() {
  if (!isSupportedPage()) return;
  if (location.protocol !== "http:" && location.protocol !== "https:" && location.protocol !== "file:") return;

  requestVisualAnalysis()
    .then((response) => {
      if (response && response.result) {
        showWarningBanner(response.result);
      }
    })
    .catch((_err) => {});
}

// Automatically trigger autonomous scan immediately and on load
if (document.readyState === "complete") {
  autoScanOnPageLoad();
} else {
  window.addEventListener("load", autoScanOnPageLoad);
  document.addEventListener("DOMContentLoaded", autoScanOnPageLoad);
}
setTimeout(autoScanOnPageLoad, 400);
