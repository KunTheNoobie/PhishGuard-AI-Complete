/*
 * PhishGuard-AI — content script.
 *
 * 1. Collects the page (URL, HTML, visible text) and sends it to the service worker.
 * 2. Shows the verdict: a full-page block screen (BLOCK_RENDER), an amber
 *    "not secure" banner (WARNING) or nothing (SAFE).
 *
 * The UI lives in a closed Shadow DOM, so the page's own CSS cannot restyle,
 * hide or overlap it, and all server text is inserted with textContent.
 * Values typed into form fields are never collected.
 */
(() => {
  "use strict";

  // Injected again by "Re-scan": reuse the running instance.
  if (window.__phishguardScan) { window.__phishguardScan(); return; }

  const TEXT_LIMIT = 30000;
  const HTML_LIMIT = 3000000;
  const HOST_ID = "phishguard-ai-root";

  function collectPage() {
    const root = document.documentElement;
    return {
      url: location.href,
      title: document.title || "",
      html: root ? root.outerHTML.slice(0, HTML_LIMIT) : "",
      text: ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, TEXT_LIMIT),
    };
  }

  function scan() {
    chrome.runtime.sendMessage({ type: "PG_PAGE", page: collectPage() }).catch(() => {});
  }
  window.__phishguardScan = scan;

  // Single-page apps change the address without reloading: scan again when it changes.
  let lastUrl = location.href;
  setInterval(() => {
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    setTimeout(scan, 800);
  }, 1000);

  /* ── Shadow-DOM host ── */
  function mount() {
    let host = document.getElementById(HOST_ID);
    if (host) host.remove();
    host = document.createElement("div");
    host.id = HOST_ID;
    host.style.cssText = "all: initial; position: fixed; z-index: 2147483647; inset: 0 0 auto 0;";
    (document.body || document.documentElement).appendChild(host);
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = CSS;
    shadow.appendChild(style);
    return { host, shadow };
  }

  function unmount() {
    const host = document.getElementById(HOST_ID);
    if (host) host.remove();
    document.documentElement.style.removeProperty("overflow");
  }

  function h(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = String(text);
    return node;
  }

  const pct = (x) => `${Math.round((Number(x) || 0) * 100)}%`;

  /* ── Red block screen ── */
  function showBlock(r) {
    const { host, shadow } = mount();
    host.style.inset = "0";
    document.documentElement.style.setProperty("overflow", "hidden", "important");

    const wrap = h("div", "screen");
    const card = h("div", "card");
    const head = h("div", "head");
    head.append(h("div", "badge", "!"));
    const titles = h("div", "titles");
    titles.append(h("div", "eyebrow", "PhishGuard-AI blocked this page"), h("h1", "", r.headline || "Dangerous page"));
    head.append(titles);

    const site = h("p", "site");
    site.append("Website: ", h("strong", "", r.hostname || location.hostname));
    const explain = h("p", "explain", r.explanation || "");

    const reasons = h("ul", "reasons");
    (r.reasons || []).filter((x) => x.severity === "high" || x.severity === "medium").slice(0, 4)
      .forEach((x) => { const li = h("li", x.severity); li.append(h("span", "dot"), h("span", "", x.text)); reasons.append(li); });

    const facts = h("dl", "facts");
    const bert = r.bert || {};
    const mule = r.mule || {};
    const visual = r.visual || null;
    [
      ["Rule", r.rule || "—"],
      ["AI URL model", bert.skipped ? "skipped" : `${pct(bert.phishing_probability)} phishing`],
      ["Mule registry", (mule.flagged_accounts || []).length ? `match: ${mule.flagged_accounts.map((a) => a.account_number).join(", ")}` : "no match"],
      ["Logo check", visual && visual.status === "ok" ? (visual.detected_logos || []).map((d) => d.brand).join(", ") || "no bank logo" : "not run"],
      ["Connection", (r.scheme || location.protocol.replace(":", "")) === "https" ? "HTTPS (encrypted)" : "HTTP (not encrypted)"],
      ["Risk score", pct(r.risk_score)],
    ].forEach(([k, v]) => { facts.append(h("dt", "", k), h("dd", "", v)); });

    const actions = h("div", "actions");
    const back = h("button", "primary", "← Back to safety");
    back.addEventListener("click", () => { if (history.length > 1) history.back(); else location.href = "about:blank"; });
    const report = h("button", "secondary", "Report to SOC");
    report.addEventListener("click", () => {
      const flagged = (mule.flagged_accounts || [])[0];
      const extracted = (mule.accounts_extracted || [])[0];
      const account = flagged ? flagged.account_number : extracted || window.prompt("Bank account or DuitNow number shown on this page:", "");
      if (!account) return;
      report.disabled = true;
      report.textContent = "Sending…";
      chrome.runtime.sendMessage({
        type: "PG_REPORT_MULE", accountNumber: account, bankName: flagged ? flagged.bank_name : "Unknown", pageUrl: location.href,
      }).then((resp) => { report.textContent = resp && resp.ok ? "Reported for review" : "Report failed"; })
        .catch(() => { report.textContent = "Report failed"; });
    });
    const proceed = h("button", "link", "Proceed anyway (unsafe)");
    proceed.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "PG_ALLOW_SITE", host: location.hostname }).catch(() => {});
      unmount();
    });
    actions.append(back, report, proceed);

    card.append(head, site, explain, reasons, facts, actions);
    wrap.append(card);
    shadow.append(wrap);
    back.focus();
  }

  /* ── Amber warning banner ── */
  function showWarning(r) {
    const { shadow } = mount();
    const bar = h("div", "banner");
    const text = h("div", "btext");
    text.append(h("strong", "", r.headline || "Be careful on this page"), h("span", "", r.explanation || ""));
    const close = h("button", "close", "Dismiss");
    close.addEventListener("click", unmount);
    bar.append(h("div", "bicon", "!"), text, close);
    shadow.append(bar);
  }

  /* ── Green corner toast for safe sites (can be switched off in the popup) ── */
  async function showSafe(r) {
    let enabled = true;
    try { enabled = (await chrome.storage.local.get({ showSafeToast: true })).showSafeToast !== false; } catch (_e) { /* keep default */ }
    if (!enabled) { unmount(); return; }
    const { host, shadow } = mount();
    host.style.inset = "auto 16px 16px auto";
    const toast = h("div", "toast");
    const text = h("div", "ttext");
    text.append(h("strong", "", "PhishGuard-AI \u2022 Verified Safe"), h("span", "", r.hostname || location.hostname));
    toast.append(h("div", "tick", "\u2713"), text);
    shadow.append(toast);
    setTimeout(() => toast.classList.add("out"), 3000);
    setTimeout(unmount, 3500);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "PG_SHOW") return;
    const r = msg.result || {};
    if (r.allowed_by_user) { unmount(); return; }
    if (r.verdict === "BLOCK_RENDER") showBlock(r);
    else if (r.verdict === "WARNING") showWarning(r);
    else if (r.verdict === "SAFE") showSafe(r);
    else unmount();
  });

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .screen { position: fixed; inset: 0; display: grid; place-items: center; padding: 16px; overflow-y: auto;
      background: rgba(7, 11, 22, 0.97); }
    .card { width: min(640px, 100%); max-height: calc(100vh - 32px); overflow-y: auto; background: #111827; color: #e6eaf2;
      border: 1px solid #3b1d24; border-top: 4px solid #ef4444; border-radius: 14px; padding: 26px 28px;
      box-shadow: 0 30px 80px rgba(0, 0, 0, 0.6); }
    .head { display: flex; gap: 16px; align-items: center; }
    .badge { flex: 0 0 48px; height: 48px; border-radius: 12px; display: grid; place-items: center;
      background: rgba(239, 68, 68, 0.15); color: #f87171; font-size: 26px; font-weight: 800; }
    .titles { min-width: 0; }
    .eyebrow { color: #f87171; font-size: 12px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
    h1 { margin: 4px 0 0; font-size: 22px; line-height: 1.25; color: #f8fafc; }
    .site { margin: 16px 0 6px; color: #94a3b8; font-size: 14px; overflow-wrap: anywhere; }
    .site strong { color: #f8fafc; }
    .explain { margin: 0 0 14px; color: #cbd5e1; font-size: 14px; line-height: 1.6; overflow-wrap: anywhere; }
    .reasons { list-style: none; margin: 0 0 16px; padding: 0; display: flex; flex-direction: column; gap: 8px; }
    .reasons li { display: grid; grid-template-columns: 14px 1fr; gap: 8px; color: #e2e8f0; font-size: 13.5px; line-height: 1.5; overflow-wrap: anywhere; }
    .dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 7px; background: #f59e0b; }
    .high .dot { background: #ef4444; }
    .facts { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0 0 20px; padding: 14px 16px;
      background: #0b1120; border: 1px solid #243047; border-radius: 10px; font-size: 13px; }
    .facts dt { color: #94a3b8; }
    .facts dd { margin: 0; color: #e6eaf2; overflow-wrap: anywhere; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    button { font-size: 14px; font-weight: 700; border-radius: 9px; cursor: pointer; padding: 10px 18px; border: 1px solid transparent; white-space: nowrap; }
    .primary { background: #ef4444; color: #fff; }
    .primary:hover { background: #dc2626; }
    .secondary { background: #172033; color: #e6eaf2; border-color: #33415c; }
    .secondary:disabled { opacity: 0.7; cursor: default; }
    .link { background: none; color: #94a3b8; padding: 10px 6px; font-weight: 600; text-decoration: underline; margin-left: auto; }
    .banner { position: fixed; top: 0; left: 0; right: 0; display: flex; align-items: center; gap: 12px; padding: 10px 16px;
      background: #1f1608; color: #fde68a; border-bottom: 2px solid #f59e0b; box-shadow: 0 6px 20px rgba(0,0,0,0.35); font-size: 13.5px; }
    .bicon { flex: 0 0 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; background: #f59e0b; color: #1f1608; font-weight: 800; }
    .btext { display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1; line-height: 1.45; overflow-wrap: anywhere; }
    .btext strong { color: #fef3c7; }
    .toast { position: fixed; right: 16px; bottom: 16px; display: flex; align-items: center; gap: 12px; padding: 12px 16px; min-width: 230px;
      background: #0f1f17; color: #bbf7d0; border: 1px solid rgba(34, 197, 94, 0.5); border-radius: 12px; font-size: 13px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45); animation: in .3s ease-out; transition: opacity .4s, transform .4s; }
    .toast.out { opacity: 0; transform: translateY(8px); }
    .tick { flex: 0 0 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; background: #22c55e; color: #052e16; font-weight: 800; }
    .ttext { display: flex; flex-direction: column; line-height: 1.35; min-width: 0; overflow-wrap: anywhere; }
    .ttext strong { color: #f0fdf4; font-size: 13.5px; }
    .ttext span { color: #86efac; font-size: 12px; }
    @keyframes in { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }
    .close { background: #f59e0b; color: #1f1608; padding: 6px 12px; font-size: 13px; }
  `;

  scan();
})();
