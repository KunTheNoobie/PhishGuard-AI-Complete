/**
 * PhishGuard-AI — Dashboard Client Application
 * ==============================================
 *
 * Fetches aggregate stats, threat telemetry, and mule-registry data
 * from the backend dashboard API and renders them into the UI.
 *
 * Auto-refreshes every 10 seconds via setInterval().
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const API_BASE      = "/api/v1/dashboard";
const REFRESH_MS    = 3_000;   // 3 seconds for live threat simulator

// ═══════════════════════════════════════════════════════════════════
// DOM REFERENCES
// ═══════════════════════════════════════════════════════════════════

const $statThreats      = document.getElementById("statThreats");
const $statConfidence   = document.getElementById("statConfidence");
const $statMule         = document.getElementById("statMule");
const $statReports      = document.getElementById("statReports");

const $telemetryBody    = document.getElementById("telemetryBody");
const $telemetryCount   = document.getElementById("telemetryCount");

const $muleBody         = document.getElementById("muleBody");
const $muleCount        = document.getElementById("muleCount");

const $statusDot        = document.getElementById("statusDot");
const $statusText       = document.getElementById("statusText");
const $lastRefresh      = document.getElementById("lastRefresh");


// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch JSON from a dashboard API endpoint.
 * @param {string} path  Relative path (e.g. "/stats")
 * @returns {Promise<Object>}
 */
async function apiFetch(path) {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

/**
 * Return a CSS class name based on a BERT confidence score.
 * @param {number} score
 * @returns {string}
 */
function scoreClass(score) {
    if (score >= 0.85) return "score-high";
    if (score >= 0.60) return "score-medium";
    return "score-low";
}

/**
 * Return a badge class based on report count severity.
 * @param {number} count
 * @returns {string}
 */
function reportBadgeClass(count) {
    if (count >= 10) return "report-badge report-badge--danger";
    if (count >= 5)  return "report-badge report-badge--warning";
    return "report-badge report-badge--info";
}

/**
 * Format an ISO timestamp to a locale-friendly string.
 * @param {string} ts  ISO 8601 timestamp
 * @returns {string}
 */
function formatTimestamp(ts) {
    if (!ts) return "—";
    const d = new Date(ts);
    return d.toLocaleString("en-MY", {
        year:   "numeric",
        month:  "short",
        day:    "2-digit",
        hour:   "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
    });
}

/**
 * Animate a stat value with a counting effect.
 * @param {HTMLElement} el    Target element
 * @param {string}      value Display value
 */
function setStatAnimated(el, value) {
    el.style.opacity = "0";
    el.style.transform = "translateY(6px)";
    requestAnimationFrame(() => {
        el.textContent = value;
        el.style.transition = "opacity 300ms ease, transform 300ms ease";
        el.style.opacity = "1";
        el.style.transform = "translateY(0)";
    });
}


// ═══════════════════════════════════════════════════════════════════
// DATA FETCHING & RENDERING
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch and render aggregate statistics into the stat cards.
 */
async function refreshStats() {
    const data = await apiFetch("/stats");

    setStatAnimated($statThreats,    data.total_threats.toLocaleString());
    setStatAnimated($statConfidence, (data.avg_confidence * 100).toFixed(1) + "%");
    setStatAnimated($statMule,       data.total_mule_accounts.toLocaleString());
    setStatAnimated($statReports,    data.total_reports.toLocaleString());
}

/**
 * Fetch and render the most recent threat telemetry entries.
 */
async function refreshTelemetry() {
    const data = await apiFetch("/telemetry");
    $telemetryCount.textContent = data.count;

    if (data.entries.length === 0) {
        $telemetryBody.innerHTML =
            '<tr class="table-empty"><td colspan="4">No threats detected yet — system is secure.</td></tr>';
        return;
    }

    $telemetryBody.innerHTML = data.entries
        .map(
            (e) => `
            <tr>
                <td>${e.log_id}</td>
                <td class="url-cell" title="${escapeHtml(e.malicious_url)}">${escapeHtml(e.malicious_url)}</td>
                <td class="${scoreClass(e.bert_score)}">${(e.bert_score * 100).toFixed(1)}%</td>
                <td>${formatTimestamp(e.timestamp)}</td>
            </tr>`
        )
        .join("");
}

/**
 * Fetch and render the full mule account registry.
 */
async function refreshMuleRegistry() {
    const data = await apiFetch("/mule-registry");
    $muleCount.textContent = data.count;

    if (data.accounts.length === 0) {
        $muleBody.innerHTML =
            '<tr class="table-empty"><td colspan="6">Registry is empty.</td></tr>';
        return;
    }

    $muleBody.innerHTML = data.accounts
        .map(
            (a) => `
            <tr>
                <td>${a.id}</td>
                <td style="font-family: 'JetBrains Mono', monospace; letter-spacing: 0.04em;">${a.account_number}</td>
                <td>${escapeHtml(a.bank_name)}</td>
                <td>${escapeHtml(a.platform_flagged)}</td>
                <td><span class="${reportBadgeClass(a.report_count)}">${a.report_count}</span></td>
                <td>${formatTimestamp(a.date_added)}</td>
            </tr>`
        )
        .join("");
}

/**
 * Escape HTML entities to prevent XSS in rendered table cells.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}


// ═══════════════════════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════

/**
 * Master refresh — fetches all three data sources in parallel
 * and updates the connection status indicator.
 */
async function refreshAll() {
    try {
        await Promise.all([
            refreshStats(),
            refreshTelemetry(),
            refreshMuleRegistry(),
        ]);

        // ── Update status indicator ──
        $statusDot.className = "status-dot live";
        $statusText.textContent = "Live";
        $lastRefresh.textContent = `Updated ${new Date().toLocaleTimeString("en-MY", { hour12: false })}`;
    } catch (err) {
        console.error("[PhishGuard Dashboard] Refresh failed:", err);
        $statusDot.className = "status-dot error";
        $statusText.textContent = "Connection Error";
    }
}


// ═══════════════════════════════════════════════════════════════════
// BOOTSTRAP
// ═══════════════════════════════════════════════════════════════════

// Initial load
refreshAll();

// Auto-refresh every 10 seconds
setInterval(refreshAll, REFRESH_MS);
