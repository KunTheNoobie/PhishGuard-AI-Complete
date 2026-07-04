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
// STATE
// ═══════════════════════════════════════════════════════════════════

let telemetryData = [];
let muleData = [];
let currentSort = { table: null, key: null, asc: null };

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

const $simToggleBtn     = document.getElementById("simToggleBtn");
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

/**
 * Generic sorting function for arrays of objects.
 * @param {Array} data 
 * @param {string|null} key 
 * @param {boolean|null} asc 
 * @returns {Array}
 */
function sortData(data, key, asc) {
    if (!key) return data; // Default mode (no client sorting, uses real-time API order)
    return [...data].sort((a, b) => {
        let valA = a[key];
        let valB = b[key];
        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();
        
        if (valA < valB) return asc ? -1 : 1;
        if (valA > valB) return asc ? 1 : -1;
        return 0;
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
 * Fetch the most recent threat telemetry entries.
 */
async function refreshTelemetry() {
    const data = await apiFetch("/telemetry");
    $telemetryCount.textContent = data.count;
    telemetryData = data.entries;
    renderTelemetry();
}

/**
 * Render telemetry entries to DOM.
 */
function renderTelemetry() {
    if (telemetryData.length === 0) {
        $telemetryBody.innerHTML =
            '<tr class="table-empty"><td colspan="4">No threats detected yet — system is secure.</td></tr>';
        return;
    }

    const displayData = sortData(
        telemetryData, 
        currentSort.table === 'telemetry' ? currentSort.key : null, 
        currentSort.asc
    );

    $telemetryBody.innerHTML = displayData
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
 * Fetch the full mule account registry.
 */
async function refreshMuleRegistry() {
    const data = await apiFetch("/mule-registry");
    $muleCount.textContent = data.count;
    muleData = data.accounts;
    renderMuleRegistry();
}

/**
 * Render mule accounts to DOM.
 */
function renderMuleRegistry() {
    if (muleData.length === 0) {
        $muleBody.innerHTML =
            '<tr class="table-empty"><td colspan="6">Registry is empty.</td></tr>';
        return;
    }

    const displayData = sortData(
        muleData, 
        currentSort.table === 'mule' ? currentSort.key : null, 
        currentSort.asc
    );

    $muleBody.innerHTML = displayData
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

/**
 * Handle clicks on sortable table headers.
 */
function handleSortClick(e) {
    const th = e.currentTarget;
    const tableId = th.closest('table').id; // 'telemetryTable' or 'muleTable'
    const tableKey = tableId === 'telemetryTable' ? 'telemetry' : 'mule';
    const sortKey = th.getAttribute('data-sort-key');
    
    // 1. If clicking a different column, sort ascending
    if (currentSort.table !== tableKey || currentSort.key !== sortKey) {
        currentSort = { table: tableKey, key: sortKey, asc: true };
    } 
    // 2. If already ascending, switch to descending
    else if (currentSort.asc === true) {
        currentSort.asc = false;
    } 
    // 3. If already descending, reset to default mode
    else {
        currentSort = { table: null, key: null, asc: null };
    }
    
    // Update header classes for UI arrows
    document.querySelectorAll('th.sortable').forEach(el => {
        el.classList.remove('sort-asc', 'sort-desc');
    });
    
    if (currentSort.key) {
        th.classList.add(currentSort.asc ? 'sort-asc' : 'sort-desc');
    }
    
    // Re-render the affected table
    if (tableKey === 'telemetry') renderTelemetry();
    if (tableKey === 'mule') renderMuleRegistry();
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
        const [stats, telemetry, mule, simStatus] = await Promise.all([
            apiFetch("/stats"),
            apiFetch("/telemetry"),
            apiFetch("/mule-registry"),
            apiFetch("/simulator/status").catch(() => ({ simulator_running: false })),
        ]);

        // Process stats
        setStatAnimated($statThreats,    stats.total_threats.toLocaleString());
        setStatAnimated($statConfidence, (stats.avg_confidence * 100).toFixed(1) + "%");
        setStatAnimated($statMule,       stats.total_mule_accounts.toLocaleString());
        setStatAnimated($statReports,    stats.total_reports.toLocaleString());

        // Process telemetry
        $telemetryCount.textContent = telemetry.count;
        telemetryData = telemetry.entries;
        renderTelemetry();

        // Process mule registry
        $muleCount.textContent = mule.count;
        muleData = mule.accounts;
        renderMuleRegistry();
        
        // Update Simulator Button
        if (simStatus.simulator_running) {
            $simToggleBtn.classList.replace("off", "on");
            $simToggleBtn.textContent = "Simulation: ON";
        } else {
            $simToggleBtn.classList.replace("on", "off");
            $simToggleBtn.textContent = "Simulation: OFF";
        }

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

async function handleSimToggle() {
    $simToggleBtn.disabled = true;
    try {
        const res = await fetch(`${API_BASE}/simulator/toggle`, { method: "POST" });
        const data = await res.json();
        if (data.simulator_running) {
            $simToggleBtn.classList.replace("off", "on");
            $simToggleBtn.textContent = "Simulation: ON";
        } else {
            $simToggleBtn.classList.replace("on", "off");
            $simToggleBtn.textContent = "Simulation: OFF";
        }
    } catch (err) {
        console.error("Failed to toggle simulator:", err);
    } finally {
        $simToggleBtn.disabled = false;
    }
}


// ═══════════════════════════════════════════════════════════════════
// BOOTSTRAP
// ═══════════════════════════════════════════════════════════════════

// Attach sorting event listeners
document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', handleSortClick);
});

$simToggleBtn.addEventListener("click", handleSimToggle);

// Initial load
refreshAll();

// Auto-refresh every 3 seconds
setInterval(refreshAll, REFRESH_MS);
