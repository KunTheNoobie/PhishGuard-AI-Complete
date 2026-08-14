/**
 * PhishGuard-AI — Dashboard Client Application (v2.2 Enterprise)
 * ==============================================================
 *
 * Real-time threat intelligence visualization with Server-Sent Events (SSE),
 * dynamic SVG charts, and interactive mule registry management.
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const API_BASE      = location.protocol === "file:" ? "http://127.0.0.1:8000/api/v1/dashboard" : "/api/v1/dashboard";
const REFRESH_MS    = 3_000;

// ═══════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════

let telemetryData = [];
let muleData = [];
let distributionsData = { banks: [], platforms: [], timeline: [] };
let currentSort = { table: null, key: null, asc: null };

let telemetryFilterText = "";
let telemetryScoreFilter = "all";
let muleFilterText = "";
let sseSource = null;

let telemetryPagination = { page: 1, pageSize: "10" };
let mulePagination = { page: 1, pageSize: "10" };

const BANK_COLORS = [
    "#f59e0b", "#ef4444", "#3b82f6", "#10b981", "#8b5cf6", "#ec4899", "#06b6d4", "#64748b"
];


// ═══════════════════════════════════════════════════════════════════
// DOM REFERENCES
// ═══════════════════════════════════════════════════════════════════

const $statThreats          = document.getElementById("statThreats");
const $statConfidence       = document.getElementById("statConfidence");
const $statMule             = document.getElementById("statMule");
const $statReports          = document.getElementById("statReports");

const $bankDonutSvg         = document.getElementById("bankDonutSvg");
const $bankLegend           = document.getElementById("bankLegend");
const $donutCenterText      = document.getElementById("donutCenterText");
const $timelineBars         = document.getElementById("timelineBars");
const $platformBars         = document.getElementById("platformBars");
const $infraBars            = document.getElementById("infraBars");

let currentReportData       = null;
let currentReportLogId      = null;


const $telemetryBody        = document.getElementById("telemetryBody");
const $telemetryCount       = document.getElementById("telemetryCount");
const $telemetrySearch      = document.getElementById("telemetrySearch");
const $telemetryScoreFilter = document.getElementById("telemetryScoreFilter");
const $exportTelemetryCsvBtn= document.getElementById("exportTelemetryCsvBtn");
const $exportTelemetryJsonBtn= document.getElementById("exportTelemetryJsonBtn");
const $telemetryPageInfo    = document.getElementById("telemetryPageInfo");
const $telemetryPageSize    = document.getElementById("telemetryPageSize");
const $telemetryPageButtons = document.getElementById("telemetryPageButtons");

const $muleBody             = document.getElementById("muleBody");
const $muleCount            = document.getElementById("muleCount");
const $muleSearch           = document.getElementById("muleSearch");
const $exportMuleCsvBtn     = document.getElementById("exportMuleCsvBtn");
const $openAddMuleModalBtn  = document.getElementById("openAddMuleModalBtn");
const $mulePageInfo         = document.getElementById("mulePageInfo");
const $mulePageSize         = document.getElementById("mulePageSize");
const $mulePageButtons      = document.getElementById("mulePageButtons");


const $simToggleBtn         = document.getElementById("simToggleBtn");
const $statusDot            = document.getElementById("statusDot");
const $statusText           = document.getElementById("statusText");
const $lastRefresh          = document.getElementById("lastRefresh");

// Modal Elements
const $addMuleModal         = document.getElementById("addMuleModal");
const $closeAddMuleModalBtn = document.getElementById("closeAddMuleModalBtn");
const $cancelAddMuleBtn     = document.getElementById("cancelAddMuleBtn");
const $addMuleForm          = document.getElementById("addMuleForm");
const $muleAccountInput     = document.getElementById("muleAccountInput");
const $muleBankInput        = document.getElementById("muleBankInput");
const $mulePlatformInput    = document.getElementById("mulePlatformInput");
const $muleReportsInput     = document.getElementById("muleReportsInput");
const $saveMuleBtn          = document.getElementById("saveMuleBtn");

// Bulk Mule Elements
const $bulkMuleModal        = document.getElementById("bulkMuleModal");
const $openBulkMuleModalBtn = document.getElementById("openBulkMuleModalBtn");
const $closeBulkMuleModalBtn= document.getElementById("closeBulkMuleModalBtn");
const $cancelBulkMuleBtn    = document.getElementById("cancelBulkMuleBtn");
const $bulkMuleForm         = document.getElementById("bulkMuleForm");
const $bulkMuleText         = document.getElementById("bulkMuleText");
const $bulkImportStatus     = document.getElementById("bulkImportStatus");

// Dossier Action Elements
const $quarantineCurrentBtn = document.getElementById("quarantineCurrentBtn");
const $whitelistCurrentBtn  = document.getElementById("whitelistCurrentBtn");
const $copyTakedownBtn      = document.getElementById("copyTakedownBtn");


// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

async function apiFetch(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, options);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

function scoreClass(score) {
    if (score >= 0.85) return "score-high";
    if (score >= 0.60) return "score-medium";
    return "score-low";
}

function reportBadgeClass(count) {
    if (count >= 10) return "report-badge report-badge--danger";
    if (count >= 5)  return "report-badge report-badge--warning";
    return "report-badge report-badge--info";
}

function formatTimestamp(ts) {
    if (!ts || ts === "Just now") return ts || "—";
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString("en-MY", {
        year: "numeric", month: "short", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: false,
    });
}

function downloadFile(filename, mimeType, content) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function setStatAnimated(el, value) {
    if (!el) return;
    el.style.opacity = "0";
    el.style.transform = "translateY(6px)";
    requestAnimationFrame(() => {
        el.textContent = value;
        el.style.transition = "opacity 300ms ease, transform 300ms ease";
        el.style.opacity = "1";
        el.style.transform = "translateY(0)";
    });
}

function sortData(data, key, asc) {
    if (!key) return data;
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

function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str || "")));
    return div.innerHTML;
}

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS VISUAL CHARTS
// ═══════════════════════════════════════════════════════════════════

function renderBankDonutChart(banks) {
    if (!banks || !banks.length) {
        $bankDonutSvg.innerHTML = '<circle cx="50" cy="50" r="38" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="14"/>';
        $bankLegend.innerHTML = '<div class="legend-item"><span>No data</span></div>';
        return;
    }

    const total = banks.reduce((acc, b) => acc + b.count, 0) || 1;
    let accumulatedAngle = 0;
    const radius = 36;
    const circumference = 2 * Math.PI * radius;
    let svgSegments = "";
    let legendHtml = "";

    banks.slice(0, 5).forEach((b, i) => {
        const color = BANK_COLORS[i % BANK_COLORS.length];
        const percent = b.count / total;
        const dashLength = percent * circumference;
        const spaceLength = circumference - dashLength;
        const dashOffset = -accumulatedAngle * (circumference / 360);
        accumulatedAngle += percent * 360;

        svgSegments += `
            <circle cx="50" cy="50" r="${radius}" fill="none" stroke="${color}" stroke-width="12"
                stroke-dasharray="${dashLength} ${spaceLength}" stroke-dashoffset="${dashOffset}"
                stroke-linecap="butt" style="transition: stroke-dasharray 0.5s ease;"></circle>
        `;

        legendHtml += `
            <div class="legend-item">
                <span style="display: flex; align-items: center; gap: 6px;">
                    <span class="legend-color" style="background: ${color};"></span>
                    ${escapeHtml(b.bank)}
                </span>
                <strong>${Math.round(percent * 100)}%</strong>
            </div>
        `;
    });

    $bankDonutSvg.innerHTML = svgSegments;
    $bankLegend.innerHTML = legendHtml;
    $donutCenterText.innerHTML = `${total}<small>Mules</small>`;
}

function renderTimelineBars(timeline) {
    if (!timeline || !timeline.length) {
        // Fallback default timeline buckets
        timeline = [
            { time: "18:00", count: 4 }, { time: "19:00", count: 7 }, { time: "20:00", count: 12 },
            { time: "21:00", count: 18 }, { time: "22:00", count: 25 }, { time: "23:00", count: 15 },
            { time: "00:00", count: 9 }, { time: "01:00", count: telemetryData.length || 1 }
        ];
    }

    const maxCount = Math.max(...timeline.map(t => t.count), 1);
    $timelineBars.innerHTML = timeline.map(t => {
        const heightPct = Math.max(8, Math.round((t.count / maxCount) * 100));
        const label = t.time.includes("T") ? t.time.split("T")[1].slice(0, 5) : t.time.slice(-5);
        return `
            <div class="timeline-bar-col" title="${label}: ${t.count} detections">
                <div class="timeline-bar" style="height: ${heightPct}%;"></div>
                <span class="timeline-label">${label}</span>
            </div>
        `;
    }).join("");
}

function renderPlatformBars(platforms) {
    if (!platforms || !platforms.length) {
        platforms = [
            { platform: "WhatsApp Scam", count: 18 },
            { platform: "Telegram Scam", count: 14 },
            { platform: "Facebook Marketplace", count: 12 },
            { platform: "Shopee Fake Shop", count: 9 }
        ];
    }

    const maxCount = Math.max(...platforms.map(p => p.count), 1);
    $platformBars.innerHTML = platforms.slice(0, 4).map(p => {
        const widthPct = Math.max(10, Math.round((p.count / maxCount) * 100));
        return `
            <div class="platform-row">
                <div class="platform-row-header">
                    <span>${escapeHtml(p.platform)}</span>
                    <strong>${p.count}</strong>
                </div>
                <div class="platform-bar-track">
                    <div class="platform-bar-fill" style="width: ${widthPct}%;"></div>
                </div>
            </div>
        `;
    }).join("");
}

function renderInfraBars(infrastructure) {
    if (!$infraBars) return;
    if (!infrastructure || !infrastructure.length) {
        infrastructure = [
            { provider: "Cloudflare (AS13335)", count: 18 },
            { provider: "Namecheap (AS22612)", count: 14 },
            { provider: "Hostinger (AS47583)", count: 11 },
            { provider: "AWS Cloud (AS16509)", count: 9 }
        ];
    }

    const maxCount = Math.max(...infrastructure.map(i => i.count), 1);
    $infraBars.innerHTML = infrastructure.slice(0, 4).map(i => {
        const widthPct = Math.max(10, Math.round((i.count / maxCount) * 100));
        return `
            <div class="platform-row">
                <div class="platform-row-header">
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem;">${escapeHtml(i.provider)}</span>
                    <strong>${i.count}</strong>
                </div>
                <div class="platform-bar-track">
                    <div class="platform-bar-fill" style="width: ${widthPct}%; background: linear-gradient(90deg, #06b6d4, #3b82f6);"></div>
                </div>
            </div>
        `;
    }).join("");
}

// ═══════════════════════════════════════════════════════════════════
// DATA FETCHING & RENDERING
// ═══════════════════════════════════════════════════════════════════

async function refreshStats() {
    const data = await apiFetch("/stats");
    setStatAnimated($statThreats,    data.total_threats.toLocaleString());
    setStatAnimated($statConfidence, (data.avg_confidence * 100).toFixed(1) + "%");
    setStatAnimated($statMule,       data.total_mule_accounts.toLocaleString());
    setStatAnimated($statReports,    data.total_reports.toLocaleString());
}

async function refreshDistributions() {
    try {
        const data = await apiFetch("/distributions");
        distributionsData = data;
        renderBankDonutChart(data.banks);
        renderTimelineBars(data.timeline);
        renderPlatformBars(data.platforms);
        renderInfraBars(data.infrastructure);
    } catch (_err) {}
}


async function refreshTelemetry() {
    const data = await apiFetch("/telemetry");
    telemetryData = data.entries;
    renderTelemetry();
}

function renderPaginationControls(container, infoEl, totalItems, currentPage, pageSize, onPageChange) {
    if (!container || !infoEl) return;
    if (pageSize === "all" || totalItems <= 0) {
        infoEl.textContent = totalItems > 0 ? `Showing all ${totalItems} entries` : "Showing 0 entries";
        container.innerHTML = "";
        return;
    }

    const numPageSize = parseInt(pageSize, 10);
    const totalPages = Math.ceil(totalItems / numPageSize) || 1;
    const validPage = Math.max(1, Math.min(currentPage, totalPages));

    const start = (validPage - 1) * numPageSize + 1;
    const end = Math.min(validPage * numPageSize, totalItems);
    infoEl.textContent = `Showing ${start} to ${end} of ${totalItems} entries`;

    let html = "";
    
    // First & Prev buttons
    html += `<button class="page-btn" ${validPage === 1 ? "disabled" : ""} data-page="1" title="First Page">⏮</button>`;
    html += `<button class="page-btn" ${validPage === 1 ? "disabled" : ""} data-page="${validPage - 1}" title="Previous Page">◀</button>`;

    // Page Number Windows with Ellipsis
    const windowSize = 2;
    let startPage = Math.max(1, validPage - windowSize);
    let endPage = Math.min(totalPages, validPage + windowSize);

    if (startPage > 1) {
        html += `<button class="page-btn" data-page="1">1</button>`;
        if (startPage > 2) html += `<span class="page-ellipsis">…</span>`;
    }

    for (let p = startPage; p <= endPage; p++) {
        html += `<button class="page-btn ${p === validPage ? "active" : ""}" data-page="${p}">${p}</button>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += `<span class="page-ellipsis">…</span>`;
        html += `<button class="page-btn" data-page="${totalPages}">${totalPages}</button>`;
    }

    // Next & Last buttons
    html += `<button class="page-btn" ${validPage === totalPages ? "disabled" : ""} data-page="${validPage + 1}" title="Next Page">▶</button>`;
    html += `<button class="page-btn" ${validPage === totalPages ? "disabled" : ""} data-page="${totalPages}" title="Last Page">⏭</button>`;

    container.innerHTML = html;

    container.querySelectorAll(".page-btn[data-page]").forEach(btn => {
        btn.addEventListener("click", () => {
            const newPage = parseInt(btn.getAttribute("data-page"), 10);
            if (!isNaN(newPage) && newPage !== currentPage) {
                onPageChange(newPage);
            }
        });
    });
}

function renderTelemetry() {
    let filtered = telemetryData;

    if (telemetryFilterText) {
        const query = telemetryFilterText.toLowerCase();
        filtered = filtered.filter(e => 
            String(e.log_id).includes(query) || 
            String(e.malicious_url).toLowerCase().includes(query)
        );
    }

    if (telemetryScoreFilter === "high") {
        filtered = filtered.filter(e => e.bert_score >= 0.85);
    } else if (telemetryScoreFilter === "medium") {
        filtered = filtered.filter(e => e.bert_score >= 0.60 && e.bert_score < 0.85);
    } else if (telemetryScoreFilter === "low") {
        filtered = filtered.filter(e => e.bert_score < 0.60);
    }

    $telemetryCount.textContent = filtered.length;

    if (filtered.length === 0) {
        $telemetryBody.innerHTML =
            '<tr class="table-empty"><td colspan="5">No threats match current filter criteria.</td></tr>';
        renderPaginationControls($telemetryPageButtons, $telemetryPageInfo, 0, 1, telemetryPagination.pageSize, () => {});
        return;
    }

    const displayData = sortData(
        filtered, 
        currentSort.table === 'telemetry' ? currentSort.key : null, 
        currentSort.asc
    );

    // Calculate pagination slice
    let pageData = displayData;
    if (telemetryPagination.pageSize !== "all") {
        const numSize = parseInt(telemetryPagination.pageSize, 10);
        const totalPages = Math.ceil(displayData.length / numSize) || 1;
        if (telemetryPagination.page > totalPages) telemetryPagination.page = totalPages;
        const start = (telemetryPagination.page - 1) * numSize;
        pageData = displayData.slice(start, start + numSize);
    }

    $telemetryBody.innerHTML = pageData
        .map(
            (e) => `
            <tr>
                <td>${e.log_id}</td>
                <td class="url-cell" title="${escapeHtml(e.malicious_url)}">${escapeHtml(e.malicious_url)}</td>
                <td class="${scoreClass(e.bert_score)}">${(e.bert_score * 100).toFixed(1)}%</td>
                <td>${formatTimestamp(e.timestamp)}</td>
                <td>
                    <button class="action-btn" style="padding: 2px 8px; font-size: 0.72rem;" onclick="openIncidentReport(${e.log_id})">
                        📄 Dossier
                    </button>
                </td>
            </tr>`
        )
        .join("");

    renderPaginationControls(
        $telemetryPageButtons,
        $telemetryPageInfo,
        displayData.length,
        telemetryPagination.page,
        telemetryPagination.pageSize,
        (newPage) => {
            telemetryPagination.page = newPage;
            renderTelemetry();
        }
    );
}


async function openIncidentReport(logId) {
    currentReportLogId = logId;
    const modal = document.getElementById("forensicReportModal");
    const body = document.getElementById("forensicReportBody");
    if (!modal || !body) return;

    modal.classList.remove("hidden");
    body.innerHTML = "Fetching forensic telemetry dossier...";

    try {
        const report = await apiFetch(`/telemetry/${logId}/report`);
        currentReportData = report;
        const mulesHtml = (report.active_mules_referenced || []).map(m => `
            <li style="margin-bottom: 4px;">
                <strong>${escapeHtml(m.bank_name)}:</strong> <code>${escapeHtml(m.account_number)}</code> 
                <span style="opacity: 0.8;">(${m.reports} incident reports on ${escapeHtml(m.platform)})</span>
            </li>
        `).join("");

        body.innerHTML = `
            <div style="background: rgba(15, 23, 42, 0.6); padding: 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <strong>Reference:</strong> <code>${escapeHtml(report.incident_id)}</code>
                    <span style="color: #f87171; font-weight: 700;">${escapeHtml(report.threat_classification)}</span>
                </div>
                <div style="margin-bottom: 6px;"><strong>Targeted URL:</strong> <code style="word-break: break-all; color: var(--accent-cyan);">${escapeHtml(report.target_url)}</code></div>
                <div style="margin-bottom: 6px;"><strong>SHA-256 Digest:</strong> <code style="font-size: 0.75rem; word-break: break-all;">${escapeHtml(report.url_hash_sha256)}</code></div>
                <div style="margin-bottom: 6px;"><strong>Target Entity:</strong> ${escapeHtml(report.targeted_institution)}</div>
                <div style="margin-bottom: 6px;"><strong>AI Threat Probability:</strong> <span class="score-high">${report.bert_confidence}%</span></div>
                <div><strong>Jurisdiction:</strong> ${escapeHtml(report.jurisdiction)}</div>
            </div>

            <div style="margin-bottom: 12px;">
                <strong>Associated High-Risk Mule Accounts:</strong>
                <ul style="margin-top: 6px; padding-left: 20px; font-size: 0.8rem;">
                    ${mulesHtml || '<li>No direct mule accounts linked in session.</li>'}
                </ul>
            </div>

            <div style="background: rgba(99, 102, 241, 0.1); border-left: 3px solid #6366f1; padding: 10px; border-radius: 4px; font-size: 0.78rem;">
                <strong>Recommended Mitigation:</strong> ${escapeHtml(report.recommended_action)}
            </div>
        `;
    } catch (err) {
        body.innerHTML = `<span style="color: #f87171;">Failed to load report: ${escapeHtml(err.message)}</span>`;
    }
}



async function refreshMuleRegistry() {
    const data = await apiFetch("/mule-registry");
    muleData = data.accounts;
    renderMuleRegistry();
}

function renderMuleRegistry() {
    let filtered = muleData;

    if (muleFilterText) {
        const query = muleFilterText.toLowerCase();
        filtered = filtered.filter(a =>
            String(a.id).includes(query) ||
            String(a.account_number).toLowerCase().includes(query) ||
            String(a.bank_name).toLowerCase().includes(query) ||
            String(a.platform_flagged).toLowerCase().includes(query)
        );
    }

    $muleCount.textContent = filtered.length;

    if (filtered.length === 0) {
        $muleBody.innerHTML =
            '<tr class="table-empty"><td colspan="7">No mule accounts match current filter.</td></tr>';
        renderPaginationControls($mulePageButtons, $mulePageInfo, 0, 1, mulePagination.pageSize, () => {});
        return;
    }

    const displayData = sortData(
        filtered, 
        currentSort.table === 'mule' ? currentSort.key : null, 
        currentSort.asc
    );

    // Calculate pagination slice
    let pageData = displayData;
    if (mulePagination.pageSize !== "all") {
        const numSize = parseInt(mulePagination.pageSize, 10);
        const totalPages = Math.ceil(displayData.length / numSize) || 1;
        if (mulePagination.page > totalPages) mulePagination.page = totalPages;
        const start = (mulePagination.page - 1) * numSize;
        pageData = displayData.slice(start, start + numSize);
    }

    $muleBody.innerHTML = pageData
        .map(
            (a) => `
            <tr>
                <td>${a.id}</td>
                <td style="font-family: 'JetBrains Mono', monospace; letter-spacing: 0.04em;">${a.account_number}</td>
                <td>${escapeHtml(a.bank_name)}</td>
                <td>${escapeHtml(a.platform_flagged)}</td>
                <td><span class="${reportBadgeClass(a.report_count)}">${a.report_count}</span></td>
                <td>${formatTimestamp(a.date_added)}</td>
                <td>
                    <button class="action-btn action-btn--delete" onclick="handleDeleteMule(${a.id})" title="Delete mule account">
                        Delete
                    </button>
                </td>
            </tr>`
        )
        .join("");

    renderPaginationControls(
        $mulePageButtons,
        $mulePageInfo,
        displayData.length,
        mulePagination.page,
        mulePagination.pageSize,
        (newPage) => {
            mulePagination.page = newPage;
            renderMuleRegistry();
        }
    );
}


window.handleDeleteMule = async function(muleId) {
    if (!confirm(`Are you sure you want to remove mule account #${muleId}?`)) return;
    try {
        await apiFetch(`/mule-registry/${muleId}`, { method: "DELETE" });
        await refreshAll();
    } catch (err) {
        alert("Failed to delete mule account: " + err.message);
    }
};

function handleSortClick(e) {
    const th = e.currentTarget;
    const tableId = th.closest('table').id;
    const tableKey = tableId === 'telemetryTable' ? 'telemetry' : 'mule';
    const sortKey = th.getAttribute('data-sort-key');
    
    if (currentSort.table !== tableKey || currentSort.key !== sortKey) {
        currentSort = { table: tableKey, key: sortKey, asc: true };
    } else if (currentSort.asc === true) {
        currentSort.asc = false;
    } else {
        currentSort = { table: null, key: null, asc: null };
    }
    
    document.querySelectorAll('th.sortable').forEach(el => {
        el.classList.remove('sort-asc', 'sort-desc');
    });
    
    if (currentSort.key) {
        th.classList.add(currentSort.asc ? 'sort-asc' : 'sort-desc');
    }
    
    if (tableKey === 'telemetry') renderTelemetry();
    if (tableKey === 'mule') renderMuleRegistry();
}

// ═══════════════════════════════════════════════════════════════════
// EXPORT GENERATORS
// ═══════════════════════════════════════════════════════════════════

function exportTelemetryCsv() {
    if (!telemetryData.length) return alert("No telemetry data to export.");
    let csv = "Log ID,Malicious URL,BERT Score,Timestamp\n";
    for (const row of telemetryData) {
        csv += `"${row.log_id}","${row.malicious_url.replace(/"/g, '""')}","${(row.bert_score * 100).toFixed(2)}%","${row.timestamp}"\n`;
    }
    downloadFile("phishguard_telemetry.csv", "text/csv;charset=utf-8;", csv);
}

function exportTelemetryJson() {
    if (!telemetryData.length) return alert("No telemetry data to export.");
    const json = JSON.stringify(telemetryData, null, 2);
    downloadFile("phishguard_telemetry.json", "application/json", json);
}

async function exportStixBundle() {
    try {
        const bundle = await apiFetch("/export/stix");
        downloadFile("phishguard_stix21_bundle.json", "application/json", JSON.stringify(bundle, null, 2));
    } catch (err) {
        alert("Failed to generate STIX 2.1 bundle: " + err.message);
    }
}

function exportMuleCsv() {
    if (!muleData.length) return alert("No mule records to export.");
    let csv = "ID,Account Number,Bank Name,Platform Flagged,Reports,Date Added\n";
    for (const row of muleData) {
        csv += `"${row.id}","${row.account_number}","${row.bank_name}","${row.platform_flagged}","${row.report_count}","${row.date_added}"\n`;
    }
    downloadFile("phishguard_mule_registry.csv", "text/csv;charset=utf-8;", csv);
}


// ═══════════════════════════════════════════════════════════════════
// MODAL HANDLERS
// ═══════════════════════════════════════════════════════════════════

function openAddMuleModal() {
    $addMuleModal.classList.remove("hidden");
    $addMuleModal.setAttribute("aria-hidden", "false");
    $muleAccountInput.focus();
}

function closeAddMuleModal() {
    $addMuleModal.classList.add("hidden");
    $addMuleModal.setAttribute("aria-hidden", "true");
    $addMuleForm.reset();
}

async function handleAddMuleSubmit(e) {
    e.preventDefault();
    $saveMuleBtn.disabled = true;
    $saveMuleBtn.textContent = "Saving...";

    const payload = {
        account_number: $muleAccountInput.value.trim(),
        bank_name: $muleBankInput.value.trim(),
        platform_flagged: $mulePlatformInput.value.trim() || "Manual Admin Entry",
        report_count: parseInt($muleReportsInput.value, 10) || 1
    };

    try {
        await apiFetch("/mule-registry", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        closeAddMuleModal();
        await refreshAll();
    } catch (err) {
        alert("Failed to register mule account: " + err.message);
    } finally {
        $saveMuleBtn.disabled = false;
        $saveMuleBtn.textContent = "Add to Registry";
    }
}

// ═══════════════════════════════════════════════════════════════════
// SERVER-SENT EVENTS (SSE) STREAM
// ═══════════════════════════════════════════════════════════════════

function initSseStream() {
    if (window.EventSource) {
        try {
            sseSource = new EventSource(`${API_BASE}/stream`);
            sseSource.addEventListener("update", (e) => {
                try {
                    const parsed = JSON.parse(e.data);
                    if (parsed.event === "new_threat" && parsed.data) {
                        telemetryData = [parsed.data, ...telemetryData.filter(t => t.log_id !== parsed.data.log_id)].slice(0, 50);
                        renderTelemetry();
                        refreshStats();
                        refreshDistributions();
                    }
                } catch (_err) {}
            });
            sseSource.onerror = () => {
                sseSource.close();
                sseSource = null;
            };
        } catch (_err) {}
    }
}

// ═══════════════════════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════

async function refreshAll() {
    try {
        const [stats, telemetry, mule, simStatus] = await Promise.all([
            apiFetch("/stats"),
            apiFetch("/telemetry"),
            apiFetch("/mule-registry"),
            apiFetch("/simulator/status").catch(() => ({ simulator_running: false })),
        ]);

        setStatAnimated($statThreats,    stats.total_threats.toLocaleString());
        setStatAnimated($statConfidence, (stats.avg_confidence * 100).toFixed(1) + "%");
        setStatAnimated($statMule,       stats.total_mule_accounts.toLocaleString());
        setStatAnimated($statReports,    stats.total_reports.toLocaleString());

        telemetryData = telemetry.entries;
        renderTelemetry();

        muleData = mule.accounts;
        renderMuleRegistry();
        
        if (simStatus.simulator_running) {
            $simToggleBtn.classList.replace("off", "on");
            $simToggleBtn.textContent = "Simulation: ON";
        } else {
            $simToggleBtn.classList.replace("on", "off");
            $simToggleBtn.textContent = "Simulation: OFF";
        }

        refreshDistributions();

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
        refreshAll();
    } catch (err) {
        console.error("Failed to toggle simulator:", err);
    } finally {
        $simToggleBtn.disabled = false;
    }
}

// Audio Alert Synthesizer (Web Audio API)
let soundAlertEnabled = false;
const $audioToggleBtn = document.getElementById("audioToggleBtn");
const $audioStatusText = document.getElementById("audioStatusText");

function playThreatAlertSound() {
    if (!soundAlertEnabled) return;
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(880, ctx.currentTime); // A5
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.25);
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0.01, ctx.currentTime + 0.25);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.25);
    } catch (_e) {}
}

if ($audioToggleBtn) {
    $audioToggleBtn.addEventListener("click", () => {
        soundAlertEnabled = !soundAlertEnabled;
        if (soundAlertEnabled) {
            $audioToggleBtn.classList.add("active");
            $audioStatusText.textContent = "Sound: ON";
            playThreatAlertSound();
        } else {
            $audioToggleBtn.classList.remove("active");
            $audioStatusText.textContent = "Sound: OFF";
        }
    });
}

// Quick URL Scanner Handler
const $quickScanForm = document.getElementById("quickScanForm");
const $quickScanInput = document.getElementById("quickScanInput");
const $quickScanBtn = document.getElementById("quickScanBtn");
const $quickScanResult = document.getElementById("quickScanResult");
const $healthText = document.getElementById("healthText");

async function refreshSystemHealth() {
    try {
        const health = await apiFetch("/system-health");
        if ($healthText) {
            $healthText.textContent = `AI Engine: Online • Cache: ${health.cache.active_entries} entries • DB: 3NF Active`;
        }
    } catch (_e) {}
}

if ($quickScanForm) {
    $quickScanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const val = $quickScanInput.value.trim();
        if (!val) return;

        $quickScanBtn.disabled = true;
        $quickScanBtn.textContent = "Inspecting...";

        try {
            const res = await apiFetch("/quick-scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: val, text_content: val })
            });

            $quickScanResult.classList.remove("hidden", "safe", "dangerous");
            const isDanger = res.verdict === "BLOCK_RENDER" || res.mule_detected;
            $quickScanResult.classList.add(isDanger ? "dangerous" : "safe");

            const muleStr = res.mule_detected
                ? `⚠️ Flagged Mule Account Detected: ${res.flagged_accounts.map(a => a.account_number + ' (' + a.bank_name + ')').join(", ")}`
                : "✅ No Mule Accounts Detected";

            $quickScanResult.innerHTML = `
                <div>
                    <strong>Verdict: ${res.verdict}</strong> — Score: ${(res.score * 100).toFixed(1)}%<br>
                    <span style="font-size: 0.8rem; opacity: 0.9;">${muleStr}</span>
                </div>
                <button class="action-btn" onclick="document.getElementById('quickScanResult').classList.add('hidden')">Dismiss</button>
            `;
            if (isDanger) playThreatAlertSound();
        } catch (err) {
            alert("Scan failed: " + err.message);
        } finally {
            $quickScanBtn.disabled = false;
            $quickScanBtn.textContent = "Inspect Target";
        }
    });
}

// ═══════════════════════════════════════════════════════════════════
// BOOTSTRAP & EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════════

document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', handleSortClick);
});

$simToggleBtn.addEventListener("click", handleSimToggle);

// Search and Filter Listeners
$telemetrySearch.addEventListener("input", (e) => {
    telemetryFilterText = e.target.value;
    telemetryPagination.page = 1;
    renderTelemetry();
});

$telemetryScoreFilter.addEventListener("change", (e) => {
    telemetryScoreFilter = e.target.value;
    telemetryPagination.page = 1;
    renderTelemetry();
});

if ($telemetryPageSize) {
    $telemetryPageSize.addEventListener("change", (e) => {
        telemetryPagination.pageSize = e.target.value;
        telemetryPagination.page = 1;
        renderTelemetry();
    });
}

$muleSearch.addEventListener("input", (e) => {
    muleFilterText = e.target.value;
    mulePagination.page = 1;
    renderMuleRegistry();
});

if ($mulePageSize) {
    $mulePageSize.addEventListener("change", (e) => {
        mulePagination.pageSize = e.target.value;
        mulePagination.page = 1;
        renderMuleRegistry();
    });
}


// Export Listeners
$exportTelemetryCsvBtn.addEventListener("click", exportTelemetryCsv);
$exportTelemetryJsonBtn.addEventListener("click", exportTelemetryJson);
const exportStixBtn = document.getElementById("exportStixBtn");
if (exportStixBtn) exportStixBtn.addEventListener("click", exportStixBundle);
$exportMuleCsvBtn.addEventListener("click", exportMuleCsv);


// Modal Listeners
$openAddMuleModalBtn.addEventListener("click", openAddMuleModal);
$closeAddMuleModalBtn.addEventListener("click", closeAddMuleModal);
$cancelAddMuleBtn.addEventListener("click", closeAddMuleModal);
$addMuleForm.addEventListener("submit", handleAddMuleSubmit);

// Bulk Mule Modal Listeners
function openBulkMuleModal() {
    if ($bulkMuleModal) {
        $bulkMuleModal.classList.remove("hidden");
        if ($bulkImportStatus) $bulkImportStatus.style.display = "none";
        if ($bulkMuleText) $bulkMuleText.value = "";
    }
}

function closeBulkMuleModal() {
    if ($bulkMuleModal) $bulkMuleModal.classList.add("hidden");
}

if ($openBulkMuleModalBtn) $openBulkMuleModalBtn.addEventListener("click", openBulkMuleModal);
if ($closeBulkMuleModalBtn) $closeBulkMuleModalBtn.addEventListener("click", closeBulkMuleModal);
if ($cancelBulkMuleBtn) $cancelBulkMuleBtn.addEventListener("click", closeBulkMuleModal);

if ($bulkMuleForm) {
    $bulkMuleForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const text = $bulkMuleText.value.trim();
        if (!text) return;

        if ($bulkImportStatus) {
            $bulkImportStatus.style.display = "block";
            $bulkImportStatus.style.color = "var(--accent-cyan)";
            $bulkImportStatus.textContent = "Processing and validating batch accounts...";
        }

        try {
            const res = await apiFetch("/mule-registry/bulk", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ raw_csv: text })
            });

            if ($bulkImportStatus) {
                $bulkImportStatus.style.color = "#34d399";
                $bulkImportStatus.textContent = `✅ Successfully ingested ${res.imported_count} mule accounts!`;
            }
            setTimeout(() => {
                closeBulkMuleModal();
                refreshAll();
            }, 1200);
        } catch (err) {
            if ($bulkImportStatus) {
                $bulkImportStatus.style.color = "#f87171";
                $bulkImportStatus.textContent = "Batch import failed: " + err.message;
            }
        }
    });
}

// Forensic Dossier Action Listeners (Quarantine, Whitelist, Takedown Notice)
if ($quarantineCurrentBtn) {
    $quarantineCurrentBtn.addEventListener("click", async () => {
        if (!currentReportData || !currentReportData.target_url) return;
        let dom = currentReportData.target_url;
        try { dom = new URL(currentReportData.target_url).hostname || dom; } catch (_e) {}
        if (!confirm(`Quarantine domain '${dom}' system-wide and broadcast emergency SIEM alert?`)) return;

        try {
            await apiFetch("/domains/quarantine", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: dom, reason: `SOC Manual Quarantine from Incident ${currentReportData.incident_id}` })
            });
            alert(`🛡️ Domain '${dom}' has been quarantined system-wide! Emergency webhook broadcast dispatched.`);
        } catch (err) {
            alert("Quarantine failed: " + err.message);
        }
    });
}

if ($whitelistCurrentBtn) {
    $whitelistCurrentBtn.addEventListener("click", async () => {
        if (!currentReportData || !currentReportData.target_url) return;
        let dom = currentReportData.target_url;
        try { dom = new URL(currentReportData.target_url).hostname || dom; } catch (_e) {}
        if (!confirm(`Whitelist domain '${dom}' as safe for 24 hours?`)) return;

        try {
            await apiFetch("/domains/whitelist", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: dom, reason: "SOC Verified Safe / False Positive Exemption", ttl_hours: 24 })
            });
            alert(`✅ Domain '${dom}' has been whitelisted for 24 hours.`);
        } catch (err) {
            alert("Whitelist failed: " + err.message);
        }
    });
}

if ($copyTakedownBtn) {
    $copyTakedownBtn.addEventListener("click", async () => {
        if (!currentReportLogId) return;
        try {
            const notice = await apiFetch(`/telemetry/${currentReportLogId}/takedown-notice`);
            await navigator.clipboard.writeText(notice.body);
            alert(`📋 Standardized RFC 2142 Abuse Takedown Notice copied to clipboard!\n\nDestination: ${notice.abuse_email}\nSubject: ${notice.subject}`);
        } catch (err) {
            alert("Failed to generate takedown notice: " + err.message);
        }
    });
}

const closeForensicModalBtn = document.getElementById("closeForensicModalBtn");
if (closeForensicModalBtn) {
    closeForensicModalBtn.addEventListener("click", () => {
        const modal = document.getElementById("forensicReportModal");
        if (modal) modal.classList.add("hidden");
    });
}


// Initial load & stream
refreshAll();

refreshSystemHealth();
initSseStream();
setInterval(refreshAll, REFRESH_MS);
setInterval(refreshSystemHealth, 10_000);
