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
// THEME INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    if (document.body) document.body.setAttribute("data-theme", t);
    localStorage.setItem("phishguard_theme", t);
}

const savedTheme = localStorage.getItem("phishguard_theme") || "cyberpunk";
applyTheme(savedTheme);

const $themeSelector = document.getElementById("themeSelector");
if ($themeSelector) {
    $themeSelector.value = savedTheme;
    $themeSelector.addEventListener("change", (e) => {
        applyTheme(e.target.value);
    });
}




// ═══════════════════════════════════════════════════════════════════
// CYBERPUNK TOAST NOTIFICATIONS & DIALOG SYSTEM
// ═══════════════════════════════════════════════════════════════════

const $cyberToastContainer = document.getElementById("cyberToastContainer");

function showCyberToast(type = "info", title = "Notification", message = "", durationMs = 4000) {
    if (!$cyberToastContainer) return;
    const toast = document.createElement("div");
    toast.className = `cyber-toast cyber-toast--${type}`;
    
    const iconMap = {
        success: "✅",
        danger: "🚨",
        warning: "⚠️",
        info: "ℹ️"
    };

    toast.innerHTML = `
        <div class="cyber-toast__icon">${iconMap[type] || "ℹ️"}</div>
        <div class="cyber-toast__content">
            <div class="cyber-toast__title">${escapeHtml(title)}</div>
            <div>${escapeHtml(message)}</div>
        </div>
        <button class="cyber-toast__close" type="button">&times;</button>
    `;

    toast.querySelector(".cyber-toast__close").addEventListener("click", () => {
        toast.remove();
    });

    $cyberToastContainer.appendChild(toast);

    if (durationMs > 0) {
        setTimeout(() => {
            toast.style.animation = "toastFadeOut 0.3s forwards";
            setTimeout(() => toast.remove(), 300);
        }, durationMs);
    }
}

// In-UI Confirmation Modal replacing native confirm()
function showCyberConfirm(title, message, confirmText = "Confirm Action") {
    return new Promise((resolve) => {
        const modal = document.getElementById("cyberConfirmModal");
        const titleEl = document.getElementById("cyberConfirmTitle");
        const msgEl = document.getElementById("cyberConfirmMessage");
        const okBtn = document.getElementById("cyberConfirmOkBtn");
        const cancelBtn = document.getElementById("cyberConfirmCancelBtn");

        if (!modal) {
            resolve(confirm(message));
            return;
        }

        if (titleEl) titleEl.textContent = title;
        if (msgEl) msgEl.textContent = message;
        if (okBtn) okBtn.textContent = confirmText;

        modal.classList.remove("hidden");

        const cleanup = () => {
            modal.classList.add("hidden");
            okBtn.removeEventListener("click", onOk);
            cancelBtn.removeEventListener("click", onCancel);
        };

        const onOk = () => {
            cleanup();
            resolve(true);
        };

        const onCancel = () => {
            cleanup();
            resolve(false);
        };

        okBtn.addEventListener("click", onOk);
        cancelBtn.addEventListener("click", onCancel);
    });
}

// In-UI Rich Notice Modal replacing bulky alert()
function showCyberNoticeModal(title, detailsHtml, copyContent = "") {
    const modal = document.getElementById("cyberNoticeModal");
    const titleEl = document.getElementById("cyberNoticeTitle");
    const bodyEl = document.getElementById("cyberNoticeBody");
    const copyBtn = document.getElementById("cyberNoticeCopyBtn");

    if (!modal) return;
    if (titleEl) titleEl.textContent = title;
    if (bodyEl) bodyEl.innerHTML = detailsHtml;

    if (copyBtn) {
        copyBtn.onclick = async () => {
            if (copyContent) {
                await navigator.clipboard.writeText(copyContent);
                showCyberToast("success", "Copied", "Notice content copied to clipboard!");
            }
        };
    }

    modal.classList.remove("hidden");
}

// ═══════════════════════════════════════════════════════════════════
// UNIVERSAL MODAL CLOSE & BACKDROP HANDLERS
// ═══════════════════════════════════════════════════════════════════
document.addEventListener("click", (e) => {
    if (e.target.closest(".modal-close-btn") || e.target.closest(".modal-dismiss-btn")) {
        const modal = e.target.closest(".modal-overlay");
        if (modal) modal.classList.add("hidden");
    } else if (e.target.classList.contains("modal-overlay")) {
        e.target.classList.add("hidden");
    }
});

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        document.querySelectorAll(".modal-overlay:not(.hidden)").forEach((m) => m.classList.add("hidden"));
    }
});

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
    return div.innerHTML.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function escapeJs(str) {
    return String(str || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/"/g, '\\"');
}

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS VISUAL CHARTS
// ═══════════════════════════════════════════════════════════════════

function renderBankDonutChart(banks, totalMulesOverride) {
    if (!banks || !banks.length) {
        $bankDonutSvg.innerHTML = '<circle cx="50" cy="50" r="38" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="14"/>';
        $bankLegend.innerHTML = '<div class="legend-item"><span>No data</span></div>';
        $donutCenterText.innerHTML = `0<small>Mules</small>`;
        return;
    }

    const total = totalMulesOverride || banks.reduce((acc, b) => acc + b.count, 0) || 1;
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
    $donutCenterText.innerHTML = `${total.toLocaleString()}<small>Mules</small>`;
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

// ═══════════════════════════════════════════════════════════════════
// MULTI-DIMENSIONAL THREAT FILTER ENGINE
// ═══════════════════════════════════════════════════════════════════

const selectedBrandFilters = new Set();
const selectedGeoFilters = new Set();
const geoMetadataMap = {
    "my": { city: "Kuala Lumpur", code: "MY" },
    "sg": { city: "Singapore", code: "SG" },
    "us": { city: "San Jose", code: "US" },
    "de": { city: "Frankfurt", code: "DE" },
    "hk": { city: "Hong Kong", code: "HK" },
    "jp": { city: "Tokyo", code: "JP" },
};

const BANK_ALIASES = {
    "maybank": ["maybank", "maybank2u", "maybznk2u", "mae"],
    "cimb bank": ["cimb", "cimbclicks", "cimb-clicks"],
    "cimb": ["cimb", "cimbclicks", "cimb-clicks"],
    "public bank": ["public", "pbb", "pbebank", "pbe"],
    "public": ["public", "pbb", "pbebank", "pbe"],
    "rhb bank": ["rhb", "rhbgroup", "rhbnow"],
    "rhb": ["rhb", "rhbgroup", "rhbnow"],
    "hong leong bank": ["hongleong", "hlb", "hlbb"],
    "hong leong": ["hongleong", "hlb", "hlbb"],
    "ambank": ["ambank", "ambankgroup", "amonline"],
    "bank islam": ["islam", "bankislam", "bimb"],
    "touch 'n go ewallet": ["touch", "tng", "tngdigital", "ewallet"],
    "touch 'n go": ["touch", "tng", "tngdigital", "ewallet"],
    "touch n go": ["touch", "tng", "tngdigital", "ewallet"],
    "grabpay malaysia": ["grab", "grabpay"],
    "grabpay": ["grab", "grabpay"],
    "shopeepay": ["shopee", "shopeepay"]
};

function matchesAnyBrand(entryUrl, brandsSet) {
    if (!brandsSet || brandsSet.size === 0) return true;
    const urlLower = String(entryUrl).toLowerCase();
    for (const brand of brandsSet) {
        const brandKey = brand.toLowerCase();
        const aliases = BANK_ALIASES[brandKey] || [brandKey];
        if (aliases.some(alias => urlLower.includes(alias))) {
            return true;
        }
    }
    return false;
}

function matchesAnyGeo(entry, geosSet) {
    if (!geosSet || geosSet.size === 0) return true;
    const cCode = (entry.country_code || "").toLowerCase();
    const cCity = (entry.city || "").toLowerCase();
    const cCountry = (entry.country || "").toLowerCase();

    for (const geo of geosSet) {
        const gLower = geo.toLowerCase();
        if (cCode === gLower || cCity.includes(gLower) || cCountry.includes(gLower)) {
            return true;
        }
    }
    return false;
}

function renderGeoRadar(nodes) {
    const group = document.getElementById("geoRadarNodesGroup");
    const legend = document.getElementById("geoNodesLegend");
    if (!group || !legend) return;

    if (!nodes || !nodes.length) {
        nodes = [
            { city: "Kuala Lumpur", country_code: "MY", threats: 111, asn: "TM Net (AS4788)", status: "critical" },
            { city: "Singapore", country_code: "SG", threats: 58, asn: "Singtel (AS7473)", status: "high" },
            { city: "San Jose", country_code: "US", threats: 42, asn: "Cloudflare Anycast (AS13335)", status: "medium" },
            { city: "Frankfurt", country_code: "DE", threats: 26, asn: "DigitalOcean (AS14061)", status: "medium" },
            { city: "Hong Kong", country_code: "HK", threats: 15, asn: "Tencent Cloud (AS132203)", status: "low" },
            { city: "Tokyo", country_code: "JP", threats: 10, asn: "AWS Tokyo (AS16509)", status: "low" },
        ];
    }

    const nodeConfig = {
        "kuala lumpur": { x: 630, y: 155, labelX: 645, labelY: 158, align: "start", leader: null },
        "singapore":    { x: 638, y: 175, labelX: 585, labelY: 215, align: "end",   leader: "638,175 605,210 585,210" },
        "san jose":     { x: 170, y: 92,  labelX: 95,  labelY: 82,  align: "end",   leader: "170,92 125,82 100,82" },
        "frankfurt":    { x: 465, y: 78,  labelX: 395, labelY: 70,  align: "end",   leader: "465,78 425,70 400,70" },
        "hong kong":    { x: 685, y: 125, labelX: 715, labelY: 135, align: "start", leader: "685,125 705,135 715,135" },
        "tokyo":        { x: 745, y: 92,  labelX: 765, labelY: 82,  align: "start", leader: "745,92 758,82 765,82" },
    };

    let svgHtml = "";
    let legendHtml = "";

    nodes.forEach(n => {
        const key = (n.city || "").toLowerCase().trim();
        const conf = nodeConfig[key] || { x: 450, y: 140, labelX: 470, labelY: 140, align: "start", leader: null };
        const isCritical = n.status === "critical";
        const isHigh = n.status === "high";
        const color = isCritical ? "#ef4444" : isHigh ? "#f59e0b" : "#06b6d4";
        const text = `${n.city} (${n.threats})`;
        const isSelected = selectedGeoFilters.has((n.country_code || '').toUpperCase()) || selectedGeoFilters.has((n.city || '').toUpperCase());

        if (conf.leader) {
            svgHtml += `<polyline points="${conf.leader}" fill="none" stroke="${color}" stroke-width="1.2" stroke-dasharray="2 2" opacity="0.75" />`;
        }

        if (isCritical || isHigh) {
            svgHtml += `<circle cx="${conf.x}" cy="${conf.y}" r="6" fill="none" stroke="${color}" stroke-width="1.8" class="radar-pulse-node" />`;
            if (isCritical) {
                svgHtml += `<circle cx="${conf.x}" cy="${conf.y}" r="12" fill="none" stroke="${color}" stroke-width="0.8" opacity="0.4" />`;
            }
        }

        svgHtml += `<circle cx="${conf.x}" cy="${conf.y}" r="4.5" fill="${color}" stroke="#ffffff" stroke-width="1.5" style="cursor: pointer;" onclick="toggleGeoFilter('${escapeJs(n.city)}', '${escapeJs(n.country_code)}')" />`;

        const badgeWidth = text.length * 7.2 + 12;
        const rectX = conf.align === "end" ? conf.labelX - badgeWidth : conf.labelX - 4;
        const textAnchor = conf.align === "end" ? "end" : "start";

        svgHtml += `
            <g style="cursor: pointer;" onclick="toggleGeoFilter('${escapeJs(n.city)}', '${escapeJs(n.country_code)}')">
                <rect x="${rectX}" y="${conf.labelY - 12}" width="${badgeWidth}" height="16" rx="4" fill="${isSelected ? color : 'rgba(10, 15, 30, 0.88)'}" stroke="${color}" stroke-width="${isSelected ? 2 : 0.8}" />
                <text x="${conf.labelX}" y="${conf.labelY}" fill="#ffffff" font-size="10.5" font-weight="600" font-family="'JetBrains Mono', monospace" text-anchor="${textAnchor}">${escapeHtml(text)}</text>
            </g>
        `;

        legendHtml += `
            <div class="geo-node-card ${isSelected ? 'active-geo-node' : ''}" onclick="toggleGeoFilter('${escapeJs(n.city)}', '${escapeJs(n.country_code)}')">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${color}; box-shadow: 0 0 8px ${color};"></span>
                        <strong style="color: #ffffff; font-size: 0.82rem;">${escapeHtml(n.city)}, ${n.country_code}</strong>
                    </div>
                    <span class="report-badge" style="font-size: 0.72rem; font-weight: 700; background: ${color}22; color: ${color}; border: 1px solid ${color}44;">${n.threats} attacks</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 2px;">
                    <span style="color: var(--text-muted); font-size: 0.72rem;">${escapeHtml(n.asn)}</span>
                    <span style="color: ${isSelected ? '#34d399' : 'var(--accent-cyan)'}; font-size: 0.7rem; font-family: monospace; font-weight: 700;">${isSelected ? '✓ ACTIVE' : '🔍 Filter'}</span>
                </div>
            </div>
        `;
    });

    group.innerHTML = svgHtml;
    legend.innerHTML = legendHtml;
}

function toggleGeoFilter(city, countryCode) {
    const code = (countryCode || city).toUpperCase();
    if (selectedGeoFilters.has(code)) {
        selectedGeoFilters.delete(code);
        showCyberToast("info", "Filter Removed", `Removed ${city} (${code}) from active filters.`);
    } else {
        selectedGeoFilters.add(code);
        geoMetadataMap[code.toLowerCase()] = { city, code };
        showCyberToast("info", "Location Filter Added", `Added ${city} (${code}) (${selectedGeoFilters.size} location(s) active).`);
    }
    syncFilterQuery();
    renderTelemetry();
    if (distributionsData) {
        apiFetch("/geo-threats").then(geo => renderGeoRadar(geo.nodes)).catch(() => {});
    }
}

function removeGeoFilter(code) {
    selectedGeoFilters.delete(code.toUpperCase());
    syncFilterQuery();
    renderTelemetry();
    if (distributionsData) {
        apiFetch("/geo-threats").then(geo => renderGeoRadar(geo.nodes)).catch(() => {});
    }
    showCyberToast("info", "Filter Removed", `Removed location filter.`);
}

function clearAllThreatFilters() {
    selectedBrandFilters.clear();
    selectedGeoFilters.clear();
    telemetryFilterText = "";
    const $search = document.getElementById("telemetrySearch");
    if ($search) $search.value = "";
    telemetryPagination.page = 1;
    renderTelemetry();
    refreshBrandMatrix();
    if (distributionsData) {
        apiFetch("/geo-threats").then(geo => renderGeoRadar(geo.nodes)).catch(() => {});
    }
    showCyberToast("info", "All Filters Cleared", "Displaying all live threat telemetry.");
}

function syncFilterQuery() {
    telemetryPagination.page = 1;
    const parts = [];
    if (selectedBrandFilters.size > 0) {
        parts.push(`bank:${Array.from(selectedBrandFilters).join(",")}`);
    }
    if (selectedGeoFilters.size > 0) {
        parts.push(`country:${Array.from(selectedGeoFilters).join(",")}`);
    }
    const queryStr = parts.join(" ");
    const $search = document.getElementById("telemetrySearch");
    if ($search) {
        $search.value = queryStr;
    }
    telemetryFilterText = queryStr;
}


async function refreshDistributions() {
    try {
        const data = await apiFetch("/distributions");
        distributionsData = data;
        renderBankDonutChart(data.banks, data.total_mules);
        renderTimelineBars(data.timeline);
        renderPlatformBars(data.platforms);
        renderInfraBars(data.infrastructure);

        const geo = await apiFetch("/geo-threats");
        renderGeoRadar(geo.nodes);
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

function evaluateHuntingFilter(entry, query) {
    if (!query) return true;
    const lowerQ = query.toLowerCase().trim();

    // Support field syntax: country:my, geo:kuala lumpur, city:singapore, bank:maybank, score:>0.85, score:<0.60, id:>50, url:.top
    const tokens = lowerQ.split(/\s+and\s+/i);
    return tokens.every(tok => {
        tok = tok.trim();
        if (tok.startsWith("country:")) {
            const val = tok.replace("country:", "").trim().toLowerCase();
            const cCode = (entry.country_code || "").toLowerCase();
            const cName = (entry.country || "").toLowerCase();
            return cCode === val || cName.includes(val);
        }
        if (tok.startsWith("geo:") || tok.startsWith("city:")) {
            const val = tok.replace(/(geo|city):/, "").trim().toLowerCase();
            const cCity = (entry.city || "").toLowerCase();
            const cName = (entry.country || "").toLowerCase();
            const cCode = (entry.country_code || "").toLowerCase();
            return cCity.includes(val) || cName.includes(val) || cCode === val;
        }
        if (tok.startsWith("bank:")) {
            const val = tok.replace("bank:", "").trim().toLowerCase();
            const bankAliases = {
                "maybank": ["maybank", "maybank2u", "maybznk2u", "mae"],
                "cimb": ["cimb", "cimbclicks", "cimb-clicks"],
                "cimb bank": ["cimb", "cimbclicks", "cimb-clicks"],
                "public": ["public", "pbb", "pbebank", "pbe"],
                "public bank": ["public", "pbb", "pbebank", "pbe"],
                "rhb": ["rhb", "rhbgroup", "rhbnow"],
                "rhb bank": ["rhb", "rhbgroup", "rhbnow"],
                "hong leong": ["hongleong", "hlb", "hlbb"],
                "hong leong bank": ["hongleong", "hlb", "hlbb"],
                "ambank": ["ambank", "ambankgroup", "amonline"],
                "bank islam": ["islam", "bankislam", "bimb"],
                "touch 'n go": ["touch", "tng", "tngdigital", "ewallet"],
                "touch 'n go ewallet": ["touch", "tng", "tngdigital", "ewallet"],
                "touch n go": ["touch", "tng", "tngdigital", "ewallet"],
                "grabpay": ["grab", "grabpay"],
                "shopeepay": ["shopee", "shopeepay"]
            };
            const aliases = bankAliases[val] || [val];
            const u = String(entry.malicious_url).toLowerCase();
            return aliases.some(alias => u.includes(alias));
        }
        if (tok.startsWith("score:>")) {
            const val = parseFloat(tok.replace("score:>", "").trim());
            return !isNaN(val) ? entry.bert_score >= val : true;
        }
        if (tok.startsWith("score:<")) {
            const val = parseFloat(tok.replace("score:<", "").trim());
            return !isNaN(val) ? entry.bert_score <= val : true;
        }
        if (tok.startsWith("id:>")) {
            const val = parseInt(tok.replace("id:>", "").trim(), 10);
            return !isNaN(val) ? entry.log_id >= val : true;
        }
        if (tok.startsWith("url:")) {
            const val = tok.replace("url:", "").trim();
            return String(entry.malicious_url).toLowerCase().includes(val);
        }
        return String(entry.log_id).includes(tok) || 
               String(entry.malicious_url).toLowerCase().includes(tok) ||
               String(entry.country || "").toLowerCase().includes(tok) ||
               String(entry.country_code || "").toLowerCase().includes(tok) ||
               String(entry.city || "").toLowerCase().includes(tok);
    });
}

function renderTelemetry() {
    let filtered = telemetryData;

    // 1. Multi-selected Brands (OR filter across all selected institutions)
    if (selectedBrandFilters.size > 0) {
        filtered = filtered.filter(e => matchesAnyBrand(e.malicious_url, selectedBrandFilters));
    }

    // 2. Multi-selected Geos (OR filter across all selected locations)
    if (selectedGeoFilters.size > 0) {
        filtered = filtered.filter(e => matchesAnyGeo(e, selectedGeoFilters));
    }

    // 3. Custom Search Query (if manual text entered)
    if (telemetryFilterText && !telemetryFilterText.startsWith("bank:") && !telemetryFilterText.startsWith("country:")) {
        filtered = filtered.filter(e => evaluateHuntingFilter(e, telemetryFilterText));
    }

    // 4. Score filter
    if (telemetryScoreFilter === "high") {
        filtered = filtered.filter(e => e.bert_score >= 0.85);
    } else if (telemetryScoreFilter === "medium") {
        filtered = filtered.filter(e => e.bert_score >= 0.60 && e.bert_score < 0.85);
    } else if (telemetryScoreFilter === "low") {
        filtered = filtered.filter(e => e.bert_score < 0.60);
    }

    $telemetryCount.textContent = filtered.length;

    // Render Active Multi-Filter Bar with individual removable chips!
    const $activeFilterBar = document.getElementById("activeGeoFilterContainer");
    if ($activeFilterBar) {
        const hasFilters = selectedBrandFilters.size > 0 || selectedGeoFilters.size > 0;
        if (hasFilters) {
            $activeFilterBar.style.display = "flex";
            const brandChips = Array.from(selectedBrandFilters).map(b => `
                <span class="geo-filter-pill geo-filter-pill--brand">
                    🏛️ <strong>${escapeHtml(b)}</strong>
                    <button class="geo-filter-pill__clear" onclick="removeBrandFilter('${escapeJs(b)}')" title="Remove ${escapeHtml(b)}">✕</button>
                </span>
            `).join("");

            const geoChips = Array.from(selectedGeoFilters).map(g => {
                const meta = geoMetadataMap[g.toLowerCase()] || { city: g, code: g };
                return `
                    <span class="geo-filter-pill geo-filter-pill--geo">
                        📍 <strong>${escapeHtml(meta.city)} (${escapeHtml(meta.code)})</strong>
                        <button class="geo-filter-pill__clear" onclick="removeGeoFilter('${escapeJs(meta.code)}')" title="Remove ${escapeHtml(meta.city)}">✕</button>
                    </span>
                `;
            }).join("");

            $activeFilterBar.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; flex-wrap: wrap; gap: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;">
                        <span style="font-size: 0.74rem; color: var(--text-muted); font-weight: 600;">Active Multi-Filters:</span>
                        ${brandChips}
                        ${geoChips}
                        <button class="action-btn action-btn--delete" style="padding: 2px 8px; font-size: 0.7rem;" onclick="clearAllThreatFilters()" title="Clear all active filters">
                            ✕ Clear All
                        </button>
                    </div>
                    <span style="font-size: 0.74rem; color: var(--text-muted); font-weight: 600;">
                        ${filtered.length} matching incident(s)
                    </span>
                </div>
            `;
        } else {
            $activeFilterBar.style.display = "none";
        }
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
                    <div style="display: flex; gap: 4px;">
                        <button class="action-btn" style="padding: 2px 6px; font-size: 0.7rem;" onclick="openIncidentReport(${e.log_id})">
                            📄 Dossier
                        </button>
                        <button class="action-btn action-btn--primary" style="padding: 2px 6px; font-size: 0.7rem;" onclick="openXaiAttribution(${e.log_id})">
                            🧠 XAI
                        </button>
                        <button class="action-btn" style="padding: 2px 6px; font-size: 0.7rem; border-color: rgba(99,102,241,0.4);" onclick="openThreatGraph(${e.log_id})">
                            🌲 Graph
                        </button>
                    </div>
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

        // Query Deep SSL/TLS Intelligence
        let sslHtml = "";
        try {
            const ssl = await apiFetch("/ssl-intel", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: report.target_url })
            });
            sslHtml = `
                <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 12px; font-size: 0.8rem;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                        <strong style="color: #fff;">🔒 SSL/TLS Certificate Provenance:</strong>
                        <span style="color: ${ssl.spoof_risk_score > 70 ? '#f87171' : '#34d399'}; font-weight: 700;">${escapeHtml(ssl.verdict)}</span>
                    </div>
                    <div>• <strong>CA Authority:</strong> ${escapeHtml(ssl.certificate_issuer)} (${escapeHtml(ssl.trust_tier)})</div>
                    <div>• <strong>Cipher Suite:</strong> <code>${escapeHtml(ssl.cipher_suite)}</code></div>
                    <div>• <strong>Est. Domain Lifespan:</strong> ${ssl.estimated_domain_age_days} days &nbsp;|&nbsp; <strong>SPF/MX Valid:</strong> ${ssl.dns_spf_record_present ? '✅ Yes' : '❌ Failed'}</div>
                </div>
            `;
        } catch (_err) {}

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

            ${sslHtml}

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
        showCyberToast("success", "Mule Ingested", `Account ${payload.account_number} (${payload.bank_name}) registered.`);
    } catch (err) {
        showCyberToast("danger", "Registration Failed", err.message);
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
                        playAlertSound();
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
            $simToggleBtn.className = "sim-toggle-btn on";
            $simToggleBtn.innerHTML = "⚡ Simulation: ACTIVE";
        } else {
            $simToggleBtn.className = "sim-toggle-btn off";
            $simToggleBtn.innerHTML = "⚡ Simulation: OFF";
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
    if (!$simToggleBtn) return;
    $simToggleBtn.disabled = true;
    try {
        const res = await fetch(`${API_BASE}/simulator/toggle`, { method: "POST" });
        const data = await res.json();
        if (data.simulator_running) {
            $simToggleBtn.className = "sim-toggle-btn on";
            $simToggleBtn.innerHTML = "⚡ Simulation: ACTIVE";
            showCyberToast("success", "Simulator Active", "Background threat simulator started generating live events.");
        } else {
            $simToggleBtn.className = "sim-toggle-btn off";
            $simToggleBtn.innerHTML = "⚡ Simulation: OFF";
            showCyberToast("info", "Simulator Paused", "Background threat simulator paused.");
        }
        refreshAll();
    } catch (err) {
        console.error("Failed to toggle simulator:", err);
        showCyberToast("danger", "Simulator Error", err.message);
    } finally {
        $simToggleBtn.disabled = false;
    }
}

if ($simToggleBtn) {
    $simToggleBtn.addEventListener("click", handleSimToggle);
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
            if (isDanger) playAlertSound();
        } catch (err) {
            showCyberToast("danger", "Inspection Failed", err.message);
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
        const confirmed = await showCyberConfirm("🛡️ System Quarantine Confirmation", `Quarantine domain '${dom}' system-wide and broadcast emergency SIEM alert?`, "Quarantine Domain");
        if (!confirmed) return;

        try {
            await apiFetch("/domains/quarantine", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: dom, reason: `SOC Manual Quarantine from Incident ${currentReportData.incident_id}` })
            });
            showCyberToast("danger", "Domain Quarantined", `🛡️ Domain '${dom}' has been quarantined system-wide!`);
        } catch (err) {
            showCyberToast("danger", "Quarantine Failed", err.message);
        }
    });
}

if ($whitelistCurrentBtn) {
    $whitelistCurrentBtn.addEventListener("click", async () => {
        if (!currentReportData || !currentReportData.target_url) return;
        let dom = currentReportData.target_url;
        try { dom = new URL(currentReportData.target_url).hostname || dom; } catch (_e) {}
        const confirmed = await showCyberConfirm("✅ Safe Whitelist Exemption", `Whitelist domain '${dom}' as verified safe for 24 hours?`, "Whitelist Domain");
        if (!confirmed) return;

        try {
            await apiFetch("/domains/whitelist", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: dom, reason: "SOC Verified Safe / False Positive Exemption", ttl_hours: 24 })
            });
            showCyberToast("success", "Domain Whitelisted", `✅ Domain '${dom}' has been whitelisted for 24 hours.`);
        } catch (err) {
            showCyberToast("danger", "Whitelist Failed", err.message);
        }
    });
}

if ($copyTakedownBtn) {
    $copyTakedownBtn.addEventListener("click", async () => {
        if (!currentReportLogId) return;
        try {
            const notice = await apiFetch(`/telemetry/${currentReportLogId}/takedown-notice`);
            const detailsHtml = `
                <div style="background: rgba(15, 23, 42, 0.7); padding: 10px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 10px; font-size: 0.8rem;">
                    <div><strong>Recipient Abuse Desk:</strong> <code style="color: var(--accent-cyan);">${escapeHtml(notice.abuse_email)}</code></div>
                    <div><strong>Subject:</strong> <code>${escapeHtml(notice.subject)}</code></div>
                </div>
                <pre style="background: rgba(0, 0, 0, 0.5); padding: 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06); font-family: monospace; font-size: 0.76rem; max-height: 200px; overflow-y: auto; white-space: pre-wrap; color: #e2e8f0;">${escapeHtml(notice.body)}</pre>
            `;
            showCyberNoticeModal("📋 RFC 2142 Abuse Takedown Notice", detailsHtml, notice.body);
            showCyberToast("info", "Takedown Generated", "RFC 2142 Abuse Notice ready for review and copy.");
        } catch (err) {
            showCyberToast("danger", "Takedown Failed", err.message);
        }
    });
}

// Webhook Modal Listeners & Test Pinger
const $webhookModal = document.getElementById("webhookModal");
const $openWebhookModalBtn = document.getElementById("openWebhookModalBtn");
const $closeWebhookModalBtn = document.getElementById("closeWebhookModalBtn");
const $cancelWebhookBtn = document.getElementById("cancelWebhookBtn");
const $webhookForm = document.getElementById("webhookForm");
const $webhookStatusMsg = document.getElementById("webhookStatusMsg");

function openWebhookModal() {
    if ($webhookModal) {
        $webhookModal.classList.remove("hidden");
        if ($webhookStatusMsg) $webhookStatusMsg.style.display = "none";
    }
}

function closeWebhookModal() {
    if ($webhookModal) $webhookModal.classList.add("hidden");
}

if ($openWebhookModalBtn) $openWebhookModalBtn.addEventListener("click", openWebhookModal);
if ($closeWebhookModalBtn) $closeWebhookModalBtn.addEventListener("click", closeWebhookModal);
if ($cancelWebhookBtn) $cancelWebhookBtn.addEventListener("click", closeWebhookModal);

async function handleTestPing(channel, urlInputId, chatInputId = null) {
    const url = document.getElementById(urlInputId)?.value.trim();
    const chat = chatInputId ? document.getElementById(chatInputId)?.value.trim() : null;
    if (!url) {
        alert("Please enter a webhook URL or token first.");
        return;
    }

    if ($webhookStatusMsg) {
        $webhookStatusMsg.style.display = "block";
        $webhookStatusMsg.style.background = "rgba(6, 182, 212, 0.15)";
        $webhookStatusMsg.style.color = "var(--accent-cyan)";
        $webhookStatusMsg.textContent = `Dispatching test ping to ${channel}...`;
    }

    try {
        const res = await apiFetch("/webhooks/test-ping", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ channel, target_url: url, chat_id: chat })
        });

        if ($webhookStatusMsg) {
            if (res.success) {
                $webhookStatusMsg.style.background = "rgba(16, 185, 129, 0.15)";
                $webhookStatusMsg.style.color = "#34d399";
                $webhookStatusMsg.textContent = `✅ ${channel} Test Ping Succeeded! (${res.status_code || 200})`;
            } else {
                $webhookStatusMsg.style.background = "rgba(239, 68, 68, 0.15)";
                $webhookStatusMsg.style.color = "#f87171";
                $webhookStatusMsg.textContent = `❌ Test Ping Failed: ${res.error || 'HTTP ' + res.status_code}`;
            }
        }
    } catch (err) {
        if ($webhookStatusMsg) {
            $webhookStatusMsg.style.background = "rgba(239, 68, 68, 0.15)";
            $webhookStatusMsg.style.color = "#f87171";
            $webhookStatusMsg.textContent = "Error: " + err.message;
        }
    }
}

document.getElementById("testDiscordBtn")?.addEventListener("click", () => handleTestPing("discord", "discordWebhookInput"));
document.getElementById("testSlackBtn")?.addEventListener("click", () => handleTestPing("slack", "slackWebhookInput"));
document.getElementById("testTelegramBtn")?.addEventListener("click", () => handleTestPing("telegram", "telegramTokenInput", "telegramChatInput"));

if ($webhookForm) {
    $webhookForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            discord_webhook: document.getElementById("discordWebhookInput")?.value || "",
            slack_webhook: document.getElementById("slackWebhookInput")?.value || "",
            telegram_token: document.getElementById("telegramTokenInput")?.value || "",
            telegram_chat_id: document.getElementById("telegramChatInput")?.value || "",
            enabled: true
        };

        try {
            await apiFetch("/webhooks/save", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            alert("✅ Webhook configuration saved successfully!");
            closeWebhookModal();
        } catch (err) {
            alert("Failed to save webhook settings: " + err.message);
        }
    });
}

// Executive CISO Report Modal
const $cisoReportModal = document.getElementById("cisoReportModal");
const $openCisoReportBtn = document.getElementById("openCisoReportBtn");
const $closeCisoModalBtn = document.getElementById("closeCisoModalBtn");
const $dismissCisoBtn = document.getElementById("dismissCisoBtn");
const $cisoReportContent = document.getElementById("cisoReportContent");

async function openCisoReport() {
    if (!$cisoReportModal || !$cisoReportContent) return;
    $cisoReportModal.classList.remove("hidden");
    $cisoReportContent.innerHTML = "Generating live CISO threat intelligence briefing...";

    try {
        const r = await apiFetch("/export/executive-report");
        const banksHtml = (r.top_targeted_entities || []).map(b => `
            <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                <span>${escapeHtml(b.brand)}</span>
                <strong>${b.mules} Flagged Mules</strong>
            </div>
        `).join("");

        const recsHtml = (r.strategic_recommendations || []).map(rec => `
            <li style="margin-bottom: 6px;">${escapeHtml(rec)}</li>
        `).join("");

        $cisoReportContent.innerHTML = `
            <div style="background: rgba(15, 23, 42, 0.7); padding: 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <strong>Document Reference:</strong> <code>${escapeHtml(r.report_id)}</code>
                    <span style="color: #34d399; font-weight: 700;">Uptime: ${r.executive_summary.system_uptime}</span>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.82rem;">
                    <div>• <strong>Mean Time to Detect (MTTD):</strong> <span style="color: var(--accent-cyan); font-weight: 700;">${r.executive_summary.mean_time_to_detect_seconds}s</span></div>
                    <div>• <strong>Threats Intercepted:</strong> <span style="color: #f87171; font-weight: 700;">${r.executive_summary.total_phishing_intercepted}</span></div>
                    <div>• <strong>Average AI Confidence:</strong> ${r.executive_summary.average_ai_confidence}%</div>
                    <div>• <strong>Active Mule Accounts:</strong> ${r.executive_summary.active_mule_syndicates}</div>
                </div>
            </div>

            <div style="margin-bottom: 14px;">
                <strong style="color: #fff;">Top Targeted Malaysian Institutions:</strong>
                <div style="margin-top: 6px; font-size: 0.82rem;">
                    ${banksHtml || '<div>No bank syndicates recorded.</div>'}
                </div>
            </div>

            <div>
                <strong style="color: #fff;">Strategic CISO Recommendations:</strong>
                <ul style="margin-top: 6px; padding-left: 20px; font-size: 0.8rem; line-height: 1.6;">
                    ${recsHtml}
                </ul>
            </div>
        `;
    } catch (err) {
        $cisoReportContent.innerHTML = `<span style="color: #f87171;">Failed to generate CISO briefing: ${escapeHtml(err.message)}</span>`;
    }
}

if ($openCisoReportBtn) $openCisoReportBtn.addEventListener("click", openCisoReport);
if ($closeCisoModalBtn) $closeCisoModalBtn.addEventListener("click", () => $cisoReportModal.classList.add("hidden"));
// ═══════════════════════════════════════════════════════════════════
// PHASE 8: BRAND CAMPAIGN MATRIX & XAI TOKEN ATTRIBUTION
// ═══════════════════════════════════════════════════════════════════

async function refreshBrandMatrix() {
    try {
        const res = await apiFetch("/brand-campaign-matrix");
        const container = document.getElementById("brandMatrixGrid");
        if (!container) return;

        const countBadge = document.getElementById("brandMatrixCount");
        if (countBadge) countBadge.textContent = `${res.total_tracked_institutions} Tracked`;

        container.innerHTML = (res.brands || []).map(b => {
            const isSelected = selectedBrandFilters.has(b.brand);
            const riskClass = b.risk_level === "CRITICAL" ? "brand-risk-badge--critical" :
                              b.risk_level === "ELEVATED" ? "brand-risk-badge--elevated" : "brand-risk-badge--monitored";
            return `
                <div class="brand-matrix-card ${isSelected ? 'active-brand-card' : ''}" onclick="toggleBrandFilter('${escapeJs(b.brand)}')">
                    <div class="brand-matrix-header">
                        <span class="brand-matrix-title">
                            <span>${b.logo}</span> ${escapeHtml(b.brand)}
                        </span>
                        <span class="brand-risk-badge ${riskClass}">${b.risk_level}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.76rem; color: var(--text-muted); margin-top: 4px;">
                        <span>Active Clones: <strong style="color: #fff;">${b.active_threats}</strong></span>
                        <span>Mules: <strong style="color: #f87171;">${b.flagged_mules}</strong></span>
                    </div>
                    <div style="font-size: 0.7rem; color: ${isSelected ? '#34d399' : 'var(--accent-cyan)'}; font-weight: 700; text-align: right; margin-top: 2px;">
                        ${isSelected ? '✓ ACTIVE' : 'Filter Stream &rarr;'}
                    </div>
                </div>
            `;
        }).join("");
    } catch (_e) {}
}

function toggleBrandFilter(brand) {
    if (selectedBrandFilters.has(brand)) {
        selectedBrandFilters.delete(brand);
        showCyberToast("info", "Filter Removed", `Removed ${brand} from active filters.`);
    } else {
        selectedBrandFilters.add(brand);
        showCyberToast("info", "Institution Filter Added", `Added ${brand} (${selectedBrandFilters.size} bank(s) active).`);
    }
    syncFilterQuery();
    renderTelemetry();
    refreshBrandMatrix();
}

function removeBrandFilter(brand) {
    selectedBrandFilters.delete(brand);
    syncFilterQuery();
    renderTelemetry();
    refreshBrandMatrix();
    showCyberToast("info", "Filter Removed", `Removed ${brand}.`);
}

// XAI Modal Attributions
async function openXaiAttribution(logId) {
    const modal = document.getElementById("xaiModal");
    const body = document.getElementById("xaiModalBody");
    if (!modal || !body) return;

    modal.classList.remove("hidden");
    body.innerHTML = "Generating Explainable AI (XAI) feature attribution heatmap...";

    try {
        const data = await apiFetch(`/telemetry/${logId}/xai`);
        
        const tokenChipsHtml = (data.tokens || []).map(t => {
            return `<span class="xai-token-chip category-${t.category}" title="Category: ${t.category} | Weight: ${t.weight}">${escapeHtml(t.token)}</span>`;
        }).join(" ");

        const driversHtml = (data.top_drivers || []).map(d => `
            <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-family: monospace;">${escapeHtml(d)}</span>
        `).join(" ");

        body.innerHTML = `
            <div style="background: rgba(15, 23, 42, 0.7); padding: 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <strong>Threat Target:</strong> <code style="color: var(--accent-cyan); word-break: break-all;">${escapeHtml(data.text)}</code>
                </div>
                <div style="font-size: 0.82rem; color: var(--text-muted);">
                    AI Phishing Confidence: <strong style="color: #f87171;">${(data.base_score * 100).toFixed(1)}%</strong>
                </div>
            </div>

            <div style="margin-bottom: 12px;">
                <strong style="color: #fff;">Interactive Semantic Heatmap (Hover for Weights):</strong>
                <div class="xai-heatmap-container" style="margin-top: 8px;">
                    ${tokenChipsHtml}
                </div>
            </div>

            <div style="margin-bottom: 12px;">
                <strong style="color: #fff;">Top Contributing Threat Drivers:</strong>
                <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px;">
                    ${driversHtml || '<span>No high-weight single token.</span>'}
                </div>
            </div>

            <div style="background: rgba(99, 102, 241, 0.12); border-left: 3px solid #6366f1; padding: 10px; border-radius: 4px; font-size: 0.8rem; line-height: 1.5;">
                <strong>Explainable AI Summary:</strong> ${escapeHtml(data.explanation)}
            </div>
        `;
    } catch (err) {
        body.innerHTML = `<span style="color: #f87171;">Failed to generate XAI attribution: ${escapeHtml(err.message)}</span>`;
    }
}

// Sinkhole & SIEM Modal Listeners
const $sinkholeModal = document.getElementById("sinkholeModal");
const $openSinkholeModalBtn = document.getElementById("openSinkholeModalBtn");
const $closeSinkholeModalBtn = document.getElementById("closeSinkholeModalBtn");
const $dismissSinkholeBtn = document.getElementById("dismissSinkholeBtn");

if ($openSinkholeModalBtn) $openSinkholeModalBtn.addEventListener("click", () => $sinkholeModal?.classList.remove("hidden"));
if ($closeSinkholeModalBtn) $closeSinkholeModalBtn.addEventListener("click", () => $sinkholeModal?.classList.add("hidden"));
if ($dismissSinkholeBtn) $dismissSinkholeBtn.addEventListener("click", () => $sinkholeModal?.classList.add("hidden"));

const $closeXaiModalBtn = document.getElementById("closeXaiModalBtn");
const $dismissXaiBtn = document.getElementById("dismissXaiBtn");
if ($closeXaiModalBtn) $closeXaiModalBtn.addEventListener("click", () => document.getElementById("xaiModal")?.classList.add("hidden"));
if ($dismissXaiBtn) $dismissXaiBtn.addEventListener("click", () => document.getElementById("xaiModal")?.classList.add("hidden"));

// ═══════════════════════════════════════════════════════════════════
// MULTI-TONE SOC AUDIO SYNTHESIZER ENGINE (Web Audio API)
// ═══════════════════════════════════════════════════════════════════

let audioContext = null;
let isAudioEnabled = localStorage.getItem("phishguard_audio_enabled") === "true";
let currentTone = localStorage.getItem("phishguard_audio_tone") || "tactical";

const $audioToggleBtn = document.getElementById("audioToggleBtn");
const $audioStatusText = document.getElementById("audioStatusText");
const $audioToneSelect = document.getElementById("audioToneSelect");

if ($audioToneSelect) {
    $audioToneSelect.value = currentTone;
    $audioToneSelect.addEventListener("change", (e) => {
        currentTone = e.target.value;
        localStorage.setItem("phishguard_audio_tone", currentTone);
        // Play instant live acoustic preview of selected tone
        playTone(currentTone, true);
    });
}

if ($audioToggleBtn) {
    if (isAudioEnabled) {
        $audioToggleBtn.classList.add("active");
        if ($audioStatusText) $audioStatusText.textContent = "Sound: ON";
    }

    $audioToggleBtn.addEventListener("click", () => {
        isAudioEnabled = !isAudioEnabled;
        localStorage.setItem("phishguard_audio_enabled", isAudioEnabled);
        if ($audioStatusText) $audioStatusText.textContent = isAudioEnabled ? "Sound: ON" : "Sound: OFF";
        $audioToggleBtn.classList.toggle("active", isAudioEnabled);
        if (isAudioEnabled) {
            playTone(currentTone, true);
        }
    });
}

function playTone(tone, forcePreview = false) {
    if (!isAudioEnabled && !forcePreview) return;
    try {
        if (!audioContext) {
            audioContext = new (window.AudioContext || window.webkitAudioContext)();
        }
        if (audioContext.state === "suspended") {
            audioContext.resume();
        }

        const now = audioContext.currentTime;

        if (tone === "warhorn") {
            // Low dual-sawtooth cyberpunk war horn
            const osc1 = audioContext.createOscillator();
            const osc2 = audioContext.createOscillator();
            const gain = audioContext.createGain();

            osc1.type = "sawtooth";
            osc2.type = "sawtooth";
            osc1.frequency.setValueAtTime(140, now);
            osc2.frequency.setValueAtTime(145, now);
            osc1.frequency.exponentialRampToValueAtTime(75, now + 0.6);
            osc2.frequency.exponentialRampToValueAtTime(78, now + 0.6);

            gain.gain.setValueAtTime(0.3, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.65);

            osc1.connect(gain);
            osc2.connect(gain);
            gain.connect(audioContext.destination);

            osc1.start(now);
            osc2.start(now);
            osc1.stop(now + 0.65);
            osc2.stop(now + 0.65);
        } else if (tone === "sonar") {
            // High-Q Submarine Sonar Acoustic Ping
            const osc = audioContext.createOscillator();
            const gain = audioContext.createGain();

            osc.type = "sine";
            osc.frequency.setValueAtTime(1050, now);
            osc.frequency.exponentialRampToValueAtTime(850, now + 0.8);

            gain.gain.setValueAtTime(0.35, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.85);

            osc.connect(gain);
            gain.connect(audioContext.destination);

            osc.start(now);
            osc.stop(now + 0.85);
        } else if (tone === "matrix") {
            // Matrix CRT Terminal Triple-Chirp Arpeggio
            [523.25, 659.25, 1046.50].forEach((freq, i) => {
                const osc = audioContext.createOscillator();
                const gain = audioContext.createGain();
                const start = now + (i * 0.08);

                osc.type = "square";
                osc.frequency.setValueAtTime(freq, start);

                gain.gain.setValueAtTime(0.18, start);
                gain.gain.exponentialRampToValueAtTime(0.001, start + 0.12);

                osc.connect(gain);
                gain.connect(audioContext.destination);

                osc.start(start);
                osc.stop(start + 0.12);
            });
        } else {
            // Tactical Double Bleep (Default)
            [880, 1760].forEach((freq, i) => {
                const osc = audioContext.createOscillator();
                const gain = audioContext.createGain();
                const start = now + (i * 0.08);

                osc.type = "sine";
                osc.frequency.setValueAtTime(freq, start);

                gain.gain.setValueAtTime(0.25, start);
                gain.gain.exponentialRampToValueAtTime(0.001, start + 0.1);

                osc.connect(gain);
                gain.connect(audioContext.destination);

                osc.start(start);
                osc.stop(start + 0.1);
            });
        }
    } catch (_err) {}
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 9: AUTONOMOUS PLAYBOOKS, TYPOSQUAT RADAR & ATTACK GRAPH
// ═══════════════════════════════════════════════════════════════════

// Simulation Speed Controller
const $simSpeedSelect = document.getElementById("simSpeedSelect");
if ($simSpeedSelect) {
    $simSpeedSelect.addEventListener("change", async (e) => {
        const speedVal = parseFloat(e.target.value) || 1.0;
        try {
            await apiFetch("/simulator/speed", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ speed: speedVal })
            });
        } catch (_e) {}
    });
}

// Autonomous Playbooks Modal
const $playbookModal = document.getElementById("playbookModal");
const $openPlaybooksBtn = document.getElementById("openPlaybooksBtn");
const $closePlaybookModalBtn = document.getElementById("closePlaybookModalBtn");
const $dismissPlaybookBtn = document.getElementById("dismissPlaybookBtn");
const $playbookModalContent = document.getElementById("playbookModalContent");

async function openPlaybooksModal() {
    if (!$playbookModal || !$playbookModalContent) return;
    $playbookModal.classList.remove("hidden");
    $playbookModalContent.innerHTML = "Fetching autonomous SOC playbooks and execution history...";

    try {
        const [pbData, histData] = await Promise.all([
            apiFetch("/playbooks"),
            apiFetch("/playbooks/history")
        ]);

        const playbooksHtml = (pbData.playbooks || []).map(p => `
            <div style="background: rgba(15, 23, 42, 0.7); padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <strong style="color: #fff;">${escapeHtml(p.name)}</strong>
                    <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 6px; border-radius: 4px; font-size: 0.72rem; font-weight: 700;">${escapeHtml(p.severity)}</span>
                </div>
                <div style="font-size: 0.78rem; color: var(--accent-cyan); margin-bottom: 6px;">
                    • <strong>Trigger:</strong> ${escapeHtml(p.trigger)}
                </div>
                <div style="font-size: 0.76rem; color: var(--text-secondary);">
                    <strong>Automated Remediation Actions:</strong>
                    <ul style="margin-top: 3px; padding-left: 18px; line-height: 1.4;">
                        ${(p.actions || []).map(a => `<li>${escapeHtml(a)}</li>`).join("")}
                    </ul>
                </div>
                <div style="text-align: right; margin-top: 8px;">
                    <button class="action-btn action-btn--primary" style="padding: 2px 8px; font-size: 0.72rem;" onclick="manualRunPlaybook('${escapeHtml(p.id)}')">
                        ⚡ Execute Remediation
                    </button>
                </div>
            </div>
        `).join("");

        const historyHtml = (histData.history || []).slice(0, 5).map(h => `
            <div style="background: rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 6px; margin-bottom: 6px; font-size: 0.75rem;">
                <div style="display: flex; justify-content: space-between;">
                    <strong>${escapeHtml(h.execution_id)} (${escapeHtml(h.playbook_name)})</strong>
                    <span style="color: #34d399; font-weight: 700;">${escapeHtml(h.status)}</span>
                </div>
                <div style="color: var(--text-muted); margin-top: 2px;">
                    Target: <code>${escapeHtml(h.target_url)}</code>
                </div>
            </div>
        `).join("");

        $playbookModalContent.innerHTML = `
            <div style="margin-bottom: 14px;">
                <strong style="color: #fff; font-size: 0.9rem;">Configured Autonomous Remediation Workflows:</strong>
                <div style="margin-top: 8px;">${playbooksHtml}</div>
            </div>

            <div>
                <strong style="color: #fff; font-size: 0.9rem;">Recent Autonomous Audit Trail:</strong>
                <div style="margin-top: 8px;">${historyHtml || '<div style="color: var(--text-muted);">No automated actions executed yet in this session.</div>'}</div>
            </div>
        `;
    } catch (err) {
        $playbookModalContent.innerHTML = `<span style="color: #f87171;">Failed to load playbooks: ${escapeHtml(err.message)}</span>`;
    }
}

async function manualRunPlaybook(playbookId) {
    try {
        const res = await apiFetch("/playbooks/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ playbook_id: playbookId, target_url: "https://maybank2u-secure-verify.top/auth", target_bank: "Maybank", confidence: 0.96 })
        });
        showCyberToast("success", "Playbook Executed", `Execution ID: ${res.execution_id}`);
        openPlaybooksModal();
    } catch (err) {
        showCyberToast("danger", "Execution Failed", err.message);
    }
}

if ($openPlaybooksBtn) $openPlaybooksBtn.addEventListener("click", openPlaybooksModal);
if ($closePlaybookModalBtn) $closePlaybookModalBtn.addEventListener("click", () => $playbookModal?.classList.add("hidden"));
if ($dismissPlaybookBtn) $dismissPlaybookBtn.addEventListener("click", () => $playbookModal?.classList.add("hidden"));

// Pre-Emptive Typosquat Radar Modal
const $typosquatModal = document.getElementById("typosquatModal");
const $openTyposquatBtn = document.getElementById("openTyposquatBtn");
const $closeTyposquatModalBtn = document.getElementById("closeTyposquatModalBtn");
const $dismissTyposquatBtn = document.getElementById("dismissTyposquatBtn");
const $typosquatModalContent = document.getElementById("typosquatModalContent");

async function openTyposquatModal() {
    if (!$typosquatModal || !$typosquatModalContent) return;
    $typosquatModal.classList.remove("hidden");
    $typosquatModalContent.innerHTML = "Computing pre-emptive homoglyph and IDN Punycode radar across 10 institutions...";

    try {
        const res = await apiFetch("/typosquat-radar");
        
        const institutionsHtml = (res.institutions || []).map(inst => {
            const variantsHtml = (inst.variants || []).map(v => `
                <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(15, 23, 42, 0.5); padding: 6px 10px; border-radius: 6px; margin-bottom: 4px; font-size: 0.75rem;">
                    <div>
                        <strong style="color: var(--accent-cyan); font-family: monospace;">${escapeHtml(v.variant)}</strong>
                        <span style="opacity: 0.7; font-size: 0.7rem; margin-left: 6px;">(${escapeHtml(v.punycode)})</span>
                        <div style="font-size: 0.7rem; color: var(--text-muted);">${escapeHtml(v.technique)}</div>
                    </div>
                    <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 6px; border-radius: 4px; font-weight: 700;">${v.risk_score}% Risk</span>
                </div>
            `).join("");

            return `
                <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); padding: 12px; border-radius: 8px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <strong style="color: #fff; font-size: 0.88rem;">${inst.logo} ${escapeHtml(inst.brand)}</strong>
                        <span style="font-size: 0.75rem; color: var(--text-muted);">Primary: <code>${escapeHtml(inst.primary_domain)}</code></span>
                    </div>
                    <div>${variantsHtml}</div>
                </div>
            `;
        }).join("");

        $typosquatModalContent.innerHTML = `
            <div style="background: rgba(99, 102, 241, 0.1); border-left: 3px solid #6366f1; padding: 10px; border-radius: 4px; font-size: 0.8rem; margin-bottom: 12px;">
                <strong>Radar Status:</strong> Active monitoring across <strong>${res.total_tracked_brands} financial entities</strong> &bull; <strong>${res.total_pre_emptive_variants} pre-emptively sinkholed permutations</strong>.
            </div>
            <div>${institutionsHtml}</div>
        `;
    } catch (err) {
        $typosquatModalContent.innerHTML = `<span style="color: #f87171;">Failed to load Typosquat Radar: ${escapeHtml(err.message)}</span>`;
    }
}

if ($openTyposquatBtn) $openTyposquatBtn.addEventListener("click", openTyposquatModal);
if ($closeTyposquatModalBtn) $closeTyposquatModalBtn.addEventListener("click", () => $typosquatModal?.classList.add("hidden"));
if ($dismissTyposquatBtn) $dismissTyposquatBtn.addEventListener("click", () => $typosquatModal?.classList.add("hidden"));

// Interactive SVG Threat Attack Tree Visualizer
const $threatGraphModal = document.getElementById("threatGraphModal");
const $closeThreatGraphModalBtn = document.getElementById("closeThreatGraphModalBtn");
const $dismissThreatGraphBtn = document.getElementById("dismissThreatGraphBtn");
const $threatGraphModalContent = document.getElementById("threatGraphModalContent");

async function openThreatGraph(logId) {
    if (!$threatGraphModal || !$threatGraphModalContent) return;
    $threatGraphModal.classList.remove("hidden");
    $threatGraphModalContent.innerHTML = "Generating interactive attack tree graph...";

    try {
        const data = await apiFetch(`/threat-graph/${logId}`);
        
        // Render stylized SVG attack graph
        const nodes = data.nodes || [];
        const links = data.links || [];

        const nodePositions = {
            "attacker": { x: 80, y: 70 },
            "victim":   { x: 80, y: 190 },
            "domain":   { x: 280, y: 130 },
            "brand":    { x: 480, y: 70 },
            "mule_0":   { x: 480, y: 140 },
            "mule_1":   { x: 480, y: 200 },
            "mule_2":   { x: 480, y: 260 },
        };

        const linesSvg = links.map(l => {
            const src = nodePositions[l.source] || { x: 100, y: 100 };
            const tgt = nodePositions[l.target] || { x: 300, y: 100 };
            return `
                <line x1="${src.x}" y1="${src.y}" x2="${tgt.x}" y2="${tgt.y}" stroke="#6366f1" stroke-width="2" stroke-dasharray="4 2" opacity="0.6"/>
            `;
        }).join("");

        const nodesSvg = nodes.map(n => {
            const pos = nodePositions[n.id] || { x: 300, y: 100 };
            return `
                <g transform="translate(${pos.x}, ${pos.y})">
                    <circle r="18" fill="rgba(15, 23, 42, 0.9)" stroke="${n.color}" stroke-width="2" />
                    <text text-anchor="middle" y="5" font-size="12">${n.icon || '📌'}</text>
                    <text text-anchor="middle" y="32" fill="#fff" font-size="10" font-weight="600" font-family="sans-serif">${escapeHtml(n.label)}</text>
                </g>
            `;
        }).join("");

        $threatGraphModalContent.innerHTML = `
            <div style="background: rgba(15, 23, 42, 0.7); padding: 10px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 12px; display: flex; justify-content: space-between; font-size: 0.8rem;">
                <strong>Incident Reference: <code>${escapeHtml(data.incident_id)}</code></strong>
                <span style="color: #f87171; font-weight: 700;">Phishing Probability: ${(data.confidence * 100).toFixed(1)}%</span>
            </div>
            <div style="background: radial-gradient(circle, rgba(99, 102, 241, 0.1) 0%, rgba(10, 13, 20, 0.9) 100%); border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); overflow: hidden;">
                <svg viewBox="0 0 620 300" style="width: 100%; height: 300px; display: block;">
                    ${linesSvg}
                    ${nodesSvg}
                </svg>
            </div>
        `;
    } catch (err) {
        $threatGraphModalContent.innerHTML = `<span style="color: #f87171;">Failed to render Attack Tree: ${escapeHtml(err.message)}</span>`;
    }
}

if ($closeThreatGraphModalBtn) $closeThreatGraphModalBtn.addEventListener("click", () => $threatGraphModal?.classList.add("hidden"));
if ($dismissThreatGraphBtn) $dismissThreatGraphBtn.addEventListener("click", () => $threatGraphModal?.classList.add("hidden"));


// Initial load & stream
async function masterRefresh() {
    await refreshAll();
    await refreshBrandMatrix();
}

masterRefresh();
refreshSystemHealth();
initSseStream();
setInterval(masterRefresh, REFRESH_MS);
setInterval(refreshSystemHealth, 10_000);



