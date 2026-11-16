/**
 * PhishGuard-AI — SOC Dashboard Session Gate (v3.2.0)
 * ====================================================
 * Every /api/v1/dashboard route requires administrative authentication.
 * This script:
 *   1. Probes GET /auth/session on load.
 *   2. If there is no session, shows a sign-in dialog and holds every
 *      dashboard API call until the operator signs in.
 *   3. Exchanges the admin key for an HttpOnly, SameSite=Strict session
 *      cookie via POST /auth/login. The key itself is never stored in
 *      localStorage / sessionStorage and never appears in a URL.
 *   4. Re-opens the dialog if a later call returns 401 (session expired).
 *
 * The cookie (rather than an Authorization header) is used so that
 * EventSource streams and <a download> export links are authenticated too.
 */
(function () {
    "use strict";

    const AUTH_BASE = "/api/v1/dashboard/auth";
    const nativeFetch = window.fetch.bind(window);
    let dialogOpen = false;

    function isDashboardApi(input) {
        const url = typeof input === "string" ? input : (input && input.url) || "";
        return url.indexOf("/api/v1/dashboard") !== -1 && url.indexOf("/api/v1/dashboard/auth/") === -1;
    }

    function el(tag, styles, text) {
        const node = document.createElement(tag);
        if (styles) node.style.cssText = styles;
        if (text) node.textContent = text;
        return node;
    }

    function showSignIn(message) {
        if (dialogOpen) return;
        dialogOpen = true;

        const overlay = el("div",
            "position:fixed;inset:0;z-index:2147483000;background:rgba(6,9,17,0.92);" +
            "display:flex;align-items:center;justify-content:center;font-family:Inter,system-ui,sans-serif;");
        overlay.setAttribute("role", "dialog");
        overlay.setAttribute("aria-modal", "true");
        overlay.setAttribute("aria-labelledby", "pgAuthTitle");

        const card = el("form",
            "width:min(420px,calc(100vw - 32px));background:#0f172a;border:1px solid rgba(99,102,241,0.45);" +
            "border-radius:14px;padding:28px;box-shadow:0 20px 60px rgba(0,0,0,0.6);color:#f1f5f9;");
        const title = el("h2", "margin:0 0 6px;font-size:1.15rem;", "SOC dashboard sign-in");
        title.id = "pgAuthTitle";
        const hint = el("p", "margin:0 0 18px;font-size:0.85rem;color:#94a3b8;line-height:1.5;",
            message || "Enter the administrative API key (PHISHGUARD_ADMIN_KEY) to access threat telemetry and registry controls.");
        const label = el("label", "display:block;font-size:0.8rem;color:#cbd5e1;margin-bottom:6px;", "Administrative key");
        label.htmlFor = "pgAuthKey";
        const input = el("input",
            "width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #334155;" +
            "background:#020617;color:#f8fafc;font-size:0.95rem;");
        input.type = "password";
        input.id = "pgAuthKey";
        input.autocomplete = "current-password";
        input.required = true;
        const error = el("p", "min-height:1.2em;margin:10px 0 0;font-size:0.8rem;color:#f87171;");
        error.setAttribute("role", "alert");
        const button = el("button",
            "margin-top:12px;width:100%;padding:10px 12px;border:0;border-radius:8px;background:#6366f1;" +
            "color:#fff;font-weight:600;font-size:0.95rem;cursor:pointer;", "Sign in");
        button.type = "submit";

        card.append(title, hint, label, input, error, button);
        overlay.appendChild(card);

        card.addEventListener("submit", async function (event) {
            event.preventDefault();
            button.disabled = true;
            error.textContent = "";
            try {
                const resp = await nativeFetch(AUTH_BASE + "/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "same-origin",
                    body: JSON.stringify({ api_key: input.value })
                });
                if (resp.ok) {
                    window.location.reload();
                    return;
                }
                error.textContent = resp.status === 401
                    ? "That key was not accepted."
                    : "Sign-in failed (HTTP " + resp.status + ").";
            } catch (_e) {
                error.textContent = "Cannot reach the PhishGuard backend.";
            }
            button.disabled = false;
            input.select();
        });

        const mount = function () { document.body.appendChild(overlay); input.focus(); };
        if (document.body) { mount(); } else { document.addEventListener("DOMContentLoaded", mount); }
    }

    function addSignOutControl() {
        const mount = function () {
            // Sits in the header toolbar so it never covers page content; the
            // fixed corner position is only a fallback for pages without one.
            const slot = document.querySelector(".header__status");
            const btn = el("button", slot
                ? "height:30px;padding:0 12px;border-radius:999px;border:1px solid rgba(148,163,184,0.4);" +
                  "background:rgba(15,23,42,0.85);color:#cbd5e1;font:600 12px Inter,system-ui,sans-serif;" +
                  "cursor:pointer;white-space:nowrap;flex:0 0 auto;"
                : "position:fixed;right:14px;bottom:14px;z-index:2147482000;padding:6px 12px;border-radius:999px;" +
                  "border:1px solid rgba(148,163,184,0.4);background:rgba(15,23,42,0.85);color:#cbd5e1;" +
                  "font:600 12px Inter,system-ui,sans-serif;cursor:pointer;", "Sign out");
            btn.type = "button";
            btn.title = "End this SOC dashboard session";
            btn.addEventListener("click", async function () {
                try {
                    await nativeFetch(AUTH_BASE + "/logout", { method: "POST", credentials: "same-origin" });
                } finally {
                    window.location.reload();
                }
            });
            (slot || document.body).appendChild(btn);
        };
        if (document.body) { mount(); } else { document.addEventListener("DOMContentLoaded", mount); }
    }

    // Resolves once a session is confirmed. While unauthenticated it stays
    // pending; a successful sign-in reloads the page with a valid cookie.
    const ready = new Promise(function (resolve) {
        nativeFetch(AUTH_BASE + "/session", { credentials: "same-origin" })
            .then(function (resp) { return resp.ok ? resp.json() : { authenticated: false }; })
            .then(function (state) {
                if (state.authenticated) {
                    addSignOutControl();
                    resolve(true);
                } else {
                    showSignIn();
                }
            })
            .catch(function () {
                // Backend unreachable: let calls through so the page's own
                // offline handling reports the outage.
                resolve(false);
            });
    });

    window.fetch = async function (input, init) {
        if (!isDashboardApi(input)) {
            return nativeFetch(input, init);
        }
        await ready;
        const response = await nativeFetch(input, init);
        if (response.status === 401) {
            showSignIn("Your session has expired. Sign in again to continue.");
        }
        return response;
    };

    window.PhishGuardAuth = { ready: ready };
})();
