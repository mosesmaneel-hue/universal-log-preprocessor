// =============================================================
// ARC - Universal Log Pre-Processing Framework
// Shared API Client  |  api.js
// =============================================================

// =============================================================
// API Root & Base URL Resolver
// 1. window.API_BASE_URL (configured for deployment)
// 2. localStorage.getItem("arc_api_base_url") (runtime override)
// 3. Fallback: "http://127.0.0.1:8000" (local development default)
// =============================================================
function resolveArcApiRoot() {
    // 1. Explicit window.API_BASE_URL (configured or injected via Vercel)
    if (typeof window !== "undefined" && window.API_BASE_URL && typeof window.API_BASE_URL === "string" && window.API_BASE_URL.trim()) {
        return window.API_BASE_URL.trim().replace(/\/+$/, "");
    }
    // 2. localStorage runtime override
    if (typeof localStorage !== "undefined") {
        try {
            const stored = localStorage.getItem("arc_api_base_url");
            if (stored && stored.trim()) return stored.trim().replace(/\/+$/, "");
        } catch (e) {}
    }
    // 3. Environment detection: if running on Vercel/production host (!localhost)
    if (typeof window !== "undefined" && window.location && window.location.hostname) {
        const host = window.location.hostname.toLowerCase();
        const isLocal = host === "localhost" ||
                        host === "127.0.0.1" ||
                        host === "0.0.0.0" ||
                        host.startsWith("192.168.") ||
                        host.startsWith("10.") ||
                        host.endsWith(".local");
        if (!isLocal) {
            return "https://universal-log-preprocessor.onrender.com";
        }
    }
    // 4. Default for local development
    return "http://127.0.0.1:8000";
}

const ARC_RESOLVED_ROOT = resolveArcApiRoot();
const ARC_RESOLVED_BASE = ARC_RESOLVED_ROOT + "/api/v1";

if (typeof window !== "undefined") {
    window.API_BASE_URL = ARC_RESOLVED_ROOT;
    window.ARC_API_ROOT = ARC_RESOLVED_ROOT;
    window.ARC_API_BASE = ARC_RESOLVED_BASE;
    window.API_BASE = ARC_RESOLVED_BASE;
    window.API = ARC_RESOLVED_BASE;

    // Asynchronously probe Vercel serverless /api/config to dynamically respect Vercel environment variable
    if (typeof fetch === "function") {
        fetch("/api/config")
            .then(r => r.ok ? r.json() : null)
            .then(cfg => {
                if (cfg && cfg.API_BASE_URL && typeof cfg.API_BASE_URL === "string") {
                    const dynamicRoot = cfg.API_BASE_URL.trim().replace(/\/+$/, "");
                    window.API_BASE_URL = dynamicRoot;
                    window.ARC_API_ROOT = dynamicRoot;
                    window.ARC_API_BASE = dynamicRoot + "/api/v1";
                    window.API_BASE = dynamicRoot + "/api/v1";
                    window.API = dynamicRoot + "/api/v1";
                }
            })
            .catch(() => {});
    }
}

const ARC = (function () {
    const BASE = ARC_RESOLVED_BASE;

    // ── Pages map for navigation ──────────────────────────────
    const PAGES = {
        "Dashboard": "/stitch_arc_universal_log_pre_processor/arc_01_dashboard/code.html",
        "Log Ingestion": "/stitch_arc_universal_log_pre_processor/arc_02_log_ingestion/code.html",
        "Source Management": "/stitch_arc_universal_log_pre_processor/arc_03_source_management/code.html",
        "Format Detection": "/stitch_arc_universal_log_pre_processor/arc_04_format_detection/code.html",
        "Parser Registry": "/stitch_arc_universal_log_pre_processor/arc_05_parser_registry/code.html",
        "Normalization / Schema": "/stitch_arc_universal_log_pre_processor/arc_06_normalization_schema/code.html",
        "Event Viewer": "/stitch_arc_universal_log_pre_processor/arc_07_event_viewer/code.html",
        "AI Assistant": "/stitch_arc_universal_log_pre_processor/arc_08_ai_assistant/code.html",
        "Quarantine": "/stitch_arc_universal_log_pre_processor/arc_09_quarantine/code.html",
        "Analytics": "/stitch_arc_universal_log_pre_processor/arc_10_analytics/code.html",
        "Audit Logs": "/stitch_arc_universal_log_pre_processor/arc_11_audit_logs/code.html",
        "Alerts": "/stitch_arc_universal_log_pre_processor/arc_12_alerts/code.html",
        "Settings": "/stitch_arc_universal_log_pre_processor/arc_13_settings/code.html",
        "Documentation": "/stitch_arc_universal_log_pre_processor/arc_14_documentation/code.html"
    };

    // ── Core fetch wrapper ─────────────────────────────────────
    async function get(path) {
        const r = await fetch(BASE + path);
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
    }

    async function post(path, body) {
        const r = await fetch(BASE + path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
    }

    // ── Public API endpoints ───────────────────────────────────
    const api = {
        health:    () => fetch(ARC_RESOLVED_ROOT + "/health").then(r => r.json()),
        stats:     () => get("/stats"),
        summary:   () => get("/summary"),
        parsers:   () => get("/parsers"),
        processed: () => get("/processed"),
        quarantine:() => get("/quarantine"),
        process:   (raw_log) => post("/process", { raw_log }),
        aiStatus:  () => get("/ai/status"),
        aiChat:    (prompt) => post("/ai/chat", { prompt }),
        severityStats: () => get("/severity/stats"),
        severityRules: () => get("/severity/rules")
    };

    // ── Fix navigation ─────────────────────────────────────────
    function fixNav() {
        document.querySelectorAll("a").forEach(a => {
            const href = a.getAttribute("href") || "";
            // Already an absolute page link? Skip.
            if (href.startsWith("/arc_") || href.startsWith("http")) return;

            const text = (a.querySelector("span")?.textContent || a.textContent).trim();
            if (PAGES[text]) {
                a.setAttribute("href", PAGES[text]);
            }
        });
    }

    // ── Error banner ───────────────────────────────────────────
    function showError(container, msg) {
        if (!container) return;
        container.innerHTML = `
            <div style="padding:12px 16px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;
                        color:#dc2626;font-size:12px;margin:8px 0;">
                <strong>⚠ Backend Error:</strong> ${msg}
            </div>`;
    }

    // ── Helper: set text of element by id ─────────────────────
    function setText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // ── Format colors ──────────────────────────────────────────
    const FORMAT_COLORS = {
        SYSLOG: "#2563eb", JSON: "#38bdf8", CSV: "#f97316",
        CEF: "#a855f7",    LEEF: "#06b6d4", XML: "#f43f5e",
        CUSTOM: "#10b981", OTHERS: "#94a3b8"
    };

    const FORMAT_BADGE_CLASSES = {
        SYSLOG: "bg-blue-100 text-blue-700",
        JSON:   "bg-sky-100 text-sky-700",
        CEF:    "bg-purple-100 text-purple-700",
        LEEF:   "bg-cyan-100 text-cyan-700",
        XML:    "bg-rose-100 text-rose-700",
        CSV:    "bg-orange-100 text-orange-700",
        CUSTOM: "bg-emerald-100 text-emerald-700"
    };

    function formatBadge(fmt) {
        const cls = FORMAT_BADGE_CLASSES[fmt] || "bg-slate-100 text-slate-700";
        return `<span class="inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${cls}">${fmt || "UNKNOWN"}</span>`;
    }

    function severityBadge(sev) {
        const s = String(sev || "CLEAN").toUpperCase();
        let cls = "bg-emerald-50 text-emerald-700 border border-emerald-200";
        if (s === "CRITICAL") cls = "bg-rose-100 text-rose-700 border border-rose-300 font-bold";
        else if (s === "HIGH" || s === "ERROR" || s === "FATAL") cls = "bg-red-50 text-red-700 border border-red-200 font-semibold";
        else if (s === "MEDIUM" || s === "WARN" || s === "WARNING") cls = "bg-amber-50 text-amber-700 border border-amber-200 font-medium";
        else if (s === "LOW" || s === "NOTICE") cls = "bg-blue-50 text-blue-700 border border-blue-200";
        else cls = "bg-emerald-50 text-emerald-700 border border-emerald-200";
        return `<span class="inline-block px-1.5 py-0.5 rounded text-[10px] ${cls}">${s}</span>`;
    }

    // ── Nested field extractor for normalized_data ─────────────
    function getField(log, ...keys) {
        const norm   = log.normalized_data || {};
        const parsed = log.parsed_data     || {};
        const nested = {
            src_ip:   norm.source?.ip,
            dst_ip:   norm.destination?.ip,
            user:     norm.user?.name,
            action:   norm.event?.action,
            severity: norm.event?.severity,
            host:     norm.host?.name,
            protocol: norm.network?.protocol,
            event_type: norm.event?.type
        };
        for (const k of keys) {
            if (nested[k] != null && nested[k] !== "") return nested[k];
            if (norm[k]   != null && typeof norm[k]   !== "object" && norm[k]   !== "") return norm[k];
            if (parsed[k] != null && typeof parsed[k] !== "object" && parsed[k] !== "") return parsed[k];
        }
        return null;
    }

    
    // ── Appearance System (Theme, Colors, Compact Mode, Animations) ──
    const THEME_STYLES_ID = "arc-appearance-styles";

    const PRIMARY_PALETTES = {
        blue:    { "500": "#3b82f6", "600": "#2563eb", "rgb": "37, 99, 235", "lightBg": "#eff6ff" },
        emerald: { "500": "#10b981", "600": "#059669", "rgb": "5, 150, 105", "lightBg": "#ecfdf5" },
        amber:   { "500": "#f59e0b", "600": "#d97706", "rgb": "217, 119, 6",  "lightBg": "#fffbeb" },
        rose:    { "500": "#f43f5e", "600": "#e11d48", "rgb": "225, 29, 72",  "lightBg": "#fff1f2" },
        pink:    { "500": "#ec4899", "600": "#db2777", "rgb": "219, 39, 119", "lightBg": "#fdf2f8" },
        slate:   { "500": "#64748b", "600": "#475569", "rgb": "71, 85, 105",  "lightBg": "#f8fafc" }
    };

    function injectAppearanceStyles() {
        if (document.getElementById(THEME_STYLES_ID)) return;
        const style = document.createElement("style");
        style.id = THEME_STYLES_ID;
        style.textContent = `
            :root {
                --arc-primary-500: #3b82f6;
                --arc-primary-600: #2563eb;
                --arc-primary-rgb: 37, 99, 235;
                --arc-primary-light: #eff6ff;
            }

            /* Primary color classes */
            .bg-blue-600, .bg-blue-500, button[data-section] {
                background-color: var(--arc-primary-600) !important;
            }
            .text-blue-600, .text-blue-500 {
                color: var(--arc-primary-600) !important;
            }
            .border-blue-600, .border-blue-500 {
                border-color: var(--arc-primary-600) !important;
            }
            .focus\\:border-blue-600:focus, .focus\\:ring-blue-500:focus {
                border-color: var(--arc-primary-600) !important;
                box-shadow: 0 0 0 2px rgba(var(--arc-primary-rgb), 0.2) !important;
            }
            .toggle-checkbox:checked, .toggle-checkbox:checked + .toggle-label {
                background-color: var(--arc-primary-600) !important;
            }

            /* Dark Theme styling */
            html[data-theme="dark"], body.arc-dark {
                background-color: #0b1329 !important;
                color: #e2e8f0 !important;
            }
            html[data-theme="dark"] main,
            html[data-theme="dark"] section,
            html[data-theme="dark"] .bg-\\[\\#f5f7fb\\],
            html[data-theme="dark"] .bg-slate-50,
            html[data-theme="dark"] .bg-gray-50 {
                background-color: #0b1329 !important;
            }
            html[data-theme="dark"] .bg-white,
            html[data-theme="dark"] [data-purpose="section-card"] {
                background-color: #111d38 !important;
                color: #e2e8f0 !important;
                border-color: #1e2e4f !important;
            }
            html[data-theme="dark"] .border-slate-100,
            html[data-theme="dark"] .border-slate-200,
            html[data-theme="dark"] .border-gray-100,
            html[data-theme="dark"] .border-gray-200 {
                border-color: #1e2e4f !important;
            }
            html[data-theme="dark"] .text-slate-800,
            html[data-theme="dark"] .text-slate-900,
            html[data-theme="dark"] .text-gray-900 {
                color: #f8fafc !important;
            }
            html[data-theme="dark"] .text-slate-600,
            html[data-theme="dark"] .text-slate-500,
            html[data-theme="dark"] .text-gray-600 {
                color: #94a3b8 !important;
            }
            html[data-theme="dark"] .text-slate-700 {
                color: #cbd5e1 !important;
            }
            html[data-theme="dark"] .form-input-custom,
            html[data-theme="dark"] input[type="text"],
            html[data-theme="dark"] input[type="number"],
            html[data-theme="dark"] input[type="email"],
            html[data-theme="dark"] select,
            html[data-theme="dark"] textarea {
                background-color: #0d172e !important;
                color: #f1f5f9 !important;
                border-color: #24355a !important;
            }
            html[data-theme="dark"] header {
                background-color: #0e1832 !important;
                border-color: #1e2e4f !important;
            }

            /* Compact Mode */
            body.arc-compact .p-6 { padding: 0.875rem 1rem !important; }
            body.arc-compact .p-5 { padding: 0.75rem 0.875rem !important; }
            body.arc-compact .p-4 { padding: 0.625rem 0.75rem !important; }
            body.arc-compact .space-y-4 > * + * { margin-top: 0.5rem !important; }
            body.arc-compact .space-y-3 > * + * { margin-top: 0.375rem !important; }
            body.arc-compact .gap-6 { gap: 0.875rem !important; }
            body.arc-compact .py-3 { padding-top: 0.35rem !important; padding-bottom: 0.35rem !important; }

            /* Disable Animations */
            body.arc-no-animations,
            body.arc-no-animations *,
            body.arc-no-animations *::before,
            body.arc-no-animations *::after {
                animation-duration: 0.001ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.001ms !important;
            }
        `;
        document.head.appendChild(style);
    }

    function applyAppearance(cfg) {
        injectAppearanceStyles();
        if (!cfg) return;

        // 1. Theme
        const theme = cfg.theme || "light";
        let isDark = false;
        if (theme === "dark") {
            isDark = true;
        } else if (theme === "system") {
            isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        }
        document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
        if (document.body) {
            document.body.classList.toggle("arc-dark", isDark);
        }

        // 2. Primary Color
        const color = cfg.primary_color || "blue";
        const pal = PRIMARY_PALETTES[color] || PRIMARY_PALETTES.blue;
        document.documentElement.setAttribute("data-primary-color", color);
        document.documentElement.style.setProperty("--arc-primary-500", pal["500"]);
        document.documentElement.style.setProperty("--arc-primary-600", pal["600"]);
        document.documentElement.style.setProperty("--arc-primary-rgb", pal.rgb);
        document.documentElement.style.setProperty("--arc-primary-light", pal.lightBg);

        // 3. Compact Mode
        const compact = (cfg.compact_mode === true || cfg.compact_mode === "true");
        if (document.body) {
            document.body.classList.toggle("arc-compact", compact);
        }

        // 4. Show Animations
        const anim = (cfg.show_animations !== false && cfg.show_animations !== "false");
        if (document.body) {
            document.body.classList.toggle("arc-no-animations", !anim);
        }

        try {
            localStorage.setItem("arc_appearance", JSON.stringify(cfg));
        } catch (e) {}
    }

    async function initAppearance() {
        injectAppearanceStyles();
        // Load cached instantly to prevent flicker
        try {
            const cached = localStorage.getItem("arc_appearance");
            if (cached) {
                applyAppearance(JSON.parse(cached));
            }
        } catch (e) {}

        // Fetch authoritative persisted settings from API
        try {
            const r = await fetch(ARC_RESOLVED_BASE + "/settings");
            if (r.ok) {
                const data = await r.json();
                const app = (data.settings && data.settings.appearance) || {};
                applyAppearance(app);
            }
        } catch (e) {}
    }

    return { api, fixNav, showError, setText, FORMAT_COLORS, FORMAT_BADGE_CLASSES, formatBadge, severityBadge, getField, PAGES, applyAppearance, initAppearance };
})();

// Fix navigation as soon as DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    ARC.fixNav();
    ARC.initAppearance();
});