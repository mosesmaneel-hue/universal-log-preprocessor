// =============================================================
// Universal Log Preprocessor - Production Frontend Config
// =============================================================
// For local development, defaults to http://127.0.0.1:8000.
// For Vercel production deployment, defaults to Render backend.
(function () {
    if (typeof window !== "undefined" && !window.API_BASE_URL) {
        const host = window.location ? window.location.hostname.toLowerCase() : "";
        const isLocal = host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || !host;
        window.API_BASE_URL = isLocal ? "http://127.0.0.1:8000" : "https://universal-log-preprocessor.onrender.com";
    }
})();
