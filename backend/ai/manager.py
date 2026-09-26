"""
AI Provider Manager and Context Orchestrator.
Dispatches to Ollama, Platform API, or BYOK Provider based on environment and request parameters.
Constructs real operational system context from SQLite.
"""
import os
import json
from typing import Dict, Any, Optional, Tuple
from ai.base import AIProvider
from ai.ollama_provider import OllamaProvider
from ai.api_provider import APIProvider
from ai.ssrf import validate_user_endpoint


def get_configured_mode() -> str:
    """
    Determines the system-wide AI mode:
    'ollama' or 'api'/'platform'.
    If AI_PROVIDER is set, respects it.
    If AI_API_KEY is present in env, defaults to platform mode.
    Otherwise defaults to ollama for local dev.
    """
    provider_env = os.getenv("AI_PROVIDER", "").strip().lower()
    if provider_env:
        if provider_env in ("ollama", "local"):
            return "ollama"
        if provider_env in ("api", "platform", "openai"):
            return "api"
        return provider_env

    if os.getenv("AI_API_KEY"):
        return "api"

    return "ollama"


def get_system_provider() -> AIProvider:
    """Returns the configured server-level AI provider (Ollama or Platform API)."""
    mode = get_configured_mode()
    if mode == "ollama":
        return OllamaProvider()
    return APIProvider(provider_name="platform")


def resolve_chat_provider(byok: Optional[Dict[str, Any]] = None) -> Tuple[Optional[AIProvider], Optional[str]]:
    """
    Resolves the provider for a chat request.
    If BYOK is supplied with an api_key, validates and returns an ephemeral APIProvider.
    Otherwise returns the system-level provider.
    
    Returns (provider, error_message).
    """
    if byok and isinstance(byok, dict) and byok.get("api_key"):
        raw_key = str(byok.get("api_key") or "").strip()
        if not raw_key:
            return None, "BYOK API key cannot be empty."

        user_endpoint = byok.get("endpoint")
        if user_endpoint and str(user_endpoint).strip():
            # Validate SSRF on user-supplied endpoint
            is_valid, err_msg = validate_user_endpoint(str(user_endpoint).strip())
            if not is_valid:
                return None, f"Invalid API endpoint: {err_msg}"
            resolved_endpoint = str(user_endpoint).strip()
        else:
            resolved_endpoint = "https://api.openai.com/v1/chat/completions"

        user_model = str(byok.get("model") or "gpt-4o-mini").strip()
        provider_type = str(byok.get("provider") or "byok").strip()

        # Instantiate request-scoped ephemeral provider
        provider = APIProvider(
            api_key=raw_key,
            endpoint=resolved_endpoint,
            model=user_model,
            provider_name=provider_type
        )
        return provider, None

    # Fall back to server configured provider
    return get_system_provider(), None


def build_operational_context() -> str:
    """
    Builds the REAL telemetry context from SQLite and the Parser Registry.
    Does NOT invent mock statistics.
    """
    from database.db import get_connection
    from parsers.registry import ParserRegistry

    connection = get_connection()
    cursor = connection.cursor()

    # Processed logs count
    cursor.execute("SELECT COUNT(*) FROM processed_logs")
    processed_count = cursor.fetchone()[0]

    # Quarantine logs count
    cursor.execute("SELECT COUNT(*) FROM quarantine_logs")
    quarantine_count = cursor.fetchone()[0]

    # Alerts count
    try:
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]
    except Exception:
        alerts_count = 0

    # Ingested format counts
    cursor.execute("""
        SELECT source_format, COUNT(*) as count
        FROM processed_logs
        GROUP BY source_format
        ORDER BY count DESC
    """)
    format_counts = {row["source_format"]: row["count"] for row in cursor.fetchall()}

    # Quarantine reasons breakdown
    cursor.execute("""
        SELECT reason, COUNT(*) as count
        FROM quarantine_logs
        GROUP BY reason
        ORDER BY count DESC
    """)
    quarantine_reasons = {row["reason"]: row["count"] for row in cursor.fetchall()}

    # Recent processed logs
    cursor.execute("""
        SELECT event_id, source_format, parser, normalized_data, created_at
        FROM processed_logs
        ORDER BY id DESC
        LIMIT 3
    """)
    recent_processed_rows = cursor.fetchall()

    # Recent quarantine logs
    cursor.execute("""
        SELECT quarantine_id, reason, raw_log, created_at
        FROM quarantine_logs
        ORDER BY id DESC
        LIMIT 3
    """)
    recent_quarantine_rows = cursor.fetchall()

    # Recent alerts
    try:
        cursor.execute("""
            SELECT alert_id, severity, alert_type, message, created_at
            FROM alerts
            ORDER BY id DESC
            LIMIT 3
        """)
        recent_alerts_rows = cursor.fetchall()
    except Exception:
        recent_alerts_rows = []

    connection.close()

    parsers = ParserRegistry().list_parsers()

    recent_events_summary = []
    for r in recent_processed_rows:
        try:
            norm = json.loads(r["normalized_data"]) if r["normalized_data"] else {}
        except Exception:
            norm = {}
        recent_events_summary.append({
            "event_id": r["event_id"],
            "format": r["source_format"],
            "parser": r["parser"],
            "action": norm.get("event", {}).get("action") or norm.get("action"),
            "severity": norm.get("event", {}).get("severity") or norm.get("severity"),
            "created_at": r["created_at"]
        })

    recent_quarantine_summary = []
    for r in recent_quarantine_rows:
        recent_quarantine_summary.append({
            "quarantine_id": r["quarantine_id"],
            "reason": r["reason"],
            "sample": (r["raw_log"] or "")[:120],
            "created_at": r["created_at"]
        })

    recent_alerts_summary = []
    for r in recent_alerts_rows:
        recent_alerts_summary.append({
            "alert_id": r["alert_id"],
            "severity": r["severity"],
            "alert_type": r["alert_type"],
            "message": r["message"],
            "created_at": r["created_at"]
        })

    system_context = (
        "You are ARC AI Assistant, the intelligent telemetry assistant for the ARC Universal Log Pre-Processing Framework.\n"
        "You must answer user questions accurately using ONLY the REAL operational project data below. Do NOT invent statistics or fake values.\n\n"
        "CURRENT OPERATIONAL DATA:\n"
        f"- Total Processed Logs: {processed_count}\n"
        f"- Total Quarantined Logs: {quarantine_count}\n"
        f"- Total Alerts Generated: {alerts_count}\n"
        f"- Formats Ingested: {json.dumps(format_counts)}\n"
        f"- Quarantine Reasons Breakdown: {json.dumps(quarantine_reasons)}\n"
        f"- Available Parsers in Registry: {json.dumps(parsers)}\n"
        f"- Recent Processed Events: {json.dumps(recent_events_summary)}\n"
        f"- Recent Quarantined Events: {json.dumps(recent_quarantine_summary)}\n"
        f"- Recent Alerts: {json.dumps(recent_alerts_summary)}\n"
    )

    return system_context
