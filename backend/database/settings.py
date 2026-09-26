import json
import re
from datetime import datetime
from database.db import get_connection

DEFAULT_SETTINGS = {
    # General
    "application_name": "Universal Log Pre-Processing Framework",
    "organization": "ARC",
    "timezone": "Asia/Kolkata",
    "date_format": "DD MMM YYYY",
    "time_format": "24-hour",
    "language": "English",

    # System
    "realtime_processing": True,
    "auto_detect_formats": True,
    "ai_suggestions": True,
    "store_raw_logs": False,
    "metrics_collection": True,
    "retention_period_days": 30,

    # Security
    "two_factor_authentication": True,
    "session_timeout_minutes": 30,
    "password_policy": "Strong",
    "ip_whitelist": "",
    "login_attempts_limit": 5,
    "account_lockout_minutes": 15,

    # Integrations
    "siem_integration": "None",
    "email_notifications": "Enabled",
    "slack_integration": "Disabled",
    "webhook_endpoint": "",
    "api_access": "Enabled",

    # Notifications
    "critical_alerts": True,
    "system_errors": True,
    "daily_summary": False,
    "weekly_report": True,
    "notification_email": "admin@arc.local",

    # Appearance
    "theme": "light",
    "primary_color": "blue",
    "compact_mode": False,
    "show_animations": True,
}

VALID_OPTIONS = {
    "date_format": {"DD MMM YYYY", "YYYY-MM-DD", "MM/DD/YYYY", "DD/MM/YYYY", "MMM DD, YYYY"},
    "time_format": {"24-hour", "12-hour"},
    "language": {"English", "Spanish", "German"},
    "password_policy": {"Strong", "Very Strong", "Standard"},
    "siem_integration": {"None", "Splunk", "Elasticsearch / Kibana", "Microsoft Sentinel"},
    "email_notifications": {"Enabled", "Disabled"},
    "slack_integration": {"Enabled", "Disabled"},
    "api_access": {"Enabled", "Disabled"},
    "theme": {"light", "dark", "system"},
    "primary_color": {"blue", "emerald", "amber", "rose", "pink", "slate"},
}

SECTIONS_MAP = {
    "general": ["application_name", "organization", "timezone", "date_format", "time_format", "language"],
    "system": ["realtime_processing", "auto_detect_formats", "ai_suggestions", "store_raw_logs", "metrics_collection", "retention_period_days"],
    "security": ["two_factor_authentication", "session_timeout_minutes", "password_policy", "ip_whitelist", "login_attempts_limit", "account_lockout_minutes"],
    "integrations": ["siem_integration", "email_notifications", "slack_integration", "webhook_endpoint", "api_access"],
    "notifications": ["critical_alerts", "system_errors", "daily_summary", "weekly_report", "notification_email"],
    "appearance": ["theme", "primary_color", "compact_mode", "show_animations"],
}


def init_settings_table():
    """Ensure the settings table exists and default values are populated."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Check if empty
    cursor.execute("SELECT COUNT(*) FROM settings")
    count = cursor.fetchone()[0]

    if count == 0:
        now = datetime.utcnow().isoformat()
        for k, v in DEFAULT_SETTINGS.items():
            val_str = json.dumps(v)
            cursor.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                (k, val_str, now)
            )

    connection.commit()
    connection.close()


def get_raw_settings():
    """Return flat dictionary of all settings with proper types from SQLite."""
    init_settings_table()
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT key, value FROM settings")
    rows = cursor.fetchall()
    connection.close()

    settings_dict = dict(DEFAULT_SETTINGS)
    for r in rows:
        key = r["key"]
        try:
            val = json.loads(r["value"])
        except Exception:
            val = r["value"]
        settings_dict[key] = val

    return settings_dict


def structure_settings(flat_dict):
    """Convert a flat settings dictionary into structured sections."""
    structured = {}
    for section, keys in SECTIONS_MAP.items():
        structured[section] = {k: flat_dict.get(k, DEFAULT_SETTINGS.get(k)) for k in keys}
    return structured


def get_all_settings():
    """Return full structured settings."""
    flat = get_raw_settings()
    return structure_settings(flat)


def validate_setting(key, value):
    """Validate a single setting value. Raises ValueError with details if invalid."""
    if key not in DEFAULT_SETTINGS:
        raise ValueError(f"Unknown setting: '{key}'")

    expected_type = type(DEFAULT_SETTINGS[key])

    # Type coercion for bools passed as strings or ints
    if expected_type == bool:
        if isinstance(value, str):
            if value.lower() in ("true", "1", "yes"):
                value = True
            elif value.lower() in ("false", "0", "no"):
                value = False
            else:
                raise ValueError(f"Invalid boolean value for '{key}': {value}")
        elif not isinstance(value, bool):
            raise ValueError(f"Expected boolean for '{key}', got {type(value).__name__}")

    # Type coercion for ints
    elif expected_type == int:
        try:
            value = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"Expected integer for '{key}', got {value}")

    # Type check for strings
    elif expected_type == str:
        if not isinstance(value, str):
            value = str(value)

    # Validate enums
    if key in VALID_OPTIONS:
        if value not in VALID_OPTIONS[key]:
            valid_list = sorted(list(VALID_OPTIONS[key]))
            raise ValueError(f"Invalid value for '{key}': '{value}'. Must be one of {valid_list}")

    # Numeric range validations
    if key == "retention_period_days":
        if not (1 <= value <= 3650):
            raise ValueError(f"retention_period_days must be between 1 and 3650, got {value}")
    elif key == "session_timeout_minutes":
        if not (1 <= value <= 1440):
            raise ValueError(f"session_timeout_minutes must be between 1 and 1440, got {value}")
    elif key == "account_lockout_minutes":
        if not (1 <= value <= 1440):
            raise ValueError(f"account_lockout_minutes must be between 1 and 1440, got {value}")
    elif key == "login_attempts_limit":
        if not (1 <= value <= 50):
            raise ValueError(f"login_attempts_limit must be between 1 and 50, got {value}")

    # Email format validation
    if key == "notification_email":
        email_pattern = r"^[\w\.\+\-]+@[\w\-]+(\.[\w\-]+)+$"
        if not re.match(email_pattern, value.strip()):
            raise ValueError(f"Invalid notification_email format: '{value}'")

    # Webhook endpoint URL validation (when non-empty)
    if key == "webhook_endpoint":
        val_str = value.strip()
        if val_str:
            url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
            if not re.match(url_pattern, val_str, re.IGNORECASE):
                raise ValueError(f"Invalid webhook_endpoint URL: '{value}'. Must begin with http:// or https://")

    # IP Whitelist validation (comma-separated IPv4/IPv6 or CIDRs, or empty)
    if key == "ip_whitelist":
        val_str = value.strip()
        if val_str:
            import ipaddress
            entries = [e.strip() for e in val_str.replace(";", ",").split(",") if e.strip()]
            for entry in entries:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    raise ValueError(f"Invalid IP address or CIDR notation in ip_whitelist: '{entry}'")

    return value


def update_settings(updates):
    """
    Accepts partial settings updates (either flat or section-nested),
    validates every provided key/value, and commits them to SQLite.
    Returns the complete updated structured settings.
    """
    init_settings_table()

    # Flatten if updates are given as section dictionaries
    flat_updates = {}
    for k, v in updates.items():
        if isinstance(v, dict) and k in SECTIONS_MAP:
            for sub_k, sub_v in v.items():
                flat_updates[sub_k] = sub_v
        else:
            flat_updates[k] = v

    # Validate all incoming values first
    validated = {}
    for k, v in flat_updates.items():
        if k in DEFAULT_SETTINGS:
            validated[k] = validate_setting(k, v)

    if not validated:
        # Nothing to update, return current
        return get_all_settings()

    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.utcnow().isoformat()

    for k, v in validated.items():
        val_str = json.dumps(v)
        cursor.execute("""
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
        """, (k, val_str, now))

    connection.commit()
    connection.close()

    return get_all_settings()


def get_setting(key: str, default=None):
    """
    Reusable helper to read a single persisted setting value.
    Reads from SQLite through get_raw_settings() to ensure freshness.
    Falls back to DEFAULT_SETTINGS if key is not found in database.
    """
    raw = get_raw_settings()
    if key in raw:
        return raw[key]
    return default if default is not None else DEFAULT_SETTINGS.get(key)


def is_setting_enabled(key: str, default=False) -> bool:
    """
    Reusable helper to check boolean settings cleanly.
    Handles booleans as well as string/integer coercions.
    """
    val = get_setting(key, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes", "enabled")
    if isinstance(val, (int, float)):
        return bool(val)
    return bool(val)


def get_retention_days() -> int:
    """
    Returns authoritative retention period in days from settings.
    """
    val = get_setting("retention_period_days", 30)
    try:
        return int(val)
    except (ValueError, TypeError):
        return 30
