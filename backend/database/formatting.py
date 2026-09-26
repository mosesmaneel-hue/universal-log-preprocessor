"""
backend/database/formatting.py

Centralized timestamp formatting utility driven by General Settings.

- Reads timezone, date_format, and time_format from the persisted Settings.
- Converts UTC-stored timestamps to the configured display timezone.
- Returns human-readable strings using the configured date/time format.

DB timestamps are stored as "YYYY-MM-DD HH:MM:SS" (UTC, no tzinfo suffix).
This module treats them as UTC and converts to the configured timezone for display.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from database.settings import get_setting

# Map Settings UI tokens to Python strftime directives
_DATE_FORMAT_MAP = {
    "DD MMM YYYY":  "%d %b %Y",
    "MMM DD, YYYY": "%b %d, %Y",
    "DD/MM/YYYY":   "%d/%m/%Y",
    "MM/DD/YYYY":   "%m/%d/%Y",
    "YYYY-MM-DD":   "%Y-%m-%d",
}

_DEFAULT_DATE_FORMAT = "%d %b %Y"   # fallback for "DD MMM YYYY"


def _get_tz():
    """Return the configured ZoneInfo object, falling back to UTC on error."""
    tz_name = get_setting("timezone", "Asia/Kolkata")
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def _get_date_fmt():
    """Return Python strftime date format string from the persisted UI token."""
    token = get_setting("date_format", "DD MMM YYYY")
    return _DATE_FORMAT_MAP.get(token, _DEFAULT_DATE_FORMAT)


def _get_time_fmt():
    """Return Python strftime time format string from the persisted setting."""
    val = get_setting("time_format", "24-hour")
    if val == "12-hour":
        return "%I:%M:%S %p"
    return "%H:%M:%S"


def format_timestamp(ts_str):
    """
    Convert a UTC timestamp string from the DB to a display string using
    the active timezone, date_format, and time_format settings.
    """
    if not ts_str:
        return ts_str
    normalized = ts_str.replace("T", " ").split(".")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt_utc = datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    else:
        return ts_str
    dt_local = dt_utc.astimezone(_get_tz())
    date_fmt = _get_date_fmt()
    time_fmt = _get_time_fmt()
    return dt_local.strftime(f"{date_fmt} {time_fmt}")


def format_timestamp_date_only(ts_str):
    """Return only the date portion of a formatted timestamp."""
    if not ts_str:
        return ts_str
    normalized = ts_str.replace("T", " ").split(".")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt_utc = datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    else:
        return ts_str
    dt_local = dt_utc.astimezone(_get_tz())
    return dt_local.strftime(_get_date_fmt())


def get_display_config():
    """
    Return all active display configuration values derived from General Settings.
    """
    tz_name = get_setting("timezone", "Asia/Kolkata")
    date_fmt_token = get_setting("date_format", "DD MMM YYYY")
    time_fmt_val = get_setting("time_format", "24-hour")
    language = get_setting("language", "English")
    app_name = get_setting("application_name", "Universal Log Pre-Processing Framework")
    organization = get_setting("organization", "ARC")
    return {
        "application_name": app_name,
        "organization": organization,
        "timezone": tz_name,
        "date_format": date_fmt_token,
        "time_format": time_fmt_val,
        "language": language,
        "language_note": (
            "Language is persisted. UI localization is not yet implemented; "
            "application language is English."
            if language != "English" else None
        ),
    }
