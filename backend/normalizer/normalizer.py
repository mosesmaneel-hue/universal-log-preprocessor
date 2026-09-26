import uuid
import re
import ipaddress
from datetime import datetime, timezone
from core.severity_classifier import classify_severity


def _as_ip(value):
    """Return value only if it is a valid IP address string, otherwise None.

    Used for semantic fallback fields (e.g. 'target', 'source') that may
    contain usernames, hostnames, or service names instead of IP addresses.
    Conventional protocol-level fields (src_ip, dst_ip, src, dst) are passed
    through directly by the caller without this guard.
    """
    if not value:
        return None
    try:
        ipaddress.ip_address(str(value).strip())
        return str(value).strip()
    except ValueError:
        return None


def to_int(value):
    if value is None:
        return None

    try:
        return int(value)
    except (ValueError, TypeError):
        return value


def normalize_event(
    parsed_data: dict,
    detection: dict,
    original_raw_log: str = None
) -> dict:

    data = parsed_data.get("data", {})

    # CSV parser returns a list of rows
    if isinstance(data, list):
        if not data:
            raise ValueError("No CSV data available for normalization")
        data = data[0]

    # Some formats store fields inside nested sections
    extension = data.get("extension", {})
    attributes = data.get("attributes", {})

    # Combine nested fields with the main data
    fields = {
        **attributes,
        **extension,
        **data
    }

    # Extract key-value pairs from message string if present (e.g. Syslog with key=value content)
    message_str = fields.get("message")
    if isinstance(message_str, str) and "=" in message_str:
        kv_pairs = re.findall(r'(\w+)=("[^"]*"|\S+)', message_str)
        for k, v in kv_pairs:
            cleaned_v = v.strip('"')
            if k not in fields or fields[k] is None:
                fields[k] = cleaned_v

    # Use the log timestamp if available.
    # Otherwise, generate the current UTC timestamp.
    timestamp = fields.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    # Unambiguous protocol-level fields are used directly.
    # Semantic fallback 'source' is only accepted when its value is a valid IP
    # (it may otherwise be a service/format name).
    source_ip = (
        fields.get("source_ip")
        or fields.get("src_ip")
        or fields.get("src")
        or _as_ip(fields.get("source"))
    )

    # Semantic fallback 'target' is only accepted when its value is a valid IP.
    # target=root (or any hostname/username) must NOT be placed in destination.ip.
    destination_ip = (
        fields.get("destination_ip")
        or fields.get("dst_ip")
        or fields.get("dst")
        or _as_ip(fields.get("target"))
    )

    source_port = to_int(
        fields.get("source_port")
        or fields.get("srcPort")
        or fields.get("src_port")
        or fields.get("spt")
    )

    destination_port = to_int(
        fields.get("destination_port")
        or fields.get("dstPort")
        or fields.get("dst_port")
        or fields.get("dpt")
    )

    action = (
        fields.get("action")
        or fields.get("act")
    )

    # Preserve the existing numeric source severity from CEF/LEEF/Syslog if present
    severity = to_int(fields.get("severity"))

    # Build normalized event structure
    normalized = {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,

        "source": {
            "ip": source_ip,
            "port": source_port
        },

        "destination": {
            "ip": destination_ip,
            "port": destination_port
        },

        "user": {
            "name": fields.get("user")
        },

        "host": {
            "name": fields.get("host")
        },

        "event": {
            "action": action,
            "severity": severity,
            "type": fields.get("event_type"),
            "id": fields.get("event_id"),
            "reason": fields.get("reason")
        },

        "network": {
            "protocol": fields.get("protocol") or fields.get("proto")
        },

        "message": fields.get("message") or fields.get("name"),

        "source_format": detection["format"],
        "parser": parsed_data.get("parser"),

        "raw_log": original_raw_log,
        "raw_data": data
    }

    # Rule-based deterministic severity/criticality classification
    sev = classify_severity(normalized, parsed_data=parsed_data, raw_log=original_raw_log)
    normalized["severity_level"] = sev["severity_level"]
    normalized["severity_score"] = sev["severity_score"]
    normalized["severity_reason"] = sev["severity_reason"]

    return normalized
