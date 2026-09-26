import json
import re


def detect_format(raw_log: str) -> dict:

    raw_log = raw_log.strip()

    # 1. JSON detection
    try:
        parsed = json.loads(raw_log)

        if isinstance(parsed, (dict, list)):
            return {
                "format": "JSON",
                "confidence": 0.99,
                "method": "JSON structure"
            }

    except json.JSONDecodeError:
        pass

    # 2. CEF detection
    if raw_log.startswith("CEF:"):
        return {
            "format": "CEF",
            "confidence": 0.99,
            "method": "CEF signature"
        }

    # 3. LEEF detection
    if raw_log.startswith("LEEF:"):
        return {
            "format": "LEEF",
            "confidence": 0.99,
            "method": "LEEF signature"
        }

    # 4. Syslog detection
    syslog_patterns = [
        r"^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",  # RFC 3164 with PRI
        r"^<\d+>\d+\s+\d{4}-\d{2}-\d{2}",             # RFC 5424 with PRI
        r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[\w\.\-]+(?:\[\d+\])?:"  # Standard syslog without PRI
    ]

    if any(re.match(p, raw_log) for p in syslog_patterns):
        return {
            "format": "SYSLOG",
            "confidence": 0.95,
            "method": "Syslog pattern"
        }

    # 5. XML detection
    if raw_log.startswith("<?xml") or (
        raw_log.startswith("<") and raw_log.endswith(">")
    ):
        return {
            "format": "XML",
            "confidence": 0.90,
            "method": "XML structure"
        }

    # 6. Custom key-value log detection (prioritized over CSV when key=val pairs exist)
    key_value_pattern = r'\b\w+=("[^"]*"|\S+)'
    if len(re.findall(key_value_pattern, raw_log)) >= 2:
        return {
            "format": "CUSTOM",
            "confidence": 0.85,
            "method": "Key-value pattern"
        }

    # 7. CSV detection (true comma-separated values)
    lines = raw_log.splitlines()
    if len(lines) >= 1 and "," in lines[0]:
        if lines[0].count(",") >= 1:
            return {
                "format": "CSV",
                "confidence": 0.75,
                "method": "CSV structure"
            }

    # 8. Unknown
    return {
        "format": "UNKNOWN",
        "confidence": 0.0,
        "method": "No matching format"
    }
