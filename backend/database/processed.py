from datetime import datetime
import json
from database.db import get_connection
from database.formatting import format_timestamp
from database.settings import is_setting_enabled


def add_processed_log(
    event_id,
    source_format,
    parser,
    parsed_data,
    normalized_data,
    raw_log,
    severity_level=None,
    severity_score=None,
    severity_reason=None
):
    norm = normalized_data or {}
    sev_lvl = severity_level or norm.get("severity_level", "CLEAN")
    sev_score = severity_score if severity_score is not None else norm.get("severity_score", 0)
    sev_reason = severity_reason if severity_reason is not None else norm.get("severity_reason", "")

    # Ensure normalized_data dict also contains severity fields
    norm["severity_level"] = sev_lvl
    norm["severity_score"] = sev_score
    norm["severity_reason"] = sev_reason

    # store_raw_logs: If false, newly processed events do not retain the raw log payload
    raw_log_to_store = raw_log if is_setting_enabled("store_raw_logs", default=False) else ""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO processed_logs
        (
            event_id,
            source_format,
            parser,
            parsed_data,
            normalized_data,
            raw_log,
            severity_level,
            severity_score,
            severity_reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            source_format,
            parser,
            json.dumps(parsed_data),
            json.dumps(norm),
            raw_log_to_store,
            sev_lvl,
            sev_score,
            sev_reason
        )
    )

    connection.commit()
    connection.close()

    # Alert Bridge: Automatically create alert for CRITICAL / HIGH severity events
    try:
        check_and_create_alert(
            event_id=event_id,
            normalized_data=norm,
            raw_log=raw_log,
            severity_level=sev_lvl,
            severity_score=sev_score,
            severity_reason=sev_reason
        )
    except Exception:
        pass



def check_and_create_alert(
    event_id: str,
    normalized_data: dict,
    raw_log: str = "",
    severity_level: str = None,
    severity_score: int = None,
    severity_reason: str = None
):
    """
    Alert Bridge: Evaluates successfully processed events for alert-worthy conditions.
    Invokes add_alert() if severity is CRITICAL or HIGH, respecting settings and avoiding duplicates.
    """
    from database.alerts import add_alert, init_alerts_table
    from database.settings import is_setting_enabled
    from database.db import get_connection

    norm = normalized_data or {}
    sev = (severity_level or norm.get("severity_level") or "CLEAN").upper()

    # Rule 1: Only CRITICAL and HIGH severities generate alerts (CLEAN, LOW, MEDIUM do not)
    if sev not in ("CRITICAL", "HIGH"):
        return None

    # Rule 2: Respect Settings - critical_alerts controls critical security alerts
    if sev == "CRITICAL" and not is_setting_enabled("critical_alerts", default=True):
        return None

    # Rule 3: Avoid duplicate alerts for the same event_id
    if event_id:
        init_alerts_table()
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM alerts WHERE event_id = ?", (event_id,))
        existing = cur.fetchone()
        conn.close()
        if existing:
            return None

    # Determine alert parameters from existing normalized event and classifier data
    reason = severity_reason or norm.get("severity_reason") or "Security alert detected"
    source_format = norm.get("source_format") or "System"
    source = norm.get("host", {}).get("name") or source_format or "System"
    timestamp = norm.get("timestamp") or datetime.utcnow().isoformat()
    source_ip = norm.get("source", {}).get("ip")
    destination_ip = norm.get("destination", {}).get("ip")
    port = norm.get("destination", {}).get("port") or norm.get("source", {}).get("port")
    port_str = str(port) if port is not None else None
    user_name = norm.get("user", {}).get("name")

    # Map reason/indicators to clean alert_type, rule_id, and tags
    combined_desc = f"{(reason or '').lower()} {(norm.get('message') or '').lower()}"

    if "ransomware" in combined_desc or "encryption" in combined_desc:
        alert_type = "Ransomware Detection"
        rule_id = "RULE-CRIT-001"
        tags = ["ransomware", "critical", "malware"]
    elif "exfiltration" in combined_desc or "data transfer" in combined_desc:
        alert_type = "Data Exfiltration"
        rule_id = "RULE-CRIT-002"
        tags = ["exfiltration", "critical", "network"]
    elif "privileged" in combined_desc or "account takeover" in combined_desc or "takeover" in combined_desc:
        alert_type = "Privilege Compromise"
        rule_id = "RULE-CRIT-003"
        tags = ["account-takeover", "critical", "auth"]
    elif "destructive" in combined_desc or "tampering" in combined_desc or "dropped" in combined_desc:
        alert_type = "Destructive Action"
        rule_id = "RULE-CRIT-004"
        tags = ["tampering", "critical", "admin"]
    elif "c2" in combined_desc or "exploit" in combined_desc or "backdoor" in combined_desc:
        alert_type = "C2 / Exploit Execution"
        rule_id = "RULE-CRIT-005"
        tags = ["exploit", "c2", "critical"]
    elif "brute" in combined_desc or "repeated failed" in combined_desc or "multiple failed" in combined_desc:
        alert_type = "Brute Force Attempt"
        rule_id = "RULE-HIGH-001"
        tags = ["brute-force", "auth", "high"]
    elif "escalation" in combined_desc:
        alert_type = "Privilege Escalation"
        rule_id = "RULE-HIGH-002"
        tags = ["privilege-escalation", "high"]
    elif "malware" in combined_desc or "trojan" in combined_desc or "virus" in combined_desc:
        alert_type = "Malware Detection"
        rule_id = "RULE-HIGH-003"
        tags = ["malware", "threat", "high"]
    elif "scan" in combined_desc or "reconnaissance" in combined_desc:
        alert_type = "Port Scan / Recon"
        rule_id = "RULE-HIGH-004"
        tags = ["reconnaissance", "portscan", "high"]
    elif "tampering" in combined_desc or "service tampering" in combined_desc:
        alert_type = "Suspicious Admin Activity"
        rule_id = "RULE-HIGH-005"
        tags = ["admin-tampering", "high"]
    elif "unauthorized access" in combined_desc or "perimeter" in combined_desc:
        alert_type = "Unauthorized Access"
        rule_id = "RULE-HIGH-006"
        tags = ["unauthorized-access", "high"]
    elif sev == "CRITICAL":
        alert_type = "Critical Security Anomaly"
        rule_id = "RULE-CRIT-999"
        tags = ["security", "critical"]
    else:
        alert_type = "High Security Anomaly"
        rule_id = "RULE-HIGH-999"
        tags = ["security", "high"]

    # Construct human-readable alert message
    message = norm.get("message") or reason
    if user_name and user_name not in message:
        message = f"{message} (User: {user_name})"

    alert_payload = {
        "event_id": event_id,
        "timestamp": timestamp,
        "severity": sev.capitalize(),  # 'Critical' or 'High'
        "source": source,
        "alert_type": alert_type,
        "message": message,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "port": port_str,
        "rule_id": rule_id,
        "status": "Open",
        "assigned_to": "Unassigned",
        "tags": tags,
        "raw_log": raw_log or norm.get("raw_log", "")
    }

    alert_id = add_alert(alert_payload)
    return alert_id


def get_processed_logs(limit: int = 500, severity: str = None):
    connection = get_connection()
    cursor = connection.cursor()

    if severity:
        cursor.execute(
            """
            SELECT *
            FROM processed_logs
            WHERE severity_level = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (severity.upper(), limit)
        )
    else:
        cursor.execute(
            """
            SELECT *
            FROM processed_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )

    rows = cursor.fetchall()
    connection.close()

    logs = []
    for row in rows:
        try:
            norm_data = json.loads(row["normalized_data"]) if row["normalized_data"] else {}
        except Exception:
            norm_data = {}

        try:
            p_data = json.loads(row["parsed_data"]) if row["parsed_data"] else {}
        except Exception:
            p_data = {}

        # Fallback if SQLite row doesn't have the column yet
        sev_lvl = row["severity_level"] if "severity_level" in row.keys() else norm_data.get("severity_level", "CLEAN")
        sev_score = row["severity_score"] if "severity_score" in row.keys() else norm_data.get("severity_score", 0)
        sev_reason = row["severity_reason"] if "severity_reason" in row.keys() else norm_data.get("severity_reason", "")

        logs.append({
            "event_id": row["event_id"],
            "source_format": row["source_format"],
            "parser": row["parser"],
            "severity_level": sev_lvl,
            "severity_score": sev_score,
            "severity_reason": sev_reason,
            "parsed_data": p_data,
            "normalized_data": norm_data,
            "raw_log": row["raw_log"],
            "created_at": row["created_at"],
            "display_timestamp": format_timestamp(row["created_at"])
        })

    return logs


def get_severity_counts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT severity_level, COUNT(*) as count
        FROM processed_logs
        GROUP BY severity_level
    """)
    rows = cursor.fetchall()
    connection.close()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for r in rows:
        lvl = r["severity_level"]
        if lvl in counts:
            counts[lvl] = r["count"]
        elif lvl:
            counts[lvl] = r["count"]

    return counts
