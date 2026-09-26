import json
import uuid
import datetime
from database.db import get_connection
from database.formatting import format_timestamp

def init_alerts_table():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL,
            event_id TEXT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            port TEXT,
            rule_id TEXT,
            status TEXT DEFAULT 'Open',
            assigned_to TEXT DEFAULT 'Unassigned',
            tags TEXT,
            raw_log TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    connection.commit()
    connection.close()

def add_alert(alert_data: dict) -> str:
    init_alerts_table()
    connection = get_connection()
    cursor = connection.cursor()

    alert_id = alert_data.get("alert_id") or ("ALERT-" + datetime.datetime.utcnow().strftime("%Y%m%d") + "-" + str(uuid.uuid4())[:8].upper())
    tags = alert_data.get("tags")
    if isinstance(tags, list):
        tags_str = json.dumps(tags)
    elif isinstance(tags, str):
        tags_str = tags
    else:
        tags_str = "[]"

    cursor.execute('''
        INSERT OR IGNORE INTO alerts (
            alert_id, event_id, timestamp, severity, source, alert_type,
            message, source_ip, destination_ip, port, rule_id, status,
            assigned_to, tags, raw_log
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_id,
        alert_data.get("event_id"),
        alert_data.get("timestamp") or datetime.datetime.utcnow().isoformat(),
        alert_data.get("severity", "Medium"),
        alert_data.get("source", "System"),
        alert_data.get("alert_type", "Security Anomaly"),
        alert_data.get("message", "Security alert triggered"),
        alert_data.get("source_ip"),
        alert_data.get("destination_ip"),
        alert_data.get("port"),
        alert_data.get("rule_id", "RULE-1001"),
        alert_data.get("status", "Open"),
        alert_data.get("assigned_to", "Unassigned"),
        tags_str,
        alert_data.get("raw_log", "")
    ))

    connection.commit()
    connection.close()
    return alert_id

def get_alerts():
    init_alerts_table()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    connection.close()

    alerts = []
    for row in rows:
        try:
            tags = json.loads(row["tags"]) if row["tags"] else []
        except Exception:
            tags = [row["tags"]] if row["tags"] else []

        alerts.append({
            "id": row["id"],
            "alert_id": row["alert_id"],
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "severity": row["severity"],
            "source": row["source"],
            "alert_type": row["alert_type"],
            "message": row["message"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "port": row["port"],
            "rule_id": row["rule_id"],
            "status": row["status"],
            "assigned_to": row["assigned_to"],
            "tags": tags,
            "raw_log": row["raw_log"],
            "created_at": row["created_at"],
            "display_timestamp": format_timestamp(row["created_at"] or row["timestamp"])
        })
    return alerts

def get_alert_by_id(alert_id: str):
    init_alerts_table()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM alerts WHERE alert_id = ? OR id = ?", (alert_id, alert_id))
    row = cursor.fetchone()
    connection.close()
    if not row:
        return None

    try:
        tags = json.loads(row["tags"]) if row["tags"] else []
    except Exception:
        tags = [row["tags"]] if row["tags"] else []

    return {
        "id": row["id"],
        "alert_id": row["alert_id"],
        "event_id": row["event_id"],
        "timestamp": row["timestamp"],
        "severity": row["severity"],
        "source": row["source"],
        "alert_type": row["alert_type"],
        "message": row["message"],
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "port": row["port"],
        "rule_id": row["rule_id"],
        "status": row["status"],
        "assigned_to": row["assigned_to"],
        "tags": tags,
        "raw_log": row["raw_log"],
        "created_at": row["created_at"],
        "display_timestamp": format_timestamp(row["created_at"] or row["timestamp"])
    }

def update_alert(alert_id: str, updates: dict):
    init_alerts_table()
    connection = get_connection()
    cursor = connection.cursor()

    valid_fields = ["status", "assigned_to", "severity"]
    set_clauses = []
    params = []
    for k, v in updates.items():
        if k in valid_fields:
            set_clauses.append(k + " = ?")
            params.append(v)

    if not set_clauses:
        connection.close()
        return False

    params.append(alert_id)
    cursor.execute("UPDATE alerts SET " + ", ".join(set_clauses) + " WHERE alert_id = ?", tuple(params))
    changed = cursor.rowcount > 0
    connection.commit()
    connection.close()
    return changed
