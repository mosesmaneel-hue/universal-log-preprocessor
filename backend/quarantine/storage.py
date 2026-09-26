import json
from database.db import get_connection


def add_to_quarantine(log_data: dict):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO quarantine_logs
        (
            quarantine_id,
            reason,
            detection,
            validation,
            normalized,
            raw_log,
            review_status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
        """,
        (
            log_data["quarantine_id"],
            log_data["reason"],
            json.dumps(log_data.get("detection", {})),
            json.dumps(log_data.get("validation", {})),
            json.dumps(log_data.get("normalized", {})),
            log_data["raw_log"]
        )
    )

    connection.commit()
    connection.close()


def get_quarantine_logs(status: str = None):
    connection = get_connection()
    cursor = connection.cursor()

    if status and status.upper() != "ALL":
        cursor.execute(
            """
            SELECT *
            FROM quarantine_logs
            WHERE UPPER(review_status) = ?
            ORDER BY id DESC
            """,
            (status.upper(),)
        )
    else:
        cursor.execute(
            """
            SELECT *
            FROM quarantine_logs
            ORDER BY id DESC
            """
        )

    rows = cursor.fetchall()
    connection.close()

    logs = []
    for row in rows:
        keys = row.keys() if hasattr(row, "keys") else []
        review_status = row["review_status"] if "review_status" in keys and row["review_status"] else "PENDING"
        reviewed_at = row["reviewed_at"] if "reviewed_at" in keys else None
        resolution_notes = row["resolution_notes"] if "resolution_notes" in keys else None

        logs.append({
            "quarantine_id": row["quarantine_id"],
            "reason": row["reason"],
            "detection": json.loads(row["detection"]) if row["detection"] else {},
            "validation": json.loads(row["validation"]) if row["validation"] else {},
            "normalized": json.loads(row["normalized"]) if row["normalized"] else {},
            "raw_log": row["raw_log"],
            "created_at": row["created_at"],
            "review_status": review_status,
            "reviewed_at": reviewed_at,
            "resolution_notes": resolution_notes
        })

    return logs


def get_quarantine_stats():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM quarantine_logs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM quarantine_logs WHERE UPPER(COALESCE(review_status, 'PENDING')) = 'PENDING'")
    pending = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM quarantine_logs WHERE UPPER(review_status) = 'RESOLVED'")
    resolved = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM quarantine_logs WHERE UPPER(review_status) = 'REJECTED'")
    rejected = cursor.fetchone()[0]

    connection.close()

    return {
        "total": total,
        "pending": pending,
        "resolved": resolved,
        "rejected": rejected
    }


def resolve_quarantine_log(quarantine_id: str, notes: str = "Resolved by operator"):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE quarantine_logs
        SET review_status = 'RESOLVED',
            reviewed_at = CURRENT_TIMESTAMP,
            resolution_notes = ?
        WHERE quarantine_id = ?
        """,
        (notes, quarantine_id)
    )
    rows_affected = cursor.rowcount
    connection.commit()
    connection.close()
    return rows_affected > 0


def reject_quarantine_log(quarantine_id: str, notes: str = "Auto-rejected by rule"):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE quarantine_logs
        SET review_status = 'REJECTED',
            reviewed_at = CURRENT_TIMESTAMP,
            resolution_notes = ?
        WHERE quarantine_id = ?
        """,
        (notes, quarantine_id)
    )
    rows_affected = cursor.rowcount
    connection.commit()
    connection.close()
    return rows_affected > 0


def reopen_quarantine_log(quarantine_id: str):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE quarantine_logs
        SET review_status = 'PENDING',
            reviewed_at = NULL,
            resolution_notes = NULL
        WHERE quarantine_id = ?
        """,
        (quarantine_id,)
    )
    rows_affected = cursor.rowcount
    connection.commit()
    connection.close()
    return rows_affected > 0
