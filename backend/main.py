import sys
import os

# Ensure backend directory is in sys.path for root invocations (e.g. Render / uvicorn backend.main:app)
_backend_dir = os.path.dirname(os.path.abspath(__file__))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from typing import Optional, List

import uuid
import time
from database.processed import add_processed_log
from database.formatting import format_timestamp, get_display_config
from database.settings import (
    get_all_settings,
    update_settings,
    init_settings_table,
    get_setting,
    is_setting_enabled,
    get_retention_days
)

# Ensure database tables (quarantine, processed, alerts, settings) are fully initialized on startup
from database.db import init_database
from database.alerts import init_alerts_table
init_database()
init_alerts_table()
init_settings_table()


from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from custom.custom_parser import parse_custom_log
from normalizer.normalizer import normalize_event
from parsers.registry import ParserRegistry
from core.detector import detect_format
from quarantine.storage import add_to_quarantine
from validation.validator import validate_event

class LogRequest(BaseModel):
    raw_log: str
    format: Optional[str] = None

class BatchLogRequest(BaseModel):
    logs: list[str]
    format: Optional[str] = None

app = FastAPI(
    title="Universal Log Pre-Processing Framework",
    description="SIH26156 Universal Log Pre-Processing Framework",
    version="1.0.0"
)
# CORS Configuration:
# Allows production domains (e.g. Vercel frontend) via ALLOWED_ORIGINS environment variable
# while keeping local development environments working automatically.
raw_origins = os.getenv("ALLOWED_ORIGINS") or os.getenv("CORS_ORIGINS") or ""
configured_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

default_dev_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]

allowed_origins = list(default_dev_origins)
for o in configured_origins:
    if o not in allowed_origins:
        allowed_origins.append(o)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    cfg = get_display_config()
    app_name = cfg["application_name"]
    org = cfg["organization"]
    return {
        "message": f"{app_name} API",
        "organization": org,
        "status": "running",
        "version": "1.0.0",
        "docs": "/docs",
        "api_base": "/api/v1"
    }

@app.get("/health")
def health():
    cfg = get_display_config()
    return {
        "status": "healthy",
        "application_name": cfg["application_name"],
        "organization": cfg["organization"]
    }


@app.post("/api/v1/process")
def process_log(request: LogRequest):
    # 1. Check realtime_processing setting
    if not is_setting_enabled("realtime_processing", default=True):
        return JSONResponse(
            status_code=400,
            content={
                "status": "disabled",
                "message": "Real-time log processing is disabled in Settings.",
                "detail": "Real-time log processing is disabled in Settings."
            }
        )

    # 2. Check auto_detect_formats setting
    auto_detect = is_setting_enabled("auto_detect_formats", default=True)
    explicit_fmt = request.format.strip().upper() if (request.format and request.format.strip()) else None

    if not auto_detect:
        if not explicit_fmt:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "validation_error",
                    "message": "Automatic format detection is disabled in Settings. An explicit format is required.",
                    "detail": "Automatic format detection is disabled in Settings. An explicit format is required."
                }
            )
        valid_formats = {"SYSLOG", "JSON", "CEF", "LEEF", "XML", "CSV", "CUSTOM"}
        if explicit_fmt not in valid_formats:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "validation_error",
                    "message": f"Unsupported explicit format: '{explicit_fmt}'. Supported formats: {', '.join(sorted(valid_formats))}",
                    "detail": f"Unsupported explicit format: '{explicit_fmt}'. Supported formats: {', '.join(sorted(valid_formats))}"
                }
            )

    raw_text = request.raw_log.strip()
    start_time = time.perf_counter()

    if explicit_fmt:
        initial_det = {"format": explicit_fmt, "confidence": 1.0, "method": "Explicitly supplied format"}
    else:
        initial_det = detect_format(raw_text)

    is_multi_doc = initial_det["format"] in ("CSV", "XML")
    lines = [l.strip() for l in raw_text.splitlines() if l.strip()]

    # If multiple lines were submitted and NOT a multi-line format like CSV/XML, process each line
    if not is_multi_doc and len(lines) > 1:
        processed_count = 0
        quarantined_count = 0
        last_result = None
        for raw_line in lines:
            if explicit_fmt:
                det = {"format": explicit_fmt, "confidence": 1.0, "method": "Explicitly supplied format"}
            else:
                det = detect_format(raw_line)

            if det["format"] in ("UNKNOWN", "CUSTOM"):
                try:
                    c_parsed = parse_custom_log(raw_line)
                    norm = normalize_event(c_parsed, {"format": "CUSTOM", "confidence": 0.70, "method": "Custom key-value parser"}, raw_line)
                    val = validate_event(norm)
                    if not val["valid"]:
                        add_to_quarantine({"quarantine_id": str(uuid.uuid4()), "reason": "Validation failed", "detection": det, "validation": val, "normalized": norm, "raw_log": raw_line})
                        quarantined_count += 1
                        last_result = {"status": "quarantined", "detection": det, "normalized": norm}
                        continue
                    add_processed_log(event_id=norm["event_id"], source_format="CUSTOM", parser=c_parsed.get("parser", "custom_parser"), parsed_data=c_parsed, normalized_data=norm, raw_log=raw_line)
                    processed_count += 1
                    last_result = {"status": "processed", "detection": det, "parsed": c_parsed, "normalized": norm, "validation": val}
                except Exception:
                    add_to_quarantine({"quarantine_id": str(uuid.uuid4()), "reason": "Unknown or unsupported log format", "detection": det, "raw_log": raw_line})
                    quarantined_count += 1
                    last_result = {"status": "quarantined", "detection": det}
            else:
                try:
                    reg = ParserRegistry()
                    parser = reg.get_parser(det["format"])
                    parsed = parser.parse(raw_line)
                    norm = normalize_event(parsed, det, raw_line)
                    val = validate_event(norm)
                    if not val["valid"]:
                        add_to_quarantine({"quarantine_id": str(uuid.uuid4()), "reason": "Validation failed", "detection": det, "validation": val, "normalized": norm, "raw_log": raw_line})
                        quarantined_count += 1
                        last_result = {"status": "quarantined", "detection": det, "normalized": norm}
                        continue
                    add_processed_log(event_id=norm["event_id"], source_format=det["format"], parser=parsed.get("parser"), parsed_data=parsed, normalized_data=norm, raw_log=raw_line)
                    processed_count += 1
                    last_result = {"status": "processed", "detection": det, "parsed": parsed, "normalized": norm, "validation": val}
                except Exception as err:
                    add_to_quarantine({"quarantine_id": str(uuid.uuid4()), "reason": str(err), "detection": det, "raw_log": raw_line})
                    quarantined_count += 1
                    last_result = {"status": "quarantined", "detection": det}

        return {
            "status": "processed" if processed_count > 0 else "quarantined",
            "total_lines": len(lines),
            "processed_count": processed_count,
            "quarantined_count": quarantined_count,
            "processing_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
            "detection": last_result.get("detection") if last_result else {"format": "BATCH"},
            "normalized": last_result.get("normalized") if last_result else {},
            "validation": last_result.get("validation") if last_result else {"valid": processed_count > 0}
        }

    raw_log = raw_text if is_multi_doc else (lines[0] if lines else raw_text)
    detection = initial_det

    # Handle custom or unknown logs
    if detection["format"] in ("UNKNOWN", "CUSTOM"):
        try:
            custom_parsed = parse_custom_log(raw_log)
            if not custom_parsed.get("data"):
                raise ValueError("No valid key-value pairs or recognizable structure found")
            normalized = normalize_event(
                custom_parsed,
                {
                    "format": "CUSTOM",
                    "confidence": 0.70,
                    "method": "Custom key-value parser"
                },
                raw_log
            )
            validation = validate_event(normalized)

            if not validation["valid"]:
                quarantine_id = str(uuid.uuid4())
                quarantine_data = {
                    "quarantine_id": quarantine_id,
                    "reason": "Validation failed",
                    "detection": detection,
                    "validation": validation,
                    "normalized": normalized,
                    "raw_log": raw_log
                }
                add_to_quarantine(quarantine_data)
                return {
                    "status": "quarantined",
                    **quarantine_data
                }

            # Save successfully processed custom log
            add_processed_log(
                event_id=normalized["event_id"],
                source_format="CUSTOM",
                parser=custom_parsed.get("parser", "custom_parser"),
                parsed_data=custom_parsed,
                normalized_data=normalized,
                raw_log=raw_log
            )

            return {
                "status": "processed",
                "processing_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "detection": detection,
                "parsed": custom_parsed,
                "normalized": normalized,
                "validation": validation
            }

        except ValueError:
            quarantine_id = str(uuid.uuid4())
            quarantine_data = {
                "quarantine_id": quarantine_id,
                "reason": "Unknown or unsupported log format",
                "detection": detection,
                "raw_log": raw_log
            }
            add_to_quarantine(quarantine_data)
            return {
                "status": "quarantined",
                **quarantine_data
            }

    # Handle supported formats
    registry = ParserRegistry()

    try:
        parser = registry.get_parser(detection["format"])
        parsed = parser.parse(raw_log)
        normalized = normalize_event(parsed, detection, raw_log)
        validation = validate_event(normalized)

        # Send invalid events to quarantine
        if not validation["valid"]:
            quarantine_id = str(uuid.uuid4())
            quarantine_data = {
                "quarantine_id": quarantine_id,
                "reason": "Validation failed",
                "detection": detection,
                "validation": validation,
                "normalized": normalized,
                "raw_log": raw_log
            }
            add_to_quarantine(quarantine_data)
            return {
                "status": "quarantined",
                **quarantine_data
            }

        # Save successfully processed event
        add_processed_log(
            event_id=normalized["event_id"],
            source_format=detection["format"],
            parser=parsed.get("parser"),
            parsed_data=parsed,
            normalized_data=normalized,
            raw_log=raw_log
        )

        return {
            "status": "processed",
            "processing_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
            "detection": detection,
            "parsed": parsed,
            "normalized": normalized,
            "validation": validation
        }

    except ValueError as error:
        quarantine_id = str(uuid.uuid4())
        quarantine_data = {
            "quarantine_id": quarantine_id,
            "reason": f"Parsing failed: {error}",
            "detection": detection,
            "raw_log": raw_log
        }
        add_to_quarantine(quarantine_data)
        return {
            "status": "quarantined",
            **quarantine_data
        }

class QuarantineActionRequest(BaseModel):
    notes: Optional[str] = "Updated via ARC console"

@app.get("/api/v1/quarantine")
def get_quarantine(status: Optional[str] = None):
    from quarantine.storage import get_quarantine_logs
    logs = get_quarantine_logs(status=status)
    return {
        "status": "success",
        "count": len(logs),
        "logs": logs
    }

@app.get("/api/v1/quarantine/stats")
def get_quarantine_stats_api():
    from quarantine.storage import get_quarantine_stats
    return {
        "status": "success",
        "stats": get_quarantine_stats()
    }

@app.post("/api/v1/quarantine/{quarantine_id}/resolve")
def resolve_quarantine_item(quarantine_id: str, payload: Optional[QuarantineActionRequest] = None):
    from quarantine.storage import resolve_quarantine_log, get_quarantine_stats
    notes = payload.notes if payload and payload.notes else "Resolved by operator"
    ok = resolve_quarantine_log(quarantine_id, notes=notes)
    if not ok:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {
        "status": "success",
        "message": f"Log {quarantine_id} marked as resolved",
        "quarantine_id": quarantine_id,
        "stats": get_quarantine_stats()
    }

@app.post("/api/v1/quarantine/{quarantine_id}/reject")
def reject_quarantine_item(quarantine_id: str, payload: Optional[QuarantineActionRequest] = None):
    from quarantine.storage import reject_quarantine_log, get_quarantine_stats
    notes = payload.notes if payload and payload.notes else "Auto-rejected by rule"
    ok = reject_quarantine_log(quarantine_id, notes=notes)
    if not ok:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {
        "status": "success",
        "message": f"Log {quarantine_id} marked as rejected",
        "quarantine_id": quarantine_id,
        "stats": get_quarantine_stats()
    }

@app.post("/api/v1/quarantine/{quarantine_id}/reopen")
def reopen_quarantine_item(quarantine_id: str):
    from quarantine.storage import reopen_quarantine_log, get_quarantine_stats
    ok = reopen_quarantine_log(quarantine_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {
        "status": "success",
        "message": f"Log {quarantine_id} reset to pending review",
        "quarantine_id": quarantine_id,
        "stats": get_quarantine_stats()
    }


@app.get("/api/v1/parsers")
def get_parsers():

    registry = ParserRegistry()

    return {
        "status": "success",
        "count": len(registry.list_parsers()),
        "parsers": registry.list_parsers()
    }

@app.get("/api/v1/processed")
def get_processed(severity: Optional[str] = None):

    from database.processed import get_processed_logs

    logs = get_processed_logs(severity=severity)

    return {
        "status": "success",
        "count": len(logs),
        "logs": logs
    }
@app.get("/api/v1/stats")
def get_stats():

    from database.db import get_connection

    connection = get_connection()
    cursor = connection.cursor()

    # Total processed logs
    cursor.execute("SELECT COUNT(*) FROM processed_logs")
    processed_count = cursor.fetchone()[0]

    # Total quarantined logs
    cursor.execute("SELECT COUNT(*) FROM quarantine_logs")
    quarantine_count = cursor.fetchone()[0]

    # Processed logs by format
    cursor.execute("""
        SELECT source_format, COUNT(*) as count
        FROM processed_logs
        GROUP BY source_format
        ORDER BY count DESC
    """)
    format_rows = cursor.fetchall()
    formats = {}
    for row in format_rows:
        formats[row["source_format"]] = row["count"]

    # Processed logs by severity
    cursor.execute("""
        SELECT severity_level, COUNT(*) as count
        FROM processed_logs
        GROUP BY severity_level
    """)
    sev_rows = cursor.fetchall()
    connection.close()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for r in sev_rows:
        lvl = r["severity_level"]
        if lvl in severity_counts:
            severity_counts[lvl] = r["count"]
        elif lvl:
            severity_counts[lvl] = r["count"]

    metrics_enabled = is_setting_enabled("metrics_collection", default=True)
    display = get_display_config()

    return {
        "status": "success",
        "processed_logs": processed_count,
        "quarantined_logs": quarantine_count,
        "metrics_collection_enabled": metrics_enabled,
        "formats": formats if metrics_enabled else {},
        "severity": severity_counts if metrics_enabled else {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0},
        "display_config": display
    }
@app.post("/api/v1/process/batch")
def process_batch(request: BatchLogRequest):
    # 1. Check realtime_processing setting
    if not is_setting_enabled("realtime_processing", default=True):
        return JSONResponse(
            status_code=400,
            content={
                "status": "disabled",
                "message": "Real-time log processing is disabled in Settings.",
                "detail": "Real-time log processing is disabled in Settings."
            }
        )

    # 2. Check auto_detect_formats setting
    auto_detect = is_setting_enabled("auto_detect_formats", default=True)
    explicit_fmt = request.format.strip().upper() if (request.format and request.format.strip()) else None

    if not auto_detect:
        if not explicit_fmt:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "validation_error",
                    "message": "Automatic format detection is disabled in Settings. An explicit format is required.",
                    "detail": "Automatic format detection is disabled in Settings. An explicit format is required."
                }
            )
        valid_formats = {"SYSLOG", "JSON", "CEF", "LEEF", "XML", "CSV", "CUSTOM"}
        if explicit_fmt not in valid_formats:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "validation_error",
                    "message": f"Unsupported explicit format: '{explicit_fmt}'. Supported formats: {', '.join(sorted(valid_formats))}",
                    "detail": f"Unsupported explicit format: '{explicit_fmt}'. Supported formats: {', '.join(sorted(valid_formats))}"
                }
            )

    results = []

    for raw_log in request.logs:
        if explicit_fmt:
            detection = {"format": explicit_fmt, "confidence": 1.0, "method": "Explicitly supplied format"}
        else:
            detection = detect_format(raw_log)

        try:
            if detection["format"] in ("UNKNOWN", "CUSTOM"):
                custom_parsed = parse_custom_log(raw_log)
                normalized = normalize_event(
                    custom_parsed,
                    {
                        "format": "CUSTOM",
                        "confidence": 0.70,
                        "method": "Custom key-value parser"
                    },
                    raw_log
                )
                validation = validate_event(normalized)

                if not validation["valid"]:
                    quarantine_id = str(uuid.uuid4())
                    quarantine_data = {
                        "quarantine_id": quarantine_id,
                        "reason": "Validation failed",
                        "detection": detection,
                        "validation": validation,
                        "normalized": normalized,
                        "raw_log": raw_log
                    }
                    add_to_quarantine(quarantine_data)
                    results.append({
                        "status": "quarantined",
                        **quarantine_data
                    })
                    continue

                add_processed_log(
                    event_id=normalized["event_id"],
                    source_format="CUSTOM",
                    parser=custom_parsed.get("parser"),
                    parsed_data=custom_parsed,
                    normalized_data=normalized,
                    raw_log=raw_log
                )
                results.append({
                    "status": "processed",
                    "detection": detection,
                    "normalized": normalized
                })
                continue

            registry = ParserRegistry()
            parser = registry.get_parser(detection["format"])
            parsed = parser.parse(raw_log)
            normalized = normalize_event(parsed, detection, raw_log)
            validation = validate_event(normalized)

            if not validation["valid"]:
                quarantine_id = str(uuid.uuid4())
                quarantine_data = {
                    "quarantine_id": quarantine_id,
                    "reason": "Validation failed",
                    "detection": detection,
                    "validation": validation,
                    "normalized": normalized,
                    "raw_log": raw_log
                }
                add_to_quarantine(quarantine_data)
                results.append({
                    "status": "quarantined",
                    **quarantine_data
                })
                continue

            add_processed_log(
                event_id=normalized["event_id"],
                source_format=detection["format"],
                parser=parsed.get("parser"),
                parsed_data=parsed,
                normalized_data=normalized,
                raw_log=raw_log
            )
            results.append({
                "status": "processed",
                "detection": detection,
                "normalized": normalized
            })

        except ValueError as error:
            results.append({
                "status": "parser_not_available",
                "detection": detection,
                "error": str(error),
                "raw_log": raw_log
            })

    return {
        "status": "success",
        "total": len(request.logs),
        "results": results
    }

@app.get("/api/v1/processed/{event_id}")
def get_processed_event(event_id: str):

    from database.db import get_connection
    import json

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM processed_logs
        WHERE event_id = ?
        """,
        (event_id,)
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return {
            "status": "not_found",
            "event_id": event_id
        }

    norm_data = json.loads(row["normalized_data"]) if row["normalized_data"] else {}
    sev_lvl = row["severity_level"] if "severity_level" in row.keys() else norm_data.get("severity_level", "CLEAN")
    sev_score = row["severity_score"] if "severity_score" in row.keys() else norm_data.get("severity_score", 0)
    sev_reason = row["severity_reason"] if "severity_reason" in row.keys() else norm_data.get("severity_reason", "")

    return {
        "status": "success",
        "event": {
            "event_id": row["event_id"],
            "source_format": row["source_format"],
            "parser": row["parser"],
            "severity_level": sev_lvl,
            "severity_score": sev_score,
            "severity_reason": sev_reason,
            "parsed_data": json.loads(row["parsed_data"]) if row["parsed_data"] else {},
            "normalized_data": norm_data,
            "raw_log": row["raw_log"],
            "created_at": row["created_at"],
            "display_timestamp": format_timestamp(row["created_at"])
        }
    }

@app.get("/api/v1/quarantine/{quarantine_id}")
def get_quarantine_event(quarantine_id: str):

    from database.db import get_connection
    import json

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM quarantine_logs
        WHERE quarantine_id = ?
        """,
        (quarantine_id,)
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return {
            "status": "not_found",
            "quarantine_id": quarantine_id
        }

    return {
        "status": "success",
        "event": {
            "quarantine_id": row["quarantine_id"],
            "reason": row["reason"],
            "detection": json.loads(row["detection"]) if row["detection"] else {},
            "validation": json.loads(row["validation"]) if row["validation"] else {},
            "normalized": json.loads(row["normalized"]) if row["normalized"] else {},
            "raw_log": row["raw_log"],
            "created_at": row["created_at"]
        }
    }
@app.get("/api/v1/summary")
def get_summary():

    from database.db import get_connection

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM processed_logs")
    processed_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM quarantine_logs")
    quarantine_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT severity_level, COUNT(*) as count
        FROM processed_logs
        GROUP BY severity_level
    """)
    sev_rows = cursor.fetchall()
    connection.close()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for r in sev_rows:
        lvl = r["severity_level"]
        if lvl in severity_counts:
            severity_counts[lvl] = r["count"]
        elif lvl:
            severity_counts[lvl] = r["count"]

    parser_count = len(ParserRegistry().list_parsers())
    total_logs = processed_count + quarantine_count

    return {
        "status": "success",
        "summary": {
            "total_logs": total_logs,
            "processed_logs": processed_count,
            "quarantined_logs": quarantine_count,
            "supported_formats": parser_count,
            "severity": severity_counts
        }
    }


class UpdateAlertRequest(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    severity: str | None = None


@app.get("/api/v1/alerts")
def get_alerts_endpoint():
    from database.alerts import get_alerts
    alerts = get_alerts()

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    type_counts = {}
    source_counts = {}

    for a in alerts:
        sev = a.get("severity", "Medium")
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts[sev] = 1

        atype = a.get("alert_type", "Other")
        type_counts[atype] = type_counts.get(atype, 0) + 1

        src = a.get("source", "System")
        source_counts[src] = source_counts.get(src, 0) + 1

    return {
        "status": "success",
        "total": len(alerts),
        "counts_by_severity": sev_counts,
        "counts_by_type": type_counts,
        "counts_by_source": source_counts,
        "alerts": alerts
    }


@app.get("/api/v1/alerts/{alert_id}")
def get_alert_detail_endpoint(alert_id: str):
    from database.alerts import get_alert_by_id
    alert = get_alert_by_id(alert_id)
    if not alert:
        return {"status": "not_found", "alert_id": alert_id}
    return {"status": "success", "alert": alert}


@app.patch("/api/v1/alerts/{alert_id}")
def update_alert_endpoint(alert_id: str, req: UpdateAlertRequest):
    from database.alerts import update_alert, get_alert_by_id
    updates = {k: v for k, v in req.dict().items() if v is not None}
    if not updates:
        return {"status": "error", "message": "No valid fields provided"}
    success = update_alert(alert_id, updates)
    if not success:
        return {"status": "not_found", "alert_id": alert_id}
    return {"status": "success", "alert": get_alert_by_id(alert_id)}


# ============================================================
# AI ASSISTANT ENDPOINTS (Provider Abstraction: Platform, Ollama, BYOK)
# ============================================================
class BYOKConfig(BaseModel):
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = "custom"


class AIChatRequest(BaseModel):
    message: Optional[str] = None
    prompt: Optional[str] = None
    include_context: bool = True
    byok: Optional[BYOKConfig] = None


@app.get("/api/v1/ai/status")
def get_ai_status():
    """
    Returns AI status safely without revealing server credentials.
    Supports Platform AI mode (default in prod) and Ollama (local dev).
    """
    from ai.manager import get_system_provider
    provider = get_system_provider()
    return provider.get_status()


@app.post("/api/v1/ai/chat")
def ai_chat_endpoint(req: AIChatRequest):
    """
    Processes chat requests with real operational database context.
    Dispatches to Platform AI, Ollama, or BYOK request-scoped provider.
    Never exposes credentials or fakes telemetry.
    """
    # Check ai_suggestions setting
    if not is_setting_enabled("ai_suggestions", default=True):
        return {
            "status": "disabled",
            "error_code": "AI_SUGGESTIONS_DISABLED",
            "configured": False,
            "response": "AI suggestions are disabled in Settings.",
            "message": "AI suggestions are disabled in Settings."
        }

    user_query = req.message or req.prompt
    if not user_query or not user_query.strip():
        return {
            "status": "error",
            "message": "Message prompt cannot be empty."
        }

    from ai.manager import resolve_chat_provider, build_operational_context

    byok_dict = (req.byok.model_dump() if hasattr(req.byok, "model_dump") else req.byok.dict()) if req.byok else None
    provider, err_msg = resolve_chat_provider(byok_dict)
    if err_msg:
        return {
            "status": "error",
            "error_code": "INVALID_CONFIGURATION",
            "configured": False,
            "response": err_msg,
            "message": err_msg
        }

    system_context = build_operational_context() if req.include_context else (
        "You are ARC AI Assistant, the intelligent telemetry assistant for the ARC Universal Log Pre-Processing Framework."
    )
    result = provider.generate(prompt=user_query.strip(), system_context=system_context)
    return result


# ============================================================
# SEVERITY / CRITICALITY CLASSIFICATION ENDPOINTS
# ============================================================
@app.get("/api/v1/severity/rules")
def get_severity_rules_endpoint():
    from core.severity_classifier import get_classification_rules
    return get_classification_rules()


@app.get("/api/v1/severity/stats")
def get_severity_stats_endpoint():
    from database.processed import get_severity_counts
    counts = get_severity_counts()
    return {
        "status": "success",
        "severity": counts,
        "total_classified": sum(counts.values())
    }


# ============================================================
# ANALYTICS: REAL PROCESSING TREND (time-series from DB)
# ============================================================
@app.get("/api/v1/analytics/processing-trend")
def get_processing_trend(hours: int = 24):
    """
    Returns real hourly processing counts derived from DB record timestamps.
    Only returns data if logs exist with real timestamps — never fakes values.
    """
    if not is_setting_enabled("metrics_collection", default=True):
        return {
            "status": "disabled",
            "metrics_collection_enabled": False,
            "message": "Metrics collection is disabled in Settings.",
            "has_data": False,
            "buckets": []
        }
    from database.db import get_connection
    import datetime

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM processed_logs")
    total = cursor.fetchone()[0]

    if total == 0:
        connection.close()
        return {
            "status": "success",
            "has_data": False,
            "message": "No processing data available yet.",
            "buckets": []
        }

    # Group by hour using SQLite strftime
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as bucket,
               COUNT(*) as count
        FROM processed_logs
        WHERE created_at >= ?
        GROUP BY bucket
        ORDER BY bucket ASC
    """, (cutoff,))
    rows = cursor.fetchall()

    # Also get quarantine in same window
    cursor.execute("""
        SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as bucket,
               COUNT(*) as count
        FROM quarantine_logs
        WHERE created_at >= ?
        GROUP BY bucket
        ORDER BY bucket ASC
    """, (cutoff,))
    q_rows = cursor.fetchall()
    connection.close()

    q_map = {r["bucket"]: r["count"] for r in q_rows}

    buckets = []
    for row in rows:
        bucket = row["bucket"]
        buckets.append({
            "timestamp": bucket,
            "processed": row["count"],
            "quarantined": q_map.get(bucket, 0)
        })

    return {
        "status": "success",
        "has_data": len(buckets) > 0,
        "total_in_window": total,
        "window_hours": hours,
        "buckets": buckets
    }


# ============================================================

# ============================================================

# ============================================================
# SETTINGS: PERSISTENT CONFIGURATION
# ============================================================
from database.settings import (
    get_all_settings,
    update_settings,
    init_settings_table
)

# Ensure settings table and default values are initialized
init_settings_table()

class GeneralSettingsModel(BaseModel):
    application_name: Optional[str] = None
    organization: Optional[str] = None
    timezone: Optional[str] = None
    date_format: Optional[str] = None
    time_format: Optional[str] = None
    language: Optional[str] = None

class SystemSettingsModel(BaseModel):
    realtime_processing: Optional[bool] = None
    auto_detect_formats: Optional[bool] = None
    ai_suggestions: Optional[bool] = None
    store_raw_logs: Optional[bool] = None
    metrics_collection: Optional[bool] = None
    retention_period_days: Optional[int] = None

class SecuritySettingsModel(BaseModel):
    two_factor_authentication: Optional[bool] = None
    session_timeout_minutes: Optional[int] = None
    password_policy: Optional[str] = None
    ip_whitelist: Optional[str] = None
    login_attempts_limit: Optional[int] = None
    account_lockout_minutes: Optional[int] = None

class IntegrationsSettingsModel(BaseModel):
    siem_integration: Optional[str] = None
    email_notifications: Optional[str] = None
    slack_integration: Optional[str] = None
    webhook_endpoint: Optional[str] = None
    api_access: Optional[str] = None

class NotificationsSettingsModel(BaseModel):
    critical_alerts: Optional[bool] = None
    system_errors: Optional[bool] = None
    daily_summary: Optional[bool] = None
    weekly_report: Optional[bool] = None
    notification_email: Optional[str] = None

class AppearanceSettingsModel(BaseModel):
    theme: Optional[str] = None
    primary_color: Optional[str] = None
    compact_mode: Optional[bool] = None
    show_animations: Optional[bool] = None

class SettingsUpdateRequestModel(BaseModel):
    general: Optional[GeneralSettingsModel] = None
    system: Optional[SystemSettingsModel] = None
    security: Optional[SecuritySettingsModel] = None
    integrations: Optional[IntegrationsSettingsModel] = None
    notifications: Optional[NotificationsSettingsModel] = None
    appearance: Optional[AppearanceSettingsModel] = None

    application_name: Optional[str] = None
    organization: Optional[str] = None
    timezone: Optional[str] = None
    date_format: Optional[str] = None
    time_format: Optional[str] = None
    language: Optional[str] = None
    realtime_processing: Optional[bool] = None
    auto_detect_formats: Optional[bool] = None
    ai_suggestions: Optional[bool] = None
    store_raw_logs: Optional[bool] = None
    metrics_collection: Optional[bool] = None
    retention_period_days: Optional[int] = None
    two_factor_authentication: Optional[bool] = None
    session_timeout_minutes: Optional[int] = None
    password_policy: Optional[str] = None
    ip_whitelist: Optional[str] = None
    login_attempts_limit: Optional[int] = None
    account_lockout_minutes: Optional[int] = None
    siem_integration: Optional[str] = None
    email_notifications: Optional[str] = None
    slack_integration: Optional[str] = None
    webhook_endpoint: Optional[str] = None
    api_access: Optional[str] = None
    critical_alerts: Optional[bool] = None
    system_errors: Optional[bool] = None
    daily_summary: Optional[bool] = None
    weekly_report: Optional[bool] = None
    notification_email: Optional[str] = None
    theme: Optional[str] = None
    primary_color: Optional[str] = None
    compact_mode: Optional[bool] = None
    show_animations: Optional[bool] = None

@app.get("/api/v1/settings")
def get_settings():
    """
    Returns all persistent settings structured by section.
    """
    try:
        data = get_all_settings()
        display = get_display_config()
        return {
            "status": "success",
            "settings": data,
            "data": data,
            "display_config": display
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/settings")
def update_settings_endpoint(payload: dict):
    """
    Accepts partial or complete settings updates.
    Validates enums, numeric ranges, email, and URLs.
    Persists changes to SQLite settings table and returns the complete updated settings.
    """
    try:
        updated = update_settings(payload)
        return {
            "status": "success",
            "message": "Settings updated successfully",
            "settings": updated,
            "data": updated
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# ADMIN: SAFE TEST RESET (clears processed + quarantine + alerts)
# ============================================================
@app.delete("/api/v1/admin/clear-test-data")
def clear_test_data(confirm: str = ""):
    """Safe reset for testing only. Requires confirm=YES query param."""
    if confirm != "YES":
        return {"status": "error", "message": "Pass ?confirm=YES to clear test data."}

    from database.db import get_connection
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM processed_logs")
    p = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM quarantine_logs")
    q = cursor.fetchone()[0]

    cursor.execute("DELETE FROM processed_logs")
    cursor.execute("DELETE FROM quarantine_logs")
    try:
        cursor.execute("DELETE FROM alerts")
    except Exception:
        pass
    try:
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='processed_logs'")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='quarantine_logs'")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
    except Exception:
        pass

    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": "Test data cleared.",
        "cleared": {"processed_logs": p, "quarantine_logs": q}
    }
