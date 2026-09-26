def normalize_event(parsed_data: dict, detection: dict) -> dict:

    data = parsed_data.get("data", {})

    return {
        "event_id": None,
        "timestamp": data.get("timestamp"),
        "source_ip": data.get("source_ip") or data.get("src"),
        "destination_ip": data.get("destination_ip") or data.get("dst"),
        "source_port": data.get("source_port") or data.get("srcPort"),
        "destination_port": data.get("destination_port") or data.get("dstPort"),
        "user": data.get("user"),
        "host": data.get("host"),
        "action": data.get("action"),
        "severity": data.get("severity"),
        "message": data.get("message"),
        "source_format": detection["format"],
        "parser": parsed_data.get("parser"),
        "raw_data": data
    }