# Severity & Criticality Classifier
# Universal Log Pre-Processing Framework
# Rule-based deterministic classification based on security context.

import re

CLASSIFICATION_RULES = {
    "CRITICAL": {
        "score_range": "90-100",
        "description": "Severe security compromise, active ransomware, data exfiltration, or destructive administrative action",
        "indicators": [
            "Ransomware detected or active destructive file encryption",
            "Unauthorized data exfiltration detected",
            "Successful or attempted privileged account compromise / account takeover",
            "Multiple failed logins followed by successful administrative login",
            "Destructive administrative action (database dropped, shadow copies deleted, logs wiped)",
            "Critical security alert, exploit execution, or known malicious C2 communication",
            "Active high-threat malware or backdoor detected",
            "Source severity >= 9 with critical security compromise context"
        ]
    },
    "HIGH": {
        "score_range": "70-89",
        "description": "Repeated failed logins, privilege escalation, malware quarantined, unauthorized access attempt, or reconnaissance",
        "indicators": [
            "Repeated failed login attempts / brute-force authentication activity",
            "Privilege escalation attempt detected (sudo abuse, token manipulation)",
            "Malware or suspicious file detected and quarantined/blocked",
            "Network port scanning or unauthorized reconnaissance detected",
            "Suspicious administrative modification or security service tampering",
            "Unauthorized access attempt or firewall blocked suspicious connection",
            "Source severity 7-8 with security alert context"
        ]
    },
    "MEDIUM": {
        "score_range": "40-69",
        "description": "Single authentication failure, unusual login, policy violation, standard blocked connection, or inconclusive anomaly",
        "indicators": [
            "Unusual login context or anomalous user access pattern",
            "Security policy violation or restricted asset usage",
            "Single authentication failure or bad password",
            "Perimeter firewall drop / blocked connection without exploit signature",
            "Suspicious but inconclusive system/network anomaly",
            "Source severity 4-6 with security/warning context"
        ]
    },
    "LOW": {
        "score_range": "15-39",
        "description": "Informational security event, configuration change, user logout, or minor operational concern",
        "indicators": [
            "System configuration or administrative setting updated",
            "Informational security event (certificate renewed, session expired, mfa token)",
            "Standard user logout or session termination",
            "Routine system event with minor operational warning",
            "Source severity 1-3 with informational context"
        ]
    },
    "CLEAN": {
        "score_range": "0-14",
        "description": "Normal operational log, successful routine login, allowed traffic, or health check",
        "indicators": [
            "Successful standard user authentication / login",
            "Normal allowed network connection (HTTP 200, TCP established, allowed)",
            "Routine service health check or heartbeat",
            "Routine background service execution (cron, log rotation, daemon)",
            "Ordinary operational application log with no security risk"
        ]
    }
}


def get_classification_rules():
    return {
        "status": "success",
        "total_categories": len(CLASSIFICATION_RULES),
        "rules": CLASSIFICATION_RULES
    }


def _extract_text_corpus(normalized_event: dict, parsed_data: dict = None, raw_log: str = None):
    norm = normalized_event or {}
    parsed = parsed_data or {}
    p_data = (parsed.get("data") or {}) if isinstance(parsed.get("data"), dict) else {}

    fields = {}
    
    # 1. Action
    action = (
        norm.get("event", {}).get("action")
        or norm.get("action")
        or p_data.get("action")
        or p_data.get("act")
        or ""
    )
    fields["action"] = str(action).lower().strip()

    # 2. Message / Name
    msg = (
        norm.get("message")
        or norm.get("event", {}).get("reason")
        or p_data.get("message")
        or p_data.get("name")
        or p_data.get("msg")
        or ""
    )
    fields["message"] = str(msg).lower().strip()

    # 3. User
    user = (
        norm.get("user", {}).get("name")
        or norm.get("user")
        or p_data.get("user")
        or p_data.get("suser")
        or p_data.get("duser")
        or ""
    )
    fields["user"] = str(user).lower().strip()

    # 4. Source / Destination / Host
    src_ip = norm.get("source", {}).get("ip") or p_data.get("src") or p_data.get("src_ip") or ""
    dst_ip = norm.get("destination", {}).get("ip") or p_data.get("dst") or p_data.get("dst_ip") or ""
    host = norm.get("host", {}).get("name") or p_data.get("host") or ""

    # 5. Raw text
    raw = str(raw_log or norm.get("raw_log") or "").lower().strip()

    # Combine into a single normalized text corpus for contextual security inspection
    base_corpus = f"{fields['action']} {fields['message']} {fields['user']} {host} {src_ip} {dst_ip} {raw}".lower()
    # Normalize underscores and hyphens into spaces so snake_case matches natural language
    space_norm = base_corpus.replace("_", " ").replace("-", " ")
    combined_corpus = f" {base_corpus}  {space_norm} "

    # 6. Source severity
    src_sev = norm.get("event", {}).get("severity")
    if src_sev is None:
        src_sev = p_data.get("severity")
    try:
        if src_sev is not None:
            fields["source_severity"] = int(src_sev)
        else:
            fields["source_severity"] = None
    except (ValueError, TypeError):
        fields["source_severity"] = None

    return combined_corpus, fields


def classify_severity(normalized_event: dict, parsed_data: dict = None, raw_log: str = None) -> dict:
    corpus, fields = _extract_text_corpus(normalized_event, parsed_data, raw_log)
    action = fields["action"]
    msg = fields["message"]
    user = fields["user"]
    src_sev = fields.get("source_severity")

    # Helper: Check if event is explicitly allowed or benign
    is_explicit_clean = any(k in corpus for k in [
        "user login successful", "successful login", "authenticated successfully",
        "login success", "login successful", "allowed connection", "allowed session",
        "action=allow", "action=permit", "act=allow", "act=permit", "traffic allowed",
        "connection established", "health check", "heartbeat", "keepalive", "status=ok",
        "accepted password"
    ]) and not any(k in corpus for k in [
        "failed", "failure", "unauthorized", "compromise", "brute", "ransomware",
        "malware", "exfiltration", "exploit", "attack", "denied", "takeover", "port scan"
    ])

    # =========================================================================
    # 1. CRITICAL RULES (Score 90 - 100)
    # =========================================================================

    # Ransomware activity
    if any(k in corpus for k in [
        "ransomware", "ransom ware", "encrypting files", "ransom note",
        "vssadmin delete shadows", "shadow copies deleted", "cryptolocker",
        "wannacry", "lockbit", "ryuk", "revil", "active file encryption"
    ]):
        return {
            "severity_level": "CRITICAL",
            "severity_score": 98,
            "severity_reason": "Ransomware activity or destructive file encryption detected"
        }

    # Data exfiltration
    if any(k in corpus for k in [
        "data exfiltration", "data_exfiltration", "unauthorized data transfer",
        "exfiltrated data", "massive data transfer", "exfiltration detected"
    ]):
        return {
            "severity_level": "CRITICAL",
            "severity_score": 95,
            "severity_reason": "Unauthorized data exfiltration detected on network host"
        }

    # Privileged account compromise / Account takeover
    if any(k in corpus for k in [
        "privileged account compromise", "privileged_account_compromise",
        "account takeover", "account_takeover", "unauthorized root access",
        "unauthorized admin access", "compromised admin", "domain admin compromised",
        "simultaneously from two different geographic", "multiple failed logins followed by successful"
    ]):
        return {
            "severity_level": "CRITICAL",
            "severity_score": 95,
            "severity_reason": "Privileged account compromise or unauthorized administrative takeover detected"
        }

    # Destructive administrative action / Defense evasion
    if any(k in corpus for k in [
        "dropped database", "drop database", "database dropped",
        "audit log wiped", "event log cleared", "security logs cleared",
        "rm -rf /", "format drive", "disk formatted"
    ]):
        return {
            "severity_level": "CRITICAL",
            "severity_score": 95,
            "severity_reason": "Destructive administrative action or security audit log tampering detected"
        }

    # Critical system compromise / Exploit execution / C2 communication
    if any(k in corpus for k in [
        "critical security alert", "critical security incident",
        "c2 communication", "command and control", "c2 beacon",
        "cobalt strike", "cobaltstrike", "remote code execution",
        "rce exploit", "zero-day exploit", "zeroday", "confirmed malware compromise",
        "critical system compromise", "confirmed system compromise"
    ]):
        return {
            "severity_level": "CRITICAL",
            "severity_score": 95,
            "severity_reason": "Critical system compromise, exploit execution, or known malicious C2 communication"
        }

    # Source severity is 9 or 10 with confirmed compromise
    if src_sev is not None and src_sev >= 9:
        if any(k in corpus for k in ["confirmed compromise", "system compromised", "breach confirmed", "critical compromise"]):
            return {
                "severity_level": "CRITICAL",
                "severity_score": 95,
                "severity_reason": "Critical confirmed security incident with highest source severity"
            }

    # =========================================================================
    # 2. HIGH RULES (Score 70 - 89)
    # =========================================================================

    # Repeated failed logins / Brute-force activity
    if any(k in corpus for k in [
        "multiple failed login", "brute force", "brute_force", "brute-force",
        "repeated authentication failures", "repeated failed login", "password spraying",
        "credential stuffing", "failed root login attempts", "brute force attack"
    ]):
        return {
            "severity_level": "HIGH",
            "severity_score": 85,
            "severity_reason": "Repeated failed login attempts or brute-force authentication activity detected"
        }

    # Privilege escalation
    if any(k in corpus for k in [
        "privilege escalation", "privilege_escalation", "sudo abuse",
        "uac bypass", "token manipulation", "privilege escalated",
        "escalated to root", "escalated to admin", "unauthorized privilege escalation",
        "chmod 4755"
    ]):
        return {
            "severity_level": "HIGH",
            "severity_score": 85,
            "severity_reason": "Privilege escalation attempt detected"
        }

    # Port scanning / Reconnaissance
    if any(k in corpus for k in [
        "port scan", "port scanning", "port_scan", "network scan", "nmap scan",
        "reconnaissance activity", "stealth scan", "syn flood", "scan syn fin",
        "syn port scan", "ports scanned", "ports_scanned"
    ]):
        return {
            "severity_level": "HIGH",
            "severity_score": 75,
            "severity_reason": "Network port scanning or unauthorized reconnaissance detected"
        }

    # Malware or Trojan detection (threat detected without confirmed system compromise)
    if any(k in corpus for k in [
        "malware", "trojan", "virus detected", "suspicious payload", "malicious file",
        "file execution blocked", "quarantined", "backdoor", "rootkit", "apt threat"
    ]):
        return {
            "severity_level": "HIGH",
            "severity_score": 80,
            "severity_reason": "Malware, Trojan, or suspicious threat detected without confirmed system compromise"
        }

    # Suspicious administrative activity
    if any(k in corpus for k in [
        "suspicious admin", "unauthorized user created", "shadow admin",
        "disabled security service", "antivirus disabled", "firewall disabled",
        "security service stopped"
    ]):
        return {
            "severity_level": "HIGH",
            "severity_score": 80,
            "severity_reason": "Suspicious administrative modification or security service tampering"
        }

    # Unauthorized access attempt / Blacklisted IP / Firewall blocked suspicious connection
    if any(k in corpus for k in [
        "unauthorized access attempt", "access denied to sensitive",
        "firewall blocked suspicious", "threat blocked", "intrusion attempt blocked",
        "blacklisted ip", "rejected from blacklisted ip", "unauthorized access to critical"
    ]):
        return {
            "severity_level": "HIGH",
            "severity_score": 75,
            "severity_reason": "Unauthorized access attempt or perimeter firewall blocked suspicious connection"
        }

    # Source severity 7 or 8 with security indicators
    if src_sev is not None and 7 <= src_sev <= 8:
        return {
            "severity_level": "HIGH",
            "severity_score": 75,
            "severity_reason": "High-priority security alert reported by source device"
        }

    # =========================================================================
    # 3. MEDIUM RULES (Score 40 - 69)
    # =========================================================================

    # Unusual login
    if any(k in corpus for k in [
        "unusual login", "anomalous login", "login from new country",
        "login off-hours", "impossible travel", "unexpected geo-location"
    ]):
        return {
            "severity_level": "MEDIUM",
            "severity_score": 60,
            "severity_reason": "Unusual login context or anomalous user access pattern"
        }

    # Policy violation
    if any(k in corpus for k in [
        "policy violation", "policy_violation", "usb storage blocked",
        "unauthorized application", "dlp policy breach", "restricted software execution",
        "connection dropped by security policy", "policy rule"
    ]):
        return {
            "severity_level": "MEDIUM",
            "severity_score": 55,
            "severity_reason": "Security policy violation or restricted asset usage detected"
        }

    # Authentication failure (single failure)
    if any(k in corpus for k in [
        "authentication failure", "authentication_failure", "authentication failed",
        "login failed", "login failure", "bad password", "invalid credentials",
        "failed login", "auth failure", "failed password", "action=login_failed"
    ]):
        return {
            "severity_level": "MEDIUM",
            "severity_score": 50,
            "severity_reason": "User authentication failure or invalid login credentials"
        }

    # Blocked connection / Perimeter drop
    if any(k in corpus for k in [
        "connection blocked", "traffic dropped", "firewall drop", "connection dropped",
        "packet dropped", "connection reset by firewall", "action=blocked",
        "action=drop", "action=deny", "act=drop", "act=deny", "action=block"
    ]):
        return {
            "severity_level": "MEDIUM",
            "severity_score": 45,
            "severity_reason": "Perimeter connection blocked or firewall access denied"
        }

    # Suspicious but inconclusive activity
    if any(k in corpus for k in [
        "suspicious activity", "anomalous traffic", "unusual request",
        "inconclusive activity", "suspicious request"
    ]):
        return {
            "severity_level": "MEDIUM",
            "severity_score": 50,
            "severity_reason": "Suspicious or inconclusive system anomaly"
        }

    # Source severity 4-6 with security/warning context
    if src_sev is not None and 4 <= src_sev <= 6 and not is_explicit_clean:
        return {
            "severity_level": "MEDIUM",
            "severity_score": 50,
            "severity_reason": "Medium-level security event reported by source"
        }

    # =========================================================================
    # 4. LOW RULES (Score 15 - 39)
    # =========================================================================

    # Configuration change / Routine administrative activity
    if any(k in corpus for k in [
        "config change", "config_change", "configuration updated", "config update",
        "configuration update", "settings changed", "policy updated", "firewall rule added",
        "system configuration changed", "action=config_change", "session opened for user root",
        "routine configuration change", "normal administrative activity"
    ]):
        return {
            "severity_level": "LOW",
            "severity_score": 25,
            "severity_reason": "System configuration or administrative setting updated"
        }

    # Informational security event
    if any(k in corpus for k in [
        "security info", "certificate renewed", "ssl certificate renewed", "session expired",
        "mfa challenge issued", "password changed successfully", "token refreshed"
    ]):
        return {
            "severity_level": "LOW",
            "severity_score": 20,
            "severity_reason": "Informational security or identity lifecycle event"
        }

    # Normal logout / Session end
    if any(k in corpus for k in [
        "user logout", "session terminated", "logout successful",
        "session closed", "action=logout"
    ]):
        return {
            "severity_level": "LOW",
            "severity_score": 15,
            "severity_reason": "Standard user logout or session termination"
        }

    # Routine system activity with minor concern
    if any(k in corpus for k in [
        "disk usage warning", "deprecated api", "minor concern",
        "resource threshold warning", "slow query", "retry attempt"
    ]):
        return {
            "severity_level": "LOW",
            "severity_score": 30,
            "severity_reason": "Routine operational event with minor warning or advisory"
        }

    # Source severity 1-3 when not explicitly clean
    if src_sev is not None and 1 <= src_sev <= 3 and not is_explicit_clean:
        return {
            "severity_level": "LOW",
            "severity_score": 20,
            "severity_reason": "Low-priority informational event from source"
        }

    # =========================================================================
    # 5. CLEAN / NORMAL RULES (Score 0 - 14)
    # =========================================================================

    # Health check / Heartbeat
    if any(k in corpus for k in [
        "health check", "heartbeat", "keepalive", "ping successful",
        "service healthy", "status=ok", "healthcheck", "action=health_check",
        "action=heartbeat"
    ]):
        return {
            "severity_level": "CLEAN",
            "severity_score": 0,
            "severity_reason": "Routine service health check or heartbeat"
        }

    # Successful normal login
    if any(k in corpus for k in [
        "user login successful", "successful login", "authenticated successfully",
        "login success", "login successful", "action=login"
    ]) and not any(k in corpus for k in ["failed", "failure", "unauthorized", "compromise", "brute"]):
        return {
            "severity_level": "CLEAN",
            "severity_score": 5,
            "severity_reason": "Successful standard user authentication"
        }

    # Normal network connection
    if any(k in corpus for k in [
        "connection established", "tcp handshake completed", "dns query successful",
        "http 200", "allowed traffic", "action=allow", "action=permit", "allowed session",
        "allowed connection", "act=allow", "act=permit"
    ]):
        return {
            "severity_level": "CLEAN",
            "severity_score": 5,
            "severity_reason": "Normal allowed network connection"
        }

    # Routine service activity
    if any(k in corpus for k in [
        "service started", "service stopped", "daemon active",
        "cron executed", "backup completed", "log rotated", "task completed"
    ]):
        return {
            "severity_level": "CLEAN",
            "severity_score": 5,
            "severity_reason": "Routine background service execution"
        }

    # Default fallback: Clean operational event
    return {
        "severity_level": "CLEAN",
        "severity_score": 5,
        "severity_reason": "Routine operational log with normal status"
    }
