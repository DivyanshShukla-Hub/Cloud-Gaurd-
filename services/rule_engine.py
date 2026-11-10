def run_rules(config_dict, active_rules):
    """
    Run all 15 security rules against config_dict.
    active_rules: list of sqlite3.Row from rules table (rule_id, rule_name, severity, fix_guidance, is_active).
    Returns list of finding dicts: [{rule_id, severity, detail}, ...]
    """
    findings = []
    config = config_dict if isinstance(config_dict, dict) else {}

    # Build lookup of active rules by rule_id (integer PK)
    rules_map = {r["rule_id"]: r for r in active_rules}

    # --- Rule 1: Public Blob Access (Critical) ---
    if 1 in rules_map:
        if config.get("storage", {}).get("allowBlobPublicAccess") is True:
            findings.append({
                "rule_id": 1,
                "severity": "Critical",
                "detail": "storage.allowBlobPublicAccess is set to true. Blobs are publicly accessible."
            })

    # --- Rule 2: HTTPS Not Enforced (Critical) ---
    if 2 in rules_map:
        if config.get("storage", {}).get("supportsHttpsTrafficOnly") is False:
            findings.append({
                "rule_id": 2,
                "severity": "Critical",
                "detail": "storage.supportsHttpsTrafficOnly is false. Unencrypted HTTP traffic is allowed."
            })

    # --- Rule 3: No Database Firewall (Critical) ---
    if 3 in rules_map:
        fw = config.get("sql", {}).get("firewallRules")
        if fw is None or fw == []:
            findings.append({
                "rule_id": 3,
                "severity": "Critical",
                "detail": "sql.firewallRules is empty or missing. Database has no firewall protection."
            })

    # --- Rule 4: Weak TLS Version (High) ---
    if 4 in rules_map:
        tls_ver = str(config.get("tls", {}).get("minimumVersion", "1.2"))
        if tls_ver < "1.2":
            findings.append({
                "rule_id": 4,
                "severity": "High",
                "detail": f"tls.minimumVersion is {tls_ver}, which is below the required 1.2."
            })

    # --- Rule 5: Encryption at Rest Disabled (High) ---
    if 5 in rules_map:
        if config.get("storage", {}).get("encryption") is False:
            findings.append({
                "rule_id": 5,
                "severity": "High",
                "detail": "storage.encryption is false. Data at rest is not encrypted."
            })

    # --- Rule 6: Open Network Access (High) ---
    if 6 in rules_map:
        if config.get("network", {}).get("defaultAction") == "Allow":
            findings.append({
                "rule_id": 6,
                "severity": "High",
                "detail": "network.defaultAction is Allow. All inbound traffic is permitted by default."
            })

    # --- Rule 7: Overly Broad Admin Access (High) ---
    if 7 in rules_map:
        if str(config.get("rbac", {}).get("adminScope", "")).lower() == "subscription":
            findings.append({
                "rule_id": 7,
                "severity": "High",
                "detail": "rbac.adminScope is subscription. Admin privileges are too broadly scoped."
            })

    # --- Rule 8: Audit Logging Disabled (Medium) ---
    if 8 in rules_map:
        if config.get("diagnostics", {}).get("auditLog") is False:
            findings.append({
                "rule_id": 8,
                "severity": "Medium",
                "detail": "diagnostics.auditLog is false. Audit events are not being recorded."
            })

    # --- Rule 9: MFA Not Required (Medium) ---
    if 9 in rules_map:
        if config.get("identity", {}).get("mfaEnabled") is False:
            findings.append({
                "rule_id": 9,
                "severity": "Medium",
                "detail": "identity.mfaEnabled is false. Multi-factor authentication is not enforced."
            })

    # --- Rule 10: Secrets in Config File (Medium) ---
    if 10 in rules_map:
        raw = str(config_dict).lower()
        keywords = ["password=", "secret=", "apikey=", "connectionstring="]
        if any(k in raw for k in keywords):
            findings.append({
                "rule_id": 10,
                "severity": "Medium",
                "detail": "Plaintext secrets detected in configuration (password=, secret=, apikey=, or connectionstring=)."
            })

    # --- Rule 11: No Resource Lock (Medium) ---
    if 11 in rules_map:
        lock_val = config.get("resource", {}).get("lock")
        if lock_val is False or lock_val is None:
            findings.append({
                "rule_id": 11,
                "severity": "Medium",
                "detail": "resource.lock is false or missing. Resources can be accidentally deleted."
            })

    # --- Rule 12: No Resource Tags (Low) ---
    if 12 in rules_map:
        tags = config.get("resource", {}).get("tags")
        if tags in [None, {}, ""]:
            findings.append({
                "rule_id": 12,
                "severity": "Low",
                "detail": "resource.tags is empty or missing. No governance tags assigned."
            })

    # --- Rule 13: Permissive CORS Policy (High) ---
    if 13 in rules_map:
        if config.get("cors", {}).get("allowedOrigins") == "*":
            findings.append({
                "rule_id": 13,
                "severity": "High",
                "detail": "cors.allowedOrigins is wildcard (*). Any domain can make cross-origin requests."
            })

    # --- Rule 14: No Backup Policy (Medium) ---
    if 14 in rules_map:
        backup_val = config.get("backup", {}).get("enabled")
        if backup_val is False or backup_val is None:
            findings.append({
                "rule_id": 14,
                "severity": "Medium",
                "detail": "backup.enabled is false or missing. No automated backup policy configured."
            })

    # --- Rule 15: No Activity Alerts (Low) ---
    if 15 in rules_map:
        alert_val = config.get("alerts", {}).get("activityLog")
        if alert_val is False or alert_val is None:
            findings.append({
                "rule_id": 15,
                "severity": "Low",
                "detail": "alerts.activityLog is false or missing. No activity log alerts configured."
            })

    return findings


def compute_risk_score(findings):
    """Compute overall risk_score string from findings list."""
    severities = {f["severity"] for f in findings}
    if "Critical" in severities:
        return "Critical"
    elif "High" in severities:
        return "High"
    elif "Medium" in severities:
        return "Medium"
    elif "Low" in severities:
        return "Low"
    else:
        return "Clean"
