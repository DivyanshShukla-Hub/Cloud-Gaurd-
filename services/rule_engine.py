def _section(config, key):
    """Safely return a nested dict section from config, avoiding AttributeError on null/non-dict."""
    val = config.get(key)
    return val if isinstance(val, dict) else {}


def _is_weak_tls(tls_cfg):
    """Return (is_weak, display_ver) checking whether TLS version is below 1.2."""
    if "minimumVersion" not in tls_cfg:
        return False, "1.2"
    raw_ver = tls_cfg.get("minimumVersion")
    if raw_ver is None or str(raw_ver).strip() == "":
        return True, "unset"
    tls_str = str(raw_ver).strip()
    try:
        parts = tuple(int(p) for p in tls_str.split("."))
        return parts < (1, 2), tls_str
    except ValueError:
        return tls_str < "1.2", tls_str


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

    def add_finding(rule_id, default_severity, detail):
        sev = rules_map[rule_id]["severity"] or default_severity
        findings.append({
            "rule_id": rule_id,
            "severity": sev,
            "detail": detail,
        })

    storage = _section(config, "storage")
    sql_cfg = _section(config, "sql")
    tls_cfg = _section(config, "tls")
    network = _section(config, "network")
    rbac = _section(config, "rbac")
    diagnostics = _section(config, "diagnostics")
    identity = _section(config, "identity")
    resource = _section(config, "resource")
    cors = _section(config, "cors")
    backup = _section(config, "backup")
    alerts = _section(config, "alerts")

    # --- Rule 1: Public Blob Access (Critical) ---
    if 1 in rules_map and storage.get("allowBlobPublicAccess") is True:
        add_finding(
            1, "Critical",
            "storage.allowBlobPublicAccess is set to true. Blobs are publicly accessible.",
        )

    # --- Rule 2: HTTPS Not Enforced (Critical) ---
    if 2 in rules_map and storage.get("supportsHttpsTrafficOnly") is False:
        add_finding(
            2, "Critical",
            "storage.supportsHttpsTrafficOnly is false. Unencrypted HTTP traffic is allowed.",
        )

    # --- Rule 3: No Database Firewall (Critical) ---
    if 3 in rules_map:
        fw = sql_cfg.get("firewallRules")
        if fw is None or fw == []:
            add_finding(
                3, "Critical",
                "sql.firewallRules is empty or missing. Database has no firewall protection.",
            )

    # --- Rule 4: Weak TLS Version (High) ---
    if 4 in rules_map:
        weak_tls, tls_ver = _is_weak_tls(tls_cfg)
        if weak_tls:
            add_finding(
                4, "High",
                f"tls.minimumVersion is {tls_ver}, which is below the required 1.2.",
            )

    # --- Rule 5: Encryption at Rest Disabled (High) ---
    if 5 in rules_map and storage.get("encryption") is False:
        add_finding(
            5, "High",
            "storage.encryption is false. Data at rest is not encrypted.",
        )

    # --- Rule 6: Open Network Access (High) ---
    if 6 in rules_map and str(network.get("defaultAction", "")).strip().lower() == "allow":
        add_finding(
            6, "High",
            "network.defaultAction is Allow. All inbound traffic is permitted by default.",
        )

    # --- Rule 7: Overly Broad Admin Access (High) ---
    if 7 in rules_map and str(rbac.get("adminScope", "")).strip().lower() == "subscription":
        add_finding(
            7, "High",
            "rbac.adminScope is subscription. Admin privileges are too broadly scoped.",
        )

    # --- Rule 8: Audit Logging Disabled (Medium) ---
    if 8 in rules_map and diagnostics.get("auditLog") is False:
        add_finding(
            8, "Medium",
            "diagnostics.auditLog is false. Audit events are not being recorded.",
        )

    # --- Rule 9: MFA Not Required (Medium) ---
    if 9 in rules_map and identity.get("mfaEnabled") is False:
        add_finding(
            9, "Medium",
            "identity.mfaEnabled is false. Multi-factor authentication is not enforced.",
        )

    # --- Rule 10: Secrets in Config File (Medium) ---
    if 10 in rules_map:
        raw = str(config_dict).lower()
        keywords = ["password=", "secret=", "apikey=", "connectionstring="]
        if any(k in raw for k in keywords):
            add_finding(
                10, "Medium",
                "Plaintext secrets detected in configuration (password=, secret=, apikey=, or connectionstring=).",
            )

    # --- Rule 11: No Resource Lock (Medium) ---
    if 11 in rules_map:
        lock_val = resource.get("lock")
        if lock_val is False or lock_val is None:
            add_finding(
                11, "Medium",
                "resource.lock is false or missing. Resources can be accidentally deleted.",
            )

    # --- Rule 12: No Resource Tags (Low) ---
    if 12 in rules_map:
        tags = resource.get("tags")
        if tags in [None, {}, ""]:
            add_finding(
                12, "Low",
                "resource.tags is empty or missing. No governance tags assigned.",
            )

    # --- Rule 13: Permissive CORS Policy (High) ---
    if 13 in rules_map:
        origins = cors.get("allowedOrigins")
        if origins == "*" or (isinstance(origins, list) and "*" in origins):
            add_finding(
                13, "High",
                "cors.allowedOrigins is wildcard (*). Any domain can make cross-origin requests.",
            )

    # --- Rule 14: No Backup Policy (Medium) ---
    if 14 in rules_map:
        backup_val = backup.get("enabled")
        if backup_val is False or backup_val is None:
            add_finding(
                14, "Medium",
                "backup.enabled is false or missing. No automated backup policy configured.",
            )

    # --- Rule 15: No Activity Alerts (Low) ---
    if 15 in rules_map:
        alert_val = alerts.get("activityLog")
        if alert_val is False or alert_val is None:
            add_finding(
                15, "Low",
                "alerts.activityLog is false or missing. No activity log alerts configured.",
            )

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
