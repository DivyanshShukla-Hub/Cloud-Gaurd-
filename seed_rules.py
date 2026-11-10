import sqlite3
from flask_bcrypt import Bcrypt

def seed_database(db_path="cloudguard.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Rule categories
    categories = [
        (1, "Storage Security"),
        (2, "Database Security"),
        (3, "Network & Access"),
        (4, "Encryption & TLS"),
        (5, "Identity & Access Management"),
        (6, "Governance & Resource Management"),
        (7, "Monitoring & Logging"),
        (8, "Resilience & Backup"),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO rule_categories (category_id, category_name) VALUES (?, ?)",
        categories,
    )

    # 15 Security Rules
    rules_data = [
        (
            1, "Public Blob Access",
            "Azure storage allows anonymous read access to blobs and containers.",
            "Critical",
            "Set allowBlobPublicAccess to false in your storage configuration.",
            1, 1
        ),
        (
            2, "HTTPS Not Enforced",
            "Storage account permits unencrypted HTTP traffic.",
            "Critical",
            "Set supportsHttpsTrafficOnly to true to enforce encrypted connections.",
            1, 1
        ),
        (
            3, "No Database Firewall",
            "SQL Server has no firewall rules restricting public IP access.",
            "Critical",
            "Add at least one firewall rule to restrict database access by IP.",
            1, 2
        ),
        (
            4, "Weak TLS Version",
            "TLS version configured is lower than the mandatory TLS 1.2 baseline.",
            "High",
            "Set minimumTlsVersion to 1.2 or higher.",
            1, 4
        ),
        (
            5, "Encryption at Rest Disabled",
            "Storage service-side encryption at rest is disabled.",
            "High",
            "Enable encryption at rest for all storage resources.",
            1, 1
        ),
        (
            6, "Open Network Access",
            "Network default action is set to Allow instead of Deny.",
            "High",
            "Set network defaultAction to Deny and whitelist specific IPs.",
            1, 3
        ),
        (
            7, "Overly Broad Admin Access",
            "RBAC administrator role is scoped at the entire subscription level.",
            "High",
            "Restrict admin role scope to resource group level, not subscription.",
            1, 5
        ),
        (
            8, "Audit Logging Disabled",
            "Diagnostic audit logging is disabled for resources.",
            "Medium",
            "Enable diagnostic audit logging for all resources.",
            1, 7
        ),
        (
            9, "MFA Not Required",
            "Multi-factor authentication is disabled for cloud identities.",
            "Medium",
            "Enable multi-factor authentication for all user accounts.",
            1, 5
        ),
        (
            10, "Secrets in Config File",
            "Plaintext credentials, secrets, or keys found in config file.",
            "Medium",
            "Remove all secrets from config files. Use Azure Key Vault or environment variables.",
            1, 6
        ),
        (
            11, "No Resource Lock",
            "Resource has no CanNotDelete management lock to prevent accidental deletion.",
            "Medium",
            "Add a resource lock to prevent accidental deletion or modification.",
            1, 6
        ),
        (
            12, "No Resource Tags",
            "Resource lacks mandatory metadata tags for cost and owner tracking.",
            "Low",
            "Add tags like env, owner, and project to all resources for better management.",
            1, 6
        ),
        (
            13, "Permissive CORS Policy",
            "Cross-origin resource sharing allows wildcard (*) origins.",
            "High",
            "Replace wildcard CORS with specific allowed origin URLs.",
            1, 3
        ),
        (
            14, "No Backup Policy",
            "Automated backups are disabled or not configured.",
            "Medium",
            "Enable automated backup for all databases and storage resources.",
            1, 8
        ),
        (
            15, "No Activity Alerts",
            "Activity log alerts for critical operational changes are disabled.",
            "Low",
            "Configure activity log alerts for critical operations and security events.",
            1, 7
        ),
    ]

    for r in rules_data:
        cursor.execute(
            """INSERT OR REPLACE INTO rules
               (rule_id, rule_name, description, severity, fix_guidance, is_active, category_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            r,
        )

    # Check if default admin exists before generating bcrypt hash (saves startup time)
    cursor.execute("SELECT user_id FROM users WHERE email = 'admin@cloudguard.com'")
    if not cursor.fetchone():
        bcrypt = Bcrypt()
        pw_hash = bcrypt.generate_password_hash("Admin@123").decode("utf-8")
        cursor.execute(
            """INSERT INTO users (email, password_hash, role, is_active)
               VALUES (?, ?, ?, ?)""",
            ("admin@cloudguard.com", pw_hash, "admin", 1),
        )

    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_database()