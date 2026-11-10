# CloudGuard — Cloud Misconfiguration Checker

CloudGuard is a full-stack cybersecurity web application designed to evaluate cloud infrastructure configurations (JSON and YAML) against 15 CIS-aligned security rules. Built as a college capstone project, it demonstrates principles across **System Design**, **RDBMS (3NF & Views)**, **DP-900 (Azure SQL, Blob Storage & Power BI)**, and **Cloud Security (RBAC & bcrypt)**.

---

## 🎓 Academic Curriculum Coverage

| Subject | Implementation in CloudGuard |
| :--- | :--- |
| **1. System Design** | Decoupled client-server architecture, modular Flask blueprints (`auth`, `scans`, `analytics`, `admin`), safe parsing pipeline, and trade-off analysis. Detailed in [`docs/SYSTEM_DESIGN.md`](docs/SYSTEM_DESIGN.md). |
| **2. RDBMS** | **6 Tables in 3NF**: `rule_categories`, `rules`, `users`, `scans`, `findings`, `audit_log`. Includes compound indexes, multi-table ACID transactions, and the `open_critical_findings` view. Full normalization proof in [`docs/RDBMS.md`](docs/RDBMS.md). |
| **3. DP-900** | Relational structured metadata in SQL; raw IaC file storage in Blob Storage; DirectQuery-ready `open_critical_findings` view for Power BI dashboards. Guide in [`docs/DP900_AZURE_POWERBI.md`](docs/DP900_AZURE_POWERBI.md). |
| **4. Cloud Security** | Role-Based Access Control (**RBAC**: `admin`, `analyst`, `viewer`), salted password hashing via `bcrypt`, `@login_required` / `@admin_required` route protection, 1MB upload limit, input whitelisting, and immutable audit logging. Documented in [`docs/CLOUD_SECURITY.md`](docs/CLOUD_SECURITY.md). |

---

## ⚡ Quick Start

### 1. Requirements & Dependencies
Ensure Python 3.10+ is installed:
```bash
pip install -r requirements.txt
```

### 2. Launch the Application
```bash
python app.py
```
Open **[http://localhost:5000](http://localhost:5000)** (or **[http://127.0.0.1:5000](http://127.0.0.1:5000)**) in your browser.

### 3. Default Admin Credentials
* **Email**: `admin@cloudguard.com`
* **Password**: `Admin@123`

*(You can also create a new account with the default `viewer` role from the `/register` page!)*

### 4. Interactive Terminal Demo
For college lab presentations and viva evaluations:
```bash
python demo.py
```

---

## 🛡️ The 15 Security Rules & Scoring Logic

| # | Rule Name | Severity | Condition Audited | Fix Recommendation |
| :-: | :--- | :-: | :--- | :--- |
| **1** | **Public Blob Access** | `Critical` | `storage.allowBlobPublicAccess == True` | Set `allowBlobPublicAccess` to false. |
| **2** | **HTTPS Not Enforced** | `Critical` | `storage.supportsHttpsTrafficOnly == False` | Set `supportsHttpsTrafficOnly` to true. |
| **3** | **No Database Firewall** | `Critical` | `sql.firewallRules in [None, []]` | Add at least one restrictive IP firewall rule. |
| **4** | **Weak TLS Version** | `High` | `tls.minimumVersion < "1.2"` | Require TLS 1.2 or 1.3 across all endpoints. |
| **5** | **Encryption at Rest Disabled** | `High` | `storage.encryption == False` | Enable encryption at rest for all storage resources. |
| **6** | **Open Network Access** | `High` | `network.defaultAction == "Allow"` | Set network defaultAction to Deny and whitelist specific IPs. |
| **7** | **Overly Broad Admin Access** | `High` | `rbac.adminScope == "subscription"` | Restrict admin role scope to resource group level. |
| **8** | **Audit Logging Disabled** | `Medium` | `diagnostics.auditLog == False` | Enable diagnostic audit logging for all resources. |
| **9** | **MFA Not Required** | `Medium` | `identity.mfaEnabled == False` | Enable multi-factor authentication for all user accounts. |
| **10** | **Secrets in Config File** | `Medium` | Keywords like `password=`, `secret=`, `apikey=` | Remove secrets; reference them securely in Azure Key Vault. |
| **11** | **No Resource Lock** | `Medium` | `resource.lock in [False, None]` | Add a resource lock to prevent accidental deletion. |
| **12** | **No Resource Tags** | `Low` | `resource.tags in [None, {}, ""]` | Add governance tags (env, owner, project). |
| **13** | **Permissive CORS Policy** | `High` | `cors.allowedOrigins == "*"` | Replace wildcard CORS with specific allowed origin URLs. |
| **14** | **No Backup Policy** | `Medium` | `backup.enabled in [False, None]` | Enable automated backup for all databases & storage. |
| **15** | **No Activity Alerts**| `Low` | `alerts.activityLog in [False, None]` | Configure activity log alerts for critical operations. |

### Overall Risk Score Hierarchy
* If any **Critical** finding &rarr; Risk Score: **`Critical`** (Red)
* Else if any **High** finding &rarr; Risk Score: **`High`** (Orange)
* Else if any **Medium** finding &rarr; Risk Score: **`Medium`** (Yellow)
* Else if any **Low** finding &rarr; Risk Score: **`Low`** (Green)
* Else &rarr; Risk Score: **`Clean`** (Green)

---

## 🧪 Included Test Samples

* [`sample_bad.json`](sample_bad.json) / [`sample_bad.yaml`](sample_bad.yaml) &rarr; Triggers 13 misconfigurations (**Critical** Risk Score).
* [`sample_good.json`](sample_good.json) / [`sample_good.yaml`](sample_good.yaml) &rarr; Zero misconfigurations (**Clean** 100% compliant).

---

## 📁 Repository Structure

```
Cloud guard/
├── app.py                      # Flask entrypoint with dual-stack loopback binding
├── config.py                   # App settings (1MB upload limit, DB path, secret key)
├── requirements.txt            # Python dependencies
├── schema.sql                  # SQLite DDL with 6 tables in 3NF and open_critical_findings view
├── azure_sql_deploy.sql        # Azure SQL / T-SQL production deployment script
├── seed_rules.py               # Pre-populates 15 rules, 8 categories & admin user
├── demo.py                     # CLI demo simulation for college viva
├── sample_bad.json / .yaml     # Vulnerable test manifests
├── sample_good.json / .yaml    # Hardened compliant test manifests
├── models/
│   └── db.py                   # DB connection, close_db teardown, and audit logging
├── services/
│   ├── parser.py               # Safe JSON and YAML parser
│   └── rule_engine.py          # 15 Security Rules engine & risk scorer
├── routes/
│   ├── auth.py                 # /login, /register, /logout
│   ├── scans.py                # /dashboard, /upload, /scan/results/<id>, /scan/history
│   ├── analytics.py            # /analytics (Chart.js bar & line charts)
│   └── admin.py                # /admin/users, /admin/rules, /admin/audit
├── templates/
│   ├── base.html               # Responsive cybersecurity dark theme layout
│   ├── login.html              # Authentication view
│   ├── register.html           # Registration view
│   ├── dashboard.html          # Stat cards & recent scans
│   ├── upload.html             # Drag-and-drop file uploader
│   ├── results.html            # Findings report with severity badges & fix advice
│   ├── history.html            # Complete scan history
│   ├── analytics.html          # Interactive Chart.js graphs
│   └── admin/
│       ├── users.html          # RBAC user management
│       ├── rules.html          # Rule toggling interface
│       └── audit.html          # System audit trail
└── docs/                       # Academic subject documentation
    ├── SYSTEM_DESIGN.md        # System Design architecture & trade-offs
    ├── RDBMS.md                # 3NF normalization proof & ER diagram
    ├── DP900_AZURE_POWERBI.md  # Azure SQL, Blob Storage & Power BI setup
    └── CLOUD_SECURITY.md       # Threat modeling, RBAC & defense-in-depth
```