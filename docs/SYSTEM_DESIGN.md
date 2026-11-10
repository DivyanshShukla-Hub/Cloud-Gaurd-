# System Design — CloudGuard Architecture & Specifications

CloudGuard is a Cloud Security Misconfiguration Checker engineered to evaluate Infrastructure as Code (IaC) templates and Azure resource configurations against CIS Azure Security Benchmark controls.

---

## 1. System Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                                  CLIENT TIER                                      |
|   Web Browser (Chrome, Edge, Firefox) -- HTML5, CSS3, JavaScript, Chart.js CDN   |
+-----------------------------------------------------------------------------------+
                                        |  HTTPS / REST (JSON & Multi-part)
                                        v
+-----------------------------------------------------------------------------------+
|                              APPLICATION TIER (Flask)                             |
|                                                                                   |
|  +-------------------+  +-------------------+  +-------------------------------+  |
|  |   routes/auth.py  |  |  routes/scans.py  |  |       routes/admin.py         |  |
|  |  Login / Register |  | Upload & Results  |  | User / Rule / Audit Mgmt     |  |
|  +-------------------+  +-------------------+  +-------------------------------+  |
|                                       |                                           |
|              +------------------------+-----------------------+                   |
|              v                                                v                   |
|  +------------------------+                      +--------------------------+     |
|  |   services/parser.py   |                      | services/rule_engine.py  |     |
|  | Safe JSON/YAML Parsing |                      |  15 CIS Security Rules   |     |
|  +------------------------+                      +--------------------------+     |
+-----------------------------------------------------------------------------------+
                                        |
                   +--------------------+--------------------+
                   |                                         |
                   v                                         v
+-------------------------------------+   +-------------------------------------+
|        DATA TIER (Local Dev)        |   |       AZURE CLOUD TIER (Prod)       |
|  SQLite 3 (cloudguard.db)           |   |  Azure App Service (PaaS Linux)     |
|  - 6 Normalized 3NF Tables          |   |  Azure SQL Database (PaaS Managed)  |
|  - open_critical_findings View      |   |  Azure Blob Storage (Config Archive)|
|  - Compound Indexes                 |   |  Power BI Embedded (Analytics)      |
+-------------------------------------+   +-------------------------------------+
```

---

## 2. API Design & Endpoints

| Endpoint | HTTP Method | Auth Required | Description |
| :--- | :---: | :---: | :--- |
| `/login` | `GET`, `POST` | Public | Authenticates user credentials via bcrypt; creates session. |
| `/register` | `GET`, `POST` | Public | Registers a new user account with default `viewer` role. |
| `/logout` | `GET` | Session | Invalidates session and logs audit event. |
| `/dashboard` | `GET` | `login_required` | Fetches aggregated summary stats & recent 5 scans. |
| `/upload` | `GET`, `POST` | `login_required` | Validates file (max 1MB, JSON/YAML), runs 15 rules, creates scan record. |
| `/scan/results/<scan_id>`| `GET` | `login_required` | Returns categorized findings and remediation guide for scan. |
| `/scan/history` | `GET` | `login_required` | Retrieves chronological history of all scans by the user. |
| `/analytics` | `GET` | `login_required` | Aggregates 30-day critical trends and top violated rules. |
| `/admin/users` | `GET` | `admin_required` | Lists all registered users and status. |
| `/admin/users/<id>/role` | `POST` | `admin_required` | Updates user role (RBAC: `admin`, `analyst`, `viewer`). |
| `/admin/users/<id>/toggle-status`| `POST` | `admin_required` | Deactivates or reactivates user account. |
| `/admin/rules` | `GET` | `admin_required` | Lists all 15 rules and active state. |
| `/admin/rules/<id>/toggle` | `POST` | `admin_required` | Toggles security rule activation in scanner. |
| `/admin/audit` | `GET` | `admin_required` | Displays immutable security audit trail. |

---

## 3. Architecture Trade-offs & Decisions

1. **Client-Side vs. Server-Side Rule Evaluation**:
   * *Decision*: Server-side evaluation in Python Flask.
   * *Trade-off*: Adds minimal compute to the Flask backend, but protects proprietary rule logic, guarantees atomic database transaction logging, and prevents tampering with findings.

2. **Synchronous vs. Asynchronous Scan Pipeline**:
   * *Decision*: Synchronous evaluation for files &le; 1MB.
   * *Trade-off*: A 1MB JSON/YAML file takes under 15ms to evaluate against 15 rules in Python memory. Synchronous handling avoids Celery/Redis overhead for the college project while providing sub-second page redirects.

3. **Database Choice (SQLite for Dev &rarr; Azure SQL for Prod)**:
   * *Decision*: Strict ANSI-SQL / T-SQL compatible schema.
   * *Trade-off*: Allows instant zero-configuration local runs while enabling seamless migration to Azure SQL Database without modifying queries.