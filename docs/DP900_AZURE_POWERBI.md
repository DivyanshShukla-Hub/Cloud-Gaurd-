# DP-900 — Azure Data Fundamentals & Power BI Architecture

This document outlines how CloudGuard aligns with Microsoft DP-900 (Azure Data Fundamentals) core pillars: Structured Data, Unstructured Storage, and Business Intelligence Analytics.

---

## 1. Structured Data: Azure SQL Database

* **Role**: Stores normalized application entities (`users`, `rules`, `rule_categories`, `scans`, `findings`, `audit_log`).
* **Service Tier**: General Purpose (Serverless or Provisioned vCore), supporting auto-pause during non-business college demo hours.
* **Firewall Security**: Configure server-level firewall rules rejecting `0.0.0.0/0` and whitelisting only the Azure App Service outbound IP addresses and university lab CIDR ranges.
* **Encryption**: Transparent Data Encryption (TDE) enabled by default (AES-256) protects data at rest.

---

## 2. Semi-Structured & Unstructured Data: Azure Blob Storage

* **Role**: Archives uploaded raw `.json` and `.yaml` cloud configurations.
* **Storage Account Tier**: Standard General-purpose v2, Hot Access Tier for recent scans, auto-lifecycle rule transitioning scans older than 90 days to Cool/Archive Tier.
* **Security Controls**:
  * `allowBlobPublicAccess = false` (Satisfies CloudGuard Rule #1).
  * `supportsHttpsTrafficOnly = true` (Satisfies CloudGuard Rule #2).
  * Storage Service Encryption (SSE) with Microsoft-managed keys (Satisfies CloudGuard Rule #5).

---

## 3. Power BI Analytics Integration

### How to Connect Power BI Desktop to CloudGuard:
1. Open **Power BI Desktop** &rarr; Select **Get Data** &rarr; **Azure SQL Database**.
2. Enter server hostname: `<your-server>.database.windows.net`, Database: `CloudGuardDB`.
3. Choose **DirectQuery** mode to ensure visualizations update automatically when new scans are conducted.
4. Select the view: `dbo.open_critical_findings` and table: `dbo.scans`.
5. Visualizations to create in Power BI:
   * **Gauge Visual**: Overall Security Posture score ($100 - \text{Risk Index}$).
   * **Donut Chart**: Findings by Severity (`Critical`, `High`, `Medium`, `Low`).
   * **Decomposition Tree**: Drill-down from `Severity` &rarr; `Rule Category` &rarr; `Rule Name`.
   * **Matrix Grid**: Remediation checklist showing `rule_name`, `detail`, `fix_guidance`.