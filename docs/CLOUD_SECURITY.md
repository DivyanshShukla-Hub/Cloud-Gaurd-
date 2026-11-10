# Cloud Security — Defense-in-Depth, RBAC & Hardening Guide

CloudGuard enforces defense-in-depth security principles across transport, authentication, authorization, and storage tiers.

---

## 1. Role-Based Access Control (RBAC) Matrix

| Action / Capability | Viewer | Analyst | Admin |
| :--- | :---: | :---: | :---: |
| Access Dashboard (`/dashboard`) | Yes | Yes | Yes |
| Upload & Run New Scans (`/upload`) | Yes | Yes | Yes |
| View Own Scan Findings (`/scan/results/<id>`) | Yes | Yes | Yes |
| View All Historical Scans (`/scan/history`) | Yes | Yes | Yes |
| Access Analytics Dashboard (`/analytics`) | Yes | Yes | Yes |
| View Other Users' Scans | No | No | Yes |
| User Account Management (`/admin/users`) | No | No | Yes |
| Modify User Roles (`/admin/users/<id>/role`) | No | No | Yes |
| Deactivate / Reactivate Users | No | No | Yes |
| Toggle Security Rules (`/admin/rules`) | No | No | Yes |
| Access Audit Trail (`/admin/audit`) | No | No | Yes |

---

## 2. Cryptographic Security & Password Hashing

* **Algorithm**: `bcrypt` via `flask-bcrypt`.
* **Salting**: Automatic per-user random cryptographic salt prevents rainbow table attacks.
* **Work Factor**: Default log rounds (12) balances security with evaluation time.
* **Storage**: Only the 60-character bcrypt hash is persisted in the database; plaintext passwords never touch database logs or disk.

---

## 3. Defense-in-Depth Controls

1. **Denial-of-Service (DoS) Upload Mitigation**:
   * File uploads are strictly constrained to 1MB (`MAX_CONTENT_LENGTH = 1 * 1024 * 1024`).
   * Double validation: Client-side JavaScript size guard + server-side Flask middleware.
2. **File Extension Whitelisting**:
   * Only `.json`, `.yaml`, and `.yml` are accepted.
   * `werkzeug.utils.secure_filename` prevents directory traversal attacks (`../../etc/passwd`).
3. **SQL Injection Prevention**:
   * All database queries utilize parameterized queries (`?` place-holders in SQLite, `@params` in T-SQL).
   * No raw string formatting or dynamic SQL concatenations.
4. **Immutable Security Audit Log**:
   * Every security-critical action (`LOGIN`, `LOGOUT`, `FILE_UPLOAD`, `SCAN_COMPLETED`, `CHANGE_ROLE`, `USER_STATUS_CHANGE`, `RULE_TOGGLE`) is appended to `audit_log`.