# RDBMS — Database Architecture, 3NF Normalization & Optimizations

This document details the relational database design implemented for CloudGuard, proving compliance with college RDBMS curriculum guidelines.

---

## 1. 3rd Normal Form (3NF) Normalization Proof

The database contains 6 relational tables designed in strict 3rd Normal Form:

### 1NF (Atomic Attributes, Unique Keys)
* Every column holds atomic, indivisible values (no comma-separated lists or nested arrays).
* Primary keys are explicitly defined for every table (`user_id`, `scan_id`, `rule_id`, `category_id`, `finding_id`, `log_id`).

### 2NF (No Partial Key Dependencies)
* All non-key attributes are fully functionally dependent on the entire primary key (all tables use single-attribute surrogate keys).

### 3NF (No Transitive Dependencies)
* To eliminate transitive dependencies ($A \rightarrow B \rightarrow C$), rule categories were separated into `rule_categories`:
  * *Un-normalized anti-pattern*: `rules(rule_id, rule_name, category_name)` &rarr; `rule_id` determines `category_name`, creating update and insertion anomalies.
  * *3NF Solution*: `rules` stores foreign key `category_id` referencing `rule_categories(category_id)`.
* `findings` stores only `scan_id` and `rule_id`, fetching rule descriptions and remediation guidance via relational joins.

---

## 2. Entity-Relationship Model

```
+--------------------+        +---------------+        +----------------------+
|  rule_categories   | 1    N |     rules     | 1    N |       findings       |
|--------------------|<-------|---------------|<-------|----------------------|
| PK  category_id    |        | PK  rule_id   |        | PK  finding_id       |
|     category_name  |        |     rule_name |        | FK  scan_id          |
+--------------------+        |     severity  |        | FK  rule_id          |
                              |     fix_guid  |        |     severity         |
                              |     is_active |        |     detail           |
                              | FK  category_i|        |     created_at       |
                              +---------------+        +----------------------+
                                                                  | N
                                                                  |
+--------------------+        +---------------+                   | 1
|       users        | 1    N |     scans     |                   |
|--------------------|<-------|---------------|<------------------+
| PK  user_id        |        | PK  scan_id   |
|     email          |        | FK  user_id   |
|     password_hash  |        |     filename  |
|     role           |        |     risk_score|
|     created_at     |        |     crit_count|
|     is_active      |        |     total_find|
+--------------------+        |     status    |
         | 1                  +---------------+
         |
         | N
         v
+--------------------+
|     audit_log      |
|--------------------|
| PK  log_id         |
| FK  user_id        |
|     action         |
|     target         |
|     performed_at   |
+--------------------+
```

---

## 3. Database View: `open_critical_findings`

Created in [`schema.sql`](file:///c:/Users/divya/OneDrive/Documents/Cloud%20gaurd/schema.sql):

```sql
CREATE VIEW open_critical_findings AS
SELECT f.finding_id, s.filename, r.rule_name, r.fix_guidance,
       f.detail, s.scanned_at, u.email
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
JOIN rules r ON f.rule_id = r.rule_id
JOIN users u ON s.user_id = u.user_id
WHERE f.severity = 'Critical';
```

---

## 4. Query Optimization & Indexes

Four non-clustered composite indexes optimize read queries:
1. `idx_scans_user ON scans(user_id)` &rarr; Accelerates dashboard and user history queries.
2. `idx_findings_scan ON findings(scan_id)` &rarr; Accelerates scan findings retrieval by foreign key.
3. `idx_findings_severity ON findings(severity)` &rarr; Optimizes critical finding aggregates and analytics charts.
4. `idx_audit_user ON audit_log(user_id)` &rarr; Optimizes chronological audit trail filtering.

---

## 5. ACID Transaction Implementation

In [`routes/scans.py`](file:///c:/Users/divya/OneDrive/Documents/Cloud%20gaurd/routes/scans.py), scan record creation and findings insertions are encapsulated in an atomic transaction:

```python
cursor = db.cursor()
try:
    cursor.execute("INSERT INTO scans (...) VALUES (...)")
    scan_id = cursor.lastrowid
    for fd in findings:
        cursor.execute("INSERT INTO findings (...) VALUES (...)")
    db.commit() # Atomic Commit
except Exception as e:
    db.rollback() # Rollback on partial failure to prevent orphaned findings
```