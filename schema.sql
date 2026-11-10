-- CloudGuard Database Schema (3NF, Azure SQL Compatible)
CREATE TABLE IF NOT EXISTS rule_categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    fix_guidance TEXT,
    is_active INTEGER DEFAULT 1,
    category_id INTEGER REFERENCES rule_categories(category_id)
);

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id),
    filename TEXT NOT NULL,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    risk_score TEXT,
    status TEXT DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(scan_id),
    rule_id INTEGER REFERENCES rules(rule_id),
    severity TEXT,
    detail TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id),
    action TEXT,
    target TEXT,
    performed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

CREATE VIEW IF NOT EXISTS open_critical_findings AS
SELECT f.finding_id, s.filename, r.rule_name, r.fix_guidance,
       f.detail, s.scanned_at, u.email
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
JOIN rules r ON f.rule_id = r.rule_id
JOIN users u ON s.user_id = u.user_id
WHERE f.severity = 'Critical';
