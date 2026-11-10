-- ============================================================================
-- CloudGuard: Azure SQL Database Deployment Script (T-SQL)
-- College Subject: RDBMS & DP-900
-- ============================================================================

-- 1. DROP EXISTING OBJECTS (For clean deployment)
IF OBJECT_ID('dbo.open_critical_findings', 'V') IS NOT NULL DROP VIEW dbo.open_critical_findings;
IF OBJECT_ID('dbo.sp_create_scan_with_findings', 'P') IS NOT NULL DROP PROCEDURE dbo.sp_create_scan_with_findings;
IF OBJECT_ID('dbo.findings', 'U') IS NOT NULL DROP TABLE dbo.findings;
IF OBJECT_ID('dbo.scans', 'U') IS NOT NULL DROP TABLE dbo.scans;
IF OBJECT_ID('dbo.audit_log', 'U') IS NOT NULL DROP TABLE dbo.audit_log;
IF OBJECT_ID('dbo.rules', 'U') IS NOT NULL DROP TABLE dbo.rules;
IF OBJECT_ID('dbo.rule_categories', 'U') IS NOT NULL DROP TABLE dbo.rule_categories;
IF OBJECT_ID('dbo.users', 'U') IS NOT NULL DROP TABLE dbo.users;

-- ============================================================================
-- 2. CREATE TABLES (3NF COMPLIANT)
-- ============================================================================

-- Table 1: rule_categories (Eliminates transitive dependencies in rules)
CREATE TABLE dbo.rule_categories (
    category_id INT IDENTITY(1,1) PRIMARY KEY,
    category_name NVARCHAR(100) NOT NULL UNIQUE
);

-- Table 2: rules (15 CIS Azure benchmark security rules)
CREATE TABLE dbo.rules (
    rule_id INT IDENTITY(1,1) PRIMARY KEY,
    rule_name NVARCHAR(150) NOT NULL,
    description NVARCHAR(MAX) NULL,
    severity NVARCHAR(20) NOT NULL CHECK(severity IN ('Critical', 'High', 'Medium', 'Low')),
    fix_guidance NVARCHAR(MAX) NULL,
    is_active BIT NOT NULL DEFAULT 1,
    category_id INT NOT NULL,
    CONSTRAINT FK_rules_category FOREIGN KEY (category_id) 
        REFERENCES dbo.rule_categories(category_id)
);

-- Table 3: users (RBAC & hashed credentials)
CREATE TABLE dbo.users (
    user_id INT IDENTITY(1,1) PRIMARY KEY,
    email NVARCHAR(255) NOT NULL UNIQUE,
    password_hash NVARCHAR(255) NOT NULL,
    role NVARCHAR(20) NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'analyst', 'viewer')),
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    is_active BIT NOT NULL DEFAULT 1
);

-- Table 4: scans (Cloud configuration scan executions)
CREATE TABLE dbo.scans (
    scan_id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL,
    filename NVARCHAR(255) NOT NULL,
    scanned_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    total_findings INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    risk_score NVARCHAR(20) NOT NULL,
    status NVARCHAR(30) NOT NULL DEFAULT 'completed',
    CONSTRAINT FK_scans_user FOREIGN KEY (user_id) 
        REFERENCES dbo.users(user_id)
);

-- Table 5: findings (Individual violations per scan)
CREATE TABLE dbo.findings (
    finding_id INT IDENTITY(1,1) PRIMARY KEY,
    scan_id INT NOT NULL,
    rule_id INT NOT NULL,
    severity NVARCHAR(20) NOT NULL,
    detail NVARCHAR(MAX) NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_findings_scan FOREIGN KEY (scan_id) 
        REFERENCES dbo.scans(scan_id) ON DELETE CASCADE,
    CONSTRAINT FK_findings_rule FOREIGN KEY (rule_id) 
        REFERENCES dbo.rules(rule_id)
);

-- Table 6: audit_log (Immutable audit trail)
CREATE TABLE dbo.audit_log (
    log_id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NULL,
    action NVARCHAR(100) NOT NULL,
    target NVARCHAR(255) NOT NULL,
    performed_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_audit_user FOREIGN KEY (user_id) 
        REFERENCES dbo.users(user_id) ON DELETE SET NULL
);

-- ============================================================================
-- 3. INDEXES (Query Optimization)
-- ============================================================================
CREATE NONCLUSTERED INDEX idx_scans_user ON dbo.scans(user_id);
CREATE NONCLUSTERED INDEX idx_findings_scan ON dbo.findings(scan_id);
CREATE NONCLUSTERED INDEX idx_findings_severity ON dbo.findings(severity);
CREATE NONCLUSTERED INDEX idx_audit_user ON dbo.audit_log(user_id);

-- ============================================================================
-- 4. VIEW: open_critical_findings (DirectQuery for Power BI)
-- ============================================================================
GO
CREATE VIEW dbo.open_critical_findings AS
SELECT 
    f.finding_id,
    s.filename,
    r.rule_name,
    r.fix_guidance,
    f.detail,
    s.scanned_at,
    u.email
FROM dbo.findings f
INNER JOIN dbo.scans s ON f.scan_id = s.scan_id
INNER JOIN dbo.rules r ON f.rule_id = r.rule_id
INNER JOIN dbo.users u ON s.user_id = u.user_id
WHERE f.severity = 'Critical';
GO

-- ============================================================================
-- 5. STORED PROCEDURE: Atomic Scan Creation (ACID Guarantee)
-- ============================================================================
GO
CREATE PROCEDURE dbo.sp_create_scan_with_findings
    @p_user_id INT,
    @p_filename NVARCHAR(255),
    @p_total_findings INT,
    @p_critical_count INT,
    @p_high_count INT,
    @p_medium_count INT,
    @p_low_count INT,
    @p_risk_score NVARCHAR(20),
    @p_new_scan_id INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    BEGIN TRANSACTION;

    BEGIN TRY
        INSERT INTO dbo.scans 
            (user_id, filename, scanned_at, total_findings, 
             critical_count, high_count, medium_count, low_count, 
             risk_score, status)
        VALUES 
            (@p_user_id, @p_filename, SYSUTCDATETIME(), @p_total_findings,
             @p_critical_count, @p_high_count, @p_medium_count, @p_low_count,
             @p_risk_score, 'completed');

        SET @p_new_scan_id = SCOPE_IDENTITY();

        INSERT INTO dbo.audit_log (user_id, action, target, performed_at)
        VALUES (@p_user_id, 'TRANSACTION_SCAN_INSERT', @p_filename, SYSUTCDATETIME());

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO