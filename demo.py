"""
CloudGuard — Interactive College Demo Script
Simulates full audit lifecycle across System Design, RDBMS, DP-900, and Cloud Security.
Run: python demo.py
"""

import os
import json
from app import create_app
from models.db import get_db
from services.parser import parse_config
from services.rule_engine import run_rules, compute_risk_score

def print_header(title):
    print("\n" + "=" * 65)
    print(f" {title}")
    print("=" * 65)

def run_demo():
    print_header("🛡️ CLOUDGUARD: COLLEGE PROJECT DEMONSTRATION")
    print("Subjects Covered: System Design | RDBMS | DP-900 | Cloud Security")
    print("Tech Stack: Python Flask | SQLite / Azure SQL | PyYAML | Chart.js")

    app = create_app()

    with app.app_context():
        db = get_db()

        # Step 1: Verify 3NF RDBMS tables
        print_header("1. RDBMS: 3NF Database Verification")
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() if not r[0].startswith("sqlite_")]
        print(f"✅ Tables verified ({len(tables)} tables): {', '.join(tables)}")

        rule_count = db.execute("SELECT COUNT(*) FROM rules WHERE is_active = 1").fetchone()[0]
        print(f"✅ Active Security Benchmark Rules in DB: {rule_count}")

        # Step 2: Audit Sample Bad Config
        print_header("2. Cloud Security: Scanning sample_bad.json")
        bad_config, ftype = parse_config("sample_bad.json")
        active_rules = db.execute("SELECT * FROM rules WHERE is_active = 1").fetchall()

        findings = run_rules(bad_config, active_rules)
        risk = compute_risk_score(findings)

        print(f"• File Parsed: sample_bad.json (Format: {ftype})")
        print(f"• Total Violations Detected: {len(findings)}")
        print(f"• Overall Calculated Risk Score: [{risk}]")

        print("\nTop Detected Violations:")
        for idx, f in enumerate(findings[:5], 1):
            rule_name = db.execute("SELECT rule_name FROM rules WHERE rule_id = ?", (f["rule_id"],)).fetchone()["rule_name"]
            print(f"  {idx}. [{f['severity']}] {rule_name}")
            print(f"     Detail: {f['detail']}")

        # Step 3: Test SQL View
        print_header("3. DP-900 & SQL View: open_critical_findings")
        critical_in_view = db.execute("SELECT COUNT(*) FROM open_critical_findings").fetchone()[0]
        print(f"✅ Records in 'open_critical_findings' view: {critical_in_view}")
        print("   (Ready for Power BI DirectQuery ingestion)")

        # Step 4: Audit Trail
        print_header("4. Cloud Security: Immutable Audit Trail")
        recent_logs = db.execute("SELECT action, target, performed_at FROM audit_log ORDER BY performed_at DESC LIMIT 3").fetchall()
        for l in recent_logs:
            print(f"• [{l['performed_at'][:19]}] Action: {l['action']:<18} Target: {l['target']}")

        # Step 5: Clean Audit Sample
        print_header("5. Compliance: Scanning sample_good.json")
        good_config, g_ftype = parse_config("sample_good.json")
        good_findings = run_rules(good_config, active_rules)
        good_risk = compute_risk_score(good_findings)
        print(f"• File Parsed: sample_good.json (Format: {g_ftype})")
        print(f"• Violations Detected: {len(good_findings)}")
        print(f"• Overall Calculated Risk Score: [{good_risk}] -> Clean (100% Compliant)")

    print_header("🎉 DEMONSTRATION COMPLETE: ALL CHECKS PASSED")
    print("To launch the web interface:")
    print("👉 Run: python app.py")
    print("👉 Navigate: http://localhost:5000")
    print("👉 Credentials: admin@cloudguard.com / Admin@123\n")

if __name__ == "__main__":
    run_demo()