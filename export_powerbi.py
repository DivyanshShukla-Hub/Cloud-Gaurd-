"""
CloudGuard — DP-900 Power BI Data Extraction Utility
Extracts normalized relational views and scan telemetry into clean CSV files
ready for instant ingestion into Power BI Desktop.
"""

import sqlite3
import csv
import os

DB_PATH = "cloudguard.db"
OUTPUT_DIR = "powerbi_export"

def export_to_powerbi():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    exports = [
        (
            "powerbi_critical_findings.csv",
            """SELECT f.finding_id, s.filename, r.rule_name, r.fix_guidance,
                      f.detail, s.scanned_at, u.email
               FROM findings f
               JOIN scans s ON f.scan_id = s.scan_id
               JOIN rules r ON f.rule_id = r.rule_id
               JOIN users u ON s.user_id = u.user_id
               WHERE f.severity = 'Critical'"""
        ),
        (
            "powerbi_scans_summary.csv",
            """SELECT scan_id, filename, scanned_at, total_findings,
                      critical_count, high_count, medium_count, low_count,
                      risk_score, status
               FROM scans"""
        ),
        (
            "powerbi_rules_distribution.csv",
            """SELECT r.rule_id, r.rule_name, r.severity, c.category_name,
                      COUNT(f.finding_id) AS trigger_frequency
               FROM rules r
               LEFT JOIN rule_categories c ON r.category_id = c.category_id
               LEFT JOIN findings f ON r.rule_id = f.rule_id
               GROUP BY r.rule_id"""
        )
    ]

    print("=" * 65)
    print(" 📊 DP-900 POWER BI DATA EXTRACTION UTILITY")
    print("=" * 65)

    for filename, query in exports:
        out_path = os.path.join(OUTPUT_DIR, filename)
        cursor.execute(query)
        rows = cursor.fetchall()
        
        if rows:
            headers = rows[0].keys()
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for r in rows:
                    writer.writerow([r[h] for h in headers])
            print(f"✅ Generated {filename:<32} ({len(rows)} records)")
        else:
            print(f"⚠️  {filename:<32} (0 records - run a scan first)")

    conn.close()
    print("\n📁 Datasets saved in directory: ./powerbi_export/")
    print("👉 In Power BI Desktop: Home -> Get Data -> Text/CSV -> select these files.\n")

if __name__ == "__main__":
    export_to_powerbi()