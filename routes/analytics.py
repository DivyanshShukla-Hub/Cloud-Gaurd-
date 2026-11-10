import json
from flask import Blueprint, render_template
from models.db import get_db
from routes.auth import login_required

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/analytics")
@login_required
def analytics():
    db = get_db()

    # Top 10 most triggered rules
    top_rules = db.execute(
        """SELECT r.rule_name, r.severity, COUNT(f.finding_id) AS cnt
           FROM findings f
           JOIN rules r ON f.rule_id = r.rule_id
           GROUP BY f.rule_id
           ORDER BY cnt DESC
           LIMIT 10"""
    ).fetchall()
    top_labels = [r["rule_name"] for r in top_rules]
    top_values = [r["cnt"] for r in top_rules]

    # Critical findings per day (last 30 days)
    daily = db.execute(
        """SELECT DATE(f.created_at) AS day, COUNT(*) AS cnt
           FROM findings f
           WHERE f.severity = 'Critical'
             AND f.created_at >= DATE('now', '-30 days')
           GROUP BY DATE(f.created_at)
           ORDER BY day"""
    ).fetchall()
    daily_labels = [r["day"] for r in daily]
    daily_values = [r["cnt"] for r in daily]

    # Summary stats
    total_month = db.execute(
        "SELECT COUNT(*) AS c FROM scans WHERE scanned_at >= DATE('now', '-30 days')"
    ).fetchone()["c"]

    most_common_sev = db.execute(
        """SELECT severity, COUNT(*) AS cnt FROM findings
           GROUP BY severity ORDER BY cnt DESC LIMIT 1"""
    ).fetchone()
    most_common_sev_name = most_common_sev["severity"] if most_common_sev else "N/A"

    most_triggered = db.execute(
        """SELECT r.rule_name, COUNT(*) AS cnt FROM findings f
           JOIN rules r ON f.rule_id = r.rule_id
           GROUP BY f.rule_id ORDER BY cnt DESC LIMIT 1"""
    ).fetchone()
    most_triggered_name = most_triggered["rule_name"] if most_triggered else "N/A"

    return render_template(
        "analytics.html",
        top_labels=json.dumps(top_labels),
        top_values=json.dumps(top_values),
        daily_labels=json.dumps(daily_labels),
        daily_values=json.dumps(daily_values),
        total_month=total_month,
        most_common_sev=most_common_sev_name,
        most_triggered=most_triggered_name,
    )
