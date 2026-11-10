import os
import uuid
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app, abort
from werkzeug.utils import secure_filename
from models.db import get_db, log_audit
from routes.auth import login_required
from services.parser import parse_config, ParseError
from services.rule_engine import run_rules, compute_risk_score

scans_bp = Blueprint("scans", __name__)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


@scans_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("scans.dashboard"))
    return redirect(url_for("auth.login"))


@scans_bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]

    total_scans = db.execute("SELECT COUNT(*) AS c FROM scans WHERE user_id = ?", (uid,)).fetchone()["c"]

    critical_findings = db.execute(
        "SELECT COUNT(*) AS c FROM findings f JOIN scans s ON f.scan_id = s.scan_id WHERE s.user_id = ? AND f.severity = 'Critical'",
        (uid,),
    ).fetchone()["c"]

    rules_active = db.execute("SELECT COUNT(*) AS c FROM rules WHERE is_active = 1").fetchone()["c"]

    last_scan = db.execute(
        "SELECT scanned_at FROM scans WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 1", (uid,)
    ).fetchone()
    last_scan_date = last_scan["scanned_at"][:10] if last_scan else "Never"

    recent = db.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 5", (uid,)
    ).fetchall()

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        critical_findings=critical_findings,
        rules_active=rules_active,
        last_scan_date=last_scan_date,
        recent_scans=recent,
    )


@scans_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        if "config_file" not in request.files:
            flash("No file selected.", "danger")
            return redirect(request.url)

        f = request.files["config_file"]
        if f.filename == "":
            flash("No file selected.", "danger")
            return redirect(request.url)

        if not allowed_file(f.filename):
            flash("Invalid file type. Only .json, .yaml, .yml allowed.", "danger")
            return redirect(request.url)

        ext = os.path.splitext(f.filename)[1].lower()
        original_name = secure_filename(f.filename) or f"manifest{ext}"
        unique_name = f"{uuid.uuid4().hex[:8]}_{original_name}"
        upload_dir = current_app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_dir, exist_ok=True)
        save_path = os.path.join(upload_dir, unique_name)
        f.save(save_path)

        uid = session["user_id"]
        log_audit(uid, "FILE_UPLOAD", original_name)

        # Parse and always remove temporary file from disk afterward
        try:
            config_dict, ftype = parse_config(save_path)
        except ParseError as e:
            flash(f"Parse error: {e}", "danger")
            return redirect(request.url)
        except Exception as e:
            flash(f"Unexpected error: {e}", "danger")
            return redirect(request.url)
        finally:
            if os.path.exists(save_path):
                os.remove(save_path)

        if not isinstance(config_dict, dict):
            flash("Config file must contain a JSON/YAML object.", "danger")
            return redirect(request.url)

        # Get active rules from DB
        db = get_db()
        active_rules = db.execute("SELECT * FROM rules WHERE is_active = 1").fetchall()

        # Run rules engine
        findings = run_rules(config_dict, active_rules)
        risk_score = compute_risk_score(findings)

        # Count severities
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for fd in findings:
            sev = fd["severity"]
            if sev in counts:
                counts[sev] += 1

        # Save scan and findings in a transaction
        try:
            cursor = db.cursor()
            cursor.execute(
                """INSERT INTO scans (user_id, filename, total_findings,
                   critical_count, high_count, medium_count, low_count, risk_score, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (uid, original_name, len(findings),
                 counts["Critical"], counts["High"], counts["Medium"], counts["Low"],
                 risk_score, "completed"),
            )
            scan_id = cursor.lastrowid

            for fd in findings:
                cursor.execute(
                    "INSERT INTO findings (scan_id, rule_id, severity, detail) VALUES (?, ?, ?, ?)",
                    (scan_id, fd["rule_id"], fd["severity"], fd["detail"]),
                )

            db.commit()
        except Exception as e:
            db.rollback()
            flash(f"Database error: {e}", "danger")
            return redirect(request.url)

        log_audit(uid, "SCAN_COMPLETED", f"Scan #{scan_id} on {original_name} - {risk_score}")
        flash(f"Scan complete! Found {len(findings)} issue(s).", "success")
        return redirect(url_for("scans.results", scan_id=scan_id))

    return render_template("upload.html")


@scans_bp.route("/scan/results/<int:scan_id>")
@login_required
def results(scan_id):
    db = get_db()
    uid = session["user_id"]

    scan = db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not scan:
        flash("Scan not found.", "danger")
        return redirect(url_for("scans.history"))

    if scan["user_id"] != uid and session.get("role") != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("scans.dashboard"))

    findings = db.execute(
        """SELECT f.*, r.rule_name, r.fix_guidance, c.category_name
           FROM findings f
           JOIN rules r ON f.rule_id = r.rule_id
           LEFT JOIN rule_categories c ON r.category_id = c.category_id
           WHERE f.scan_id = ?
           ORDER BY
               CASE f.severity
                   WHEN 'Critical' THEN 1
                   WHEN 'High' THEN 2
                   WHEN 'Medium' THEN 3
                   WHEN 'Low' THEN 4
               END""",
        (scan_id,),
    ).fetchall()

    return render_template("results.html", scan=scan, findings=findings)


@scans_bp.route("/scan/history")
@login_required
def history():
    db = get_db()
    uid = session["user_id"]
    scans = db.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY scanned_at DESC", (uid,)
    ).fetchall()
    return render_template("history.html", scans=scans)


@scans_bp.route("/sample_<name>.json")
def serve_sample(name):
    from flask import send_from_directory
    if name not in ("bad", "good"):
        abort(404)
    filename = f"sample_{name}.json"
    return send_from_directory(current_app.root_path, filename)
