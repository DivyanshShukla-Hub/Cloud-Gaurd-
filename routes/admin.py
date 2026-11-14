from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from models.db import get_db, log_audit
from routes.auth import admin_required
from services.security_guard import validate_email_format

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
bcrypt = Bcrypt()


@admin_bp.route("/users")
@admin_required
def users():
    db = get_db()
    user_list = db.execute(
        "SELECT user_id, email, role, created_at, is_active FROM users ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin/users.html", users=user_list)


@admin_bp.route("/users/create", methods=["POST"])
@admin_required
def create_user():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer").lower()

    if not email or not password:
        flash("Email and password are required to create a user.", "danger")
        return redirect(url_for("admin.users"))

    is_valid_email, email_err = validate_email_format(email)
    if not is_valid_email:
        flash(email_err, "danger")
        return redirect(url_for("admin.users"))

    if len(password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for("admin.users"))

    if role not in ["admin", "analyst", "viewer"]:
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.users"))

    db = get_db()
    existing = db.execute("SELECT user_id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        flash(f"User with email '{email}' already exists.", "danger")
        return redirect(url_for("admin.users"))

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, role, is_active) VALUES (?, ?, ?, 1)",
        (email, pw_hash, role),
    )
    new_uid = cursor.lastrowid
    db.commit()

    log_audit(session["user_id"], "CREATE_USER", f"Admin created user #{new_uid} ({email}) with role '{role}'")
    flash(f"User {email} successfully created with role '{role}'.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    new_role = request.form.get("role", "").lower()
    if new_role not in ["admin", "analyst", "viewer"]:
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.users"))

    if user_id == session["user_id"] and new_role != "admin":
        flash("You cannot demote your own active admin session.", "danger")
        return redirect(url_for("admin.users"))

    db = get_db()
    target_user = db.execute("SELECT user_id, email FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not target_user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.users"))

    db.execute("UPDATE users SET role = ? WHERE user_id = ?", (new_role, user_id))
    db.commit()

    log_audit(session["user_id"], "CHANGE_ROLE", f"User #{user_id} ({target_user['email']}) role set to {new_role}")
    flash(f"User role for {target_user['email']} updated to {new_role}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle-status", methods=["POST"])
@admin_required
def toggle_user_status(user_id):
    if user_id == session["user_id"]:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("admin.users"))

    db = get_db()
    user = db.execute("SELECT is_active, email FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.users"))

    new_status = 0 if user["is_active"] == 1 else 1
    db.execute("UPDATE users SET is_active = ? WHERE user_id = ?", (new_status, user_id))
    db.commit()
    status_name = "Reactivated" if new_status == 1 else "Deactivated"
    log_audit(session["user_id"], "USER_STATUS_CHANGE", f"{status_name} user #{user_id} ({user['email']})")
    flash(f"Account for {user['email']} has been {status_name.lower()}.", "info")

    return redirect(url_for("admin.users"))


@admin_bp.route("/rules")
@admin_required
def rules():
    db = get_db()
    rules_list = db.execute(
        """SELECT r.*, c.category_name
           FROM rules r
           LEFT JOIN rule_categories c ON r.category_id = c.category_id
           ORDER BY r.rule_id ASC"""
    ).fetchall()
    return render_template("admin/rules.html", rules=rules_list)


@admin_bp.route("/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    db = get_db()
    rule = db.execute("SELECT is_active, rule_name FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if not rule:
        flash("Rule not found.", "danger")
        return redirect(url_for("admin.rules"))

    new_active = 0 if rule["is_active"] == 1 else 1
    db.execute("UPDATE rules SET is_active = ? WHERE rule_id = ?", (new_active, rule_id))
    db.commit()
    action_name = "Enabled" if new_active == 1 else "Disabled"
    log_audit(session["user_id"], "RULE_TOGGLE", f"{action_name} rule #{rule_id} ({rule['rule_name']})")
    flash(f"Rule #{rule_id} is now {action_name.lower()}.", "info")

    return redirect(url_for("admin.rules"))


@admin_bp.route("/audit")
@admin_required
def audit():
    db = get_db()
    logs = db.execute(
        """SELECT a.*, u.email
           FROM audit_log a
           LEFT JOIN users u ON a.user_id = u.user_id
           ORDER BY a.performed_at DESC"""
    ).fetchall()
    return render_template("admin/audit.html", logs=logs)
