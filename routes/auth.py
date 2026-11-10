from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from models.db import get_db, log_audit

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("auth.login"))
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("scans.dashboard"))
        return f(*args, **kwargs)
    return wrapper


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("scans.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template("login.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and bcrypt.check_password_hash(user["password_hash"], password):
            if user["is_active"] != 1:
                flash("Your account has been suspended. Contact an administrator.", "danger")
                return render_template("login.html")

            session.clear()
            session["user_id"] = user["user_id"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            log_audit(user["user_id"], "LOGIN", f"User {email} logged in")
            flash(f"Welcome back, {email}!", "success")
            return redirect(url_for("scans.dashboard"))

        flash("Invalid email or password.", "danger")
        return render_template("login.html")

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("scans.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT user_id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("An account with that email already exists.", "danger")
            return render_template("register.html")

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, pw_hash, "viewer"),
        )
        new_uid = cursor.lastrowid
        db.commit()
        log_audit(new_uid, "USER_REGISTER", f"Registered {email} with default viewer role")
        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
def logout():
    uid = session.get("user_id")
    email = session.get("email")
    if uid:
        log_audit(uid, "LOGOUT", f"User {email} logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
