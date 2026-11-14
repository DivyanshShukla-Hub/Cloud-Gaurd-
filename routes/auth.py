import time
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from models.db import get_db, log_audit
from services.security_guard import (
    validate_email_format,
    rate_limiter,
    generate_otp,
    send_otp_email,
)

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


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
        ip = get_client_ip()
        allowed, retry_after = rate_limiter.is_allowed(f"login_{ip}", max_requests=6, window_seconds=300)
        if not allowed:
            flash(
                f"Rate limit exceeded: Too many login attempts. Protection active. Please retry in {retry_after} seconds.",
                "danger",
            )
            return render_template("login.html"), 429

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

            rate_limiter.reset(f"login_{ip}")
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
        ip = get_client_ip()
        allowed, retry_after = rate_limiter.is_allowed(f"register_{ip}", max_requests=5, window_seconds=600)
        if not allowed:
            flash(
                f"Rate limit exceeded: Too many registration attempts from this network. Please retry in {retry_after} seconds.",
                "danger",
            )
            return render_template("register.html"), 429

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        # Validate Email Format & Reject Disposable/Throwaway Domains
        is_valid_email, email_err = validate_email_format(email)
        if not is_valid_email:
            flash(email_err, "danger")
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

        # Generate 6-digit OTP and store pending registration state
        otp_code = generate_otp()
        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        session["pending_reg"] = {
            "email": email,
            "password_hash": pw_hash,
            "otp": otp_code,
            "expires_at": time.time() + 600,  # 10 minutes expiry
            "attempts": 0,
        }

        # Attempt real email dispatch via SMTP, or provide simulation alert
        sent, msg = send_otp_email(email, otp_code)
        if sent:
            flash(f"A 6-digit verification code has been dispatched to {email}. Enter it below to activate.", "info")
        else:
            flash(
                f"[SIMULATED OTP] Verification code for {email} is: {otp_code} (Valid for 10 mins). Set SMTP_HOST to send live emails.",
                "info",
            )

        return redirect(url_for("auth.verify_otp"))

    return render_template("register.html")


@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "user_id" in session:
        return redirect(url_for("scans.dashboard"))

    pending = session.get("pending_reg")
    if not pending:
        flash("No pending registration session found. Please fill out registration first.", "warning")
        return redirect(url_for("auth.register"))

    if request.method == "POST":
        ip = get_client_ip()
        allowed, retry_after = rate_limiter.is_allowed(f"otp_{ip}", max_requests=6, window_seconds=300)
        if not allowed:
            flash(f"Rate limit exceeded on OTP verification. Please retry in {retry_after} seconds.", "danger")
            return render_template("verify_otp.html", email=pending["email"]), 429

        # Check code expiration
        if time.time() > pending["expires_at"]:
            session.pop("pending_reg", None)
            flash("Verification passcode has expired (10-minute limit). Please register again.", "danger")
            return redirect(url_for("auth.register"))

        code_entered = request.form.get("otp_code", "").strip()

        if code_entered != pending["otp"]:
            pending["attempts"] += 1
            session.modified = True
            if pending["attempts"] >= 3:
                session.pop("pending_reg", None)
                flash("Too many incorrect OTP attempts. Registration session terminated for security.", "danger")
                return redirect(url_for("auth.register"))

            remaining = 3 - pending["attempts"]
            flash(f"Invalid verification code. {remaining} attempt(s) remaining.", "danger")
            return render_template("verify_otp.html", email=pending["email"])

        # Code matched successfully! Commit operator into database
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (email, password_hash, role, is_active) VALUES (?, ?, ?, 1)",
            (pending["email"], pending["password_hash"], "viewer"),
        )
        new_uid = cursor.lastrowid
        db.commit()

        log_audit(new_uid, "USER_REGISTER_VERIFIED", f"Registered and verified {pending['email']} via 6-digit OTP challenge")
        session.pop("pending_reg", None)
        flash(f"Identity verified! Account for {pending['email']} activated. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("verify_otp.html", email=pending["email"])


@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    pending = session.get("pending_reg")
    if not pending:
        flash("No active registration found. Please register first.", "warning")
        return redirect(url_for("auth.register"))

    ip = get_client_ip()
    allowed, retry_after = rate_limiter.is_allowed(f"resend_{ip}", max_requests=3, window_seconds=300)
    if not allowed:
        flash(f"Please wait {retry_after} seconds before requesting another code.", "danger")
        return render_template("verify_otp.html", email=pending["email"])

    new_otp = generate_otp()
    pending["otp"] = new_otp
    pending["expires_at"] = time.time() + 600
    pending["attempts"] = 0
    session.modified = True

    sent, msg = send_otp_email(pending["email"], new_otp)
    if sent:
        flash(f"A fresh verification code has been dispatched to {pending['email']}.", "info")
    else:
        flash(f"[SIMULATED OTP] New verification passcode is: {new_otp} (valid for 10 mins).", "info")

    return redirect(url_for("auth.verify_otp"))


@auth_bp.route("/logout")
def logout():
    uid = session.get("user_id")
    email = session.get("email")
    if uid:
        log_audit(uid, "LOGOUT", f"User {email} logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
