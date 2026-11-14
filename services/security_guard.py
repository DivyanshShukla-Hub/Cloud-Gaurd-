import os
import re
import time
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from threading import Lock

# RFC 5322 simplified regex for realistic email syntax
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

# Obvious throwaway or reserved test domains that shouldn't pass real validation
BLOCKED_DOMAINS = {
    "fake.com", "fake.org", "test.com", "test.org", "example.com", "example.org",
    "trashmail.com", "tempmail.com", "mailinator.com", "dispostable.com", "10minutemail.com"
}


def validate_email_format(email: str) -> tuple[bool, str]:
    """Validates email format, structure, and checks for disposable/throwaway domains."""
    if not email or len(email) > 254:
        return False, "Email address must be between 3 and 254 characters."

    clean = email.strip().lower()
    if not EMAIL_REGEX.match(clean):
        return False, "Please provide a valid corporate or operational email format (e.g., user@domain.com)."

    domain = clean.split("@")[-1]
    if domain in BLOCKED_DOMAINS:
        return False, f"Domain '@{domain}' is a restricted disposable/test domain. Please use a valid email."

    # Must contain a period in domain with at least 2 chars TLD
    parts = domain.split(".")
    if len(parts) < 2 or len(parts[-1]) < 2:
        return False, "Email must have a valid top-level domain (e.g. .com, .edu, .org, .io)."

    return True, ""


class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter per client IP or key."""
    def __init__(self):
        self._history = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """
        Check if key has exceeded max_requests within window_seconds.
        Returns: (allowed: bool, retry_after: int)
        """
        now = time.time()
        with self._lock:
            # Purge expired timestamps
            timestamps = [t for t in self._history[key] if now - t < window_seconds]
            self._history[key] = timestamps

            if len(timestamps) >= max_requests:
                oldest = timestamps[0]
                retry_after = int(window_seconds - (now - oldest)) + 1
                return False, max(1, retry_after)

            # Record attempt
            self._history[key].append(now)
            return True, 0

    def reset(self, key: str):
        with self._lock:
            self._history.pop(key, None)


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter()


def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit numeric OTP."""
    code = secrets.randbelow(900000) + 100000
    return str(code)


def send_otp_email(recipient_email: str, otp_code: str) -> tuple[bool, str]:
    """
    Sends 6-digit verification code via SMTP if configured.
    Falls back gracefully to simulated dev delivery if SMTP is not configured.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    sender_email = os.environ.get("SMTP_FROM", smtp_user or "secops@cloudguard.local")

    # If no SMTP credentials provided, return False to trigger simulated display
    if not smtp_host or not smtp_user or not smtp_pass:
        return False, "SMTP server not configured; simulated delivery enabled."

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"CloudGuard SecOps // Verification Code: {otp_code}"
        msg["From"] = f"CloudGuard Security <{sender_email}>"
        msg["To"] = recipient_email

        text_content = (
            f"CloudGuard SecOps Verification\n\n"
            f"Your one-time registration code is: {otp_code}\n\n"
            f"This code will expire in 10 minutes. If you did not request this, please ignore this message.\n"
        )

        html_content = f"""
        <html>
        <body style="font-family: 'JetBrains Mono', monospace, Arial, sans-serif; background: #0a0a0c; color: #f5f5f7; padding: 24px;">
            <div style="max-width: 480px; margin: 0 auto; background: #131418; border: 2px solid #27272a; padding: 24px;">
                <div style="border-bottom: 2px solid #27272a; padding-bottom: 12px; margin-bottom: 16px;">
                    <span style="background: #e11d48; color: #ffffff; padding: 4px 8px; font-weight: bold; font-size: 12px;">CLOUDWATCH // SECOPS</span>
                    <h2 style="margin: 12px 0 0 0; font-size: 18px; text-transform: uppercase;">Operator Identity Verification</h2>
                </div>
                <p style="color: #a1a1aa; font-size: 13px;">Enter the following 6-digit one-time passcode to finalize your CloudGuard security platform registration:</p>
                <div style="background: #18191e; border: 2px dashed #0284c7; padding: 16px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 32px; font-weight: 900; letter-spacing: 8px; color: #38bdf8;">{otp_code}</span>
                </div>
                <p style="color: #71717a; font-size: 11px;">Expires in 10 minutes. For system security, do not share this passcode with anyone.</p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        return True, "Verification email dispatched via SMTP."
    except Exception as e:
        return False, f"SMTP dispatch failed: {str(e)}"
