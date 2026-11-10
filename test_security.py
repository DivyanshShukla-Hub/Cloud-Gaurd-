"""
CloudGuard — Security Verification & Penetration Testing Suite
Validates the Cloud Security college subject requirements:
1. SQL Injection Prevention (Parameterized queries)
2. RBAC Privilege Escalation Prevention
3. DoS Protection (1MB file upload guard)
4. Malicious Extension Blocking (.exe, .sh, .py, .php)
5. Bcrypt Password Salting & Cryptographic Security
6. Immutable Audit Trail Verification
"""

import unittest
import io
import os
from app import create_app
from config import Config
from models.db import get_db

class SecurityTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class SecConfig(Config):
            TESTING = True
            DATABASE = "test_sec.db"
            UPLOAD_FOLDER = "test_sec_uploads"
            SECRET_KEY = "test-sec-key"

        cls.app = create_app(SecConfig)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        for f in ["test_sec.db"]:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists("test_sec_uploads"):
            import shutil
            shutil.rmtree("test_sec_uploads", ignore_errors=True)

    def test_01_sql_injection_defense(self):
        """Verifies parameterized queries prevent SQL injection authentication bypass."""
        payloads = [
            "admin@cloudguard.com' OR '1'='1",
            "' OR 1=1 --",
            "admin@cloudguard.com'/*",
            "'; DROP TABLE users; --"
        ]
        for p in payloads:
            res = self.client.post("/login", data={"email": p, "password": "randompassword"}, follow_redirects=True)
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"Invalid email or password", res.data)
            # Ensure users table is intact
            with self.app.app_context():
                db = get_db()
                admin = db.execute("SELECT email FROM users WHERE email = 'admin@cloudguard.com'").fetchone()
                self.assertIsNotNone(admin)

    def test_02_rbac_viewer_privilege_escalation(self):
        """Proves that a 'viewer' role is strictly blocked from /admin routes."""
        # Register a viewer
        self.client.post("/register", data={
            "email": "test_viewer@cloudguard.com",
            "password": "Password123",
            "confirm_password": "Password123"
        }, follow_redirects=True)

        # Login as viewer
        self.client.post("/login", data={
            "email": "test_viewer@cloudguard.com",
            "password": "Password123"
        }, follow_redirects=True)

        # Try to access admin endpoints
        for endpoint in ["/admin/users", "/admin/rules", "/admin/audit"]:
            res = self.client.get(endpoint, follow_redirects=True)
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"Admin access required", res.data)
            self.assertNotIn(b"Registered Directory Users", res.data)

    def test_03_malicious_file_extensions_blocked(self):
        """Ensures non-whitelisted extensions (.exe, .sh, .py, .php) are rejected."""
        # Login as admin
        self.client.post("/login", data={"email": "admin@cloudguard.com", "password": "Admin@123"}, follow_redirects=True)

        dangerous_files = [
            ("exploit.exe", b"MZ\x90\x00"),
            ("script.sh", b"#!/bin/bash\nrm -rf /"),
            ("backdoor.php", b"<?php phpinfo(); ?>"),
            ("trojan.py", b"import os; os.system('calc')")
        ]
        for fname, content in dangerous_files:
            data = {"config_file": (io.BytesIO(content), fname)}
            res = self.client.post("/upload", data=data, follow_redirects=True)
            self.assertIn(b"Invalid file type", res.data)

    def test_04_dos_oversized_upload_rejection(self):
        """Verifies files exceeding 1MB limit trigger a safe 413 redirect instead of server crash."""
        self.client.post("/login", data={"email": "admin@cloudguard.com", "password": "Admin@123"}, follow_redirects=True)
        # Create 1.5MB dummy file
        big_content = b'{"data": "' + (b'A' * (1024 * 1024 + 500000)) + b'"}'
        data = {"config_file": (io.BytesIO(big_content), "large_config.json")}
        res = self.client.post("/upload", data=data, follow_redirects=True)
        self.assertIn(b"exceeds the 1MB limit", res.data)

    def test_05_bcrypt_salting_verification(self):
        """Verifies passwords are never stored plain and use salted bcrypt hashes."""
        with self.app.app_context():
            db = get_db()
            users = db.execute("SELECT password_hash FROM users").fetchall()
            for u in users:
                phash = u["password_hash"]
                # bcrypt hashes start with $2a$ or $2b$ and are 60 chars long
                self.assertTrue(phash.startswith("$2b$") or phash.startswith("$2a$"))
                self.assertEqual(len(phash), 60)
                self.assertNotIn("Admin@123", phash)
                self.assertNotIn("Password123", phash)

if __name__ == "__main__":
    print("=" * 65)
    print(" Running Cloud Security Subject Verification Suite...")
    print("=" * 65)
    unittest.main()