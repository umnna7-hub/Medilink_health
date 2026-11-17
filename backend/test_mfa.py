import base64
import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
import unittest
from datetime import datetime, timezone
from types import ModuleType
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import jwt
try:
    import pyotp  # pyright: ignore[reportMissingImports]
except ImportError:
    class _FallbackTotp:
        def __init__(self, secret):
            self.secret = secret

        def now(self):
            key = base64.b32decode(self.secret + "=" * (-len(self.secret) % 8))
            counter = int(time.time()) // 30
            digest = hmac.new(
                key,
                struct.pack(">Q", counter),
                hashlib.sha1,
            ).digest()
            offset = digest[-1] & 0x0F
            value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
            return f"{value % 1000000:06d}"

    pyotp = ModuleType("pyotp")
    pyotp.random_base32 = lambda: base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    pyotp.TOTP = _FallbackTotp
    sys.modules["pyotp"] = pyotp
from cryptography.fernet import Fernet

import app as backend


def utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MfaCursor:
    def __init__(self, state):
        self.state = state
        self.result = None
        self.rowcount = 0

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        self.result = None
        self.rowcount = 0

        if "FROM revoked_tokens" in normalized:
            return

        if normalized.startswith(
            "SELECT failed_count, locked_until FROM login_attempts"
        ):
            attempt = self.state["attempts"].get(params[0])
            self.result = dict(attempt) if attempt else None
            return

        if normalized.startswith(
            "SELECT user_id, full_name, email, password_hash"
        ):
            user = self.state["users_by_email"].get(params[0])
            self.result = dict(user) if user else None
            return

        if normalized.startswith(
            "SELECT user_id, role, account_status, session_version"
        ):
            user = self.state["users_by_id"].get(params[0])
            self.result = (
                {
                    "user_id": user["user_id"],
                    "role": user["role"],
                    "account_status": user["account_status"],
                    "session_version": user["session_version"],
                    "mfa_confirmed_at": user["mfa_confirmed_at"],
                    "mfa_secret": user["mfa_secret"],
                    "mfa_secret_format": user["mfa_secret_format"],
                }
                if user else None
            )
            return

        if normalized.startswith("SELECT email, mfa_secret"):
            user = self.state["users_by_id"].get(params[0])
            self.result = (
                {
                    "email": user["email"],
                    "mfa_secret": user["mfa_secret"],
                    "mfa_secret_format": user["mfa_secret_format"],
                    "mfa_confirmed_at": user["mfa_confirmed_at"],
                }
                if user else None
            )
            return

        if normalized.startswith(
            "UPDATE users SET mfa_secret = %s, mfa_secret_format = 'fernet'"
        ):
            secret, user_id = params
            user = self.state["users_by_id"].get(user_id)
            if user and user["mfa_confirmed_at"] is None:
                user["mfa_secret"] = secret
                user["mfa_secret_format"] = "fernet"
                self.rowcount = 1
            return

        if normalized.startswith("INSERT INTO login_attempts"):
            email = params[0]
            attempt = self.state["attempts"].setdefault(
                email, {"failed_count": 0, "locked_until": None}
            )
            attempt["failed_count"] += 1
            return

        if normalized.startswith(
            "UPDATE login_attempts SET locked_until = DATE_ADD"
        ):
            attempt = self.state["attempts"].get(params[0])
            if attempt and attempt["failed_count"] >= 5:
                attempt["locked_until"] = "locked"
            return

        if normalized.startswith(
            "UPDATE login_attempts SET failed_count = 0"
        ):
            attempt = self.state["attempts"].get(params[0])
            if attempt:
                attempt["failed_count"] = 0
                attempt["locked_until"] = None

    def fetchone(self):
        return self.result

    def fetchall(self):
        return []

    def close(self):
        pass


class MfaConnection:
    def __init__(self, state):
        self.state = state

    def cursor(self, dictionary=False):
        return MfaCursor(self.state)

    def start_transaction(self):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class MfaRouteTests(unittest.TestCase):
    def setUp(self):
        user = {
            "user_id": 7,
            "full_name": "Test Staff",
            "email": "staff@example.test",
            "password_hash": "test-hash",
            "role": "admin",
            "account_status": "active",
            "mfa_secret": None,
            "mfa_secret_format": "fernet",
            "mfa_confirmed_at": None,
            "session_version": 0,
        }
        self.state = {
            "users_by_id": {user["user_id"]: user},
            "users_by_email": {user["email"]: user},
            "attempts": {},
        }
        self.original_testing = backend.app.config["TESTING"]
        backend.app.config["TESTING"] = True
        self.client = backend.app.test_client()
        self.db_patch = patch.object(
            backend,
            "get_db_connection",
            side_effect=lambda: MfaConnection(self.state),
        )
        self.password_patch = patch.object(
            backend,
            "check_password_hash",
            side_effect=lambda password_hash, password: (
                password == "correct-password"
            ),
        )
        self.audit_patch = patch.object(backend, "write_audit_log")
        self.encryption_key = Fernet.generate_key().decode("ascii")
        self.encryption_patch = patch.dict(
            os.environ, {"MFA_ENCRYPTION_KEY": self.encryption_key}
        )
        self.encryption_patch.start()
        self.db_patch.start()
        self.password_patch.start()
        self.audit_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.password_patch.stop()
        self.audit_patch.stop()
        self.encryption_patch.stop()
        backend.app.config["TESTING"] = self.original_testing

    def authorization_headers(self, role=None, purpose="session"):
        token = jwt.encode(
            {
                "sub": "7",
                "role": role or self.state["users_by_id"][7]["role"],
                "jti": "mfa-test-session",
                "sv": 0,
                "purpose": purpose,
                "exp": int(time.time()) + 60,
            },
            backend.app.config["JWT_SECRET_KEY"],
            algorithm="HS256",
        )
        return {"Authorization": f"Bearer {token}"}

    def setup_headers(self, role=None):
        return self.authorization_headers(role, purpose="mfa_setup")

    def login(self, password="correct-password", **fields):
        return self.client.post(
            "/api/login",
            json={
                "email": "staff@example.test",
                "password": password,
                **fields,
            },
        )

    def enable_mfa(self, role="admin"):
        user = self.state["users_by_id"][7]
        user["role"] = role
        secret = pyotp.random_base32()
        user["mfa_secret"] = backend._encrypt_mfa_secret(secret)
        user["mfa_secret_format"] = "fernet"
        user["mfa_confirmed_at"] = utcnow_naive()
        return secret

    def test_enrollment_returns_uncached_uri_and_encrypted_secret(self):
        response = self.client.post(
            "/api/mfa/enroll", headers=self.setup_headers()
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        uri = response.get_json()["provisioning_uri"]
        self.assertTrue(uri.startswith("otpauth://totp/"))
        returned_secret = parse_qs(urlparse(uri).query)["secret"][0]
        self.assertEqual(
            backend._decrypt_mfa_secret(
                self.state["users_by_id"][7]["mfa_secret"]
            ),
            returned_secret
        )

        second_response = self.client.post(
            "/api/mfa/enroll", headers=self.setup_headers()
        )
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(
            parse_qs(urlparse(
                second_response.get_json()["provisioning_uri"]
            ).query)["secret"][0],
            returned_secret
        )

    def test_enrollment_requires_token_and_privileged_role(self):
        self.assertEqual(
            self.client.post("/api/mfa/enroll").status_code, 401
        )

        self.state["users_by_id"][7]["role"] = "patient"
        response = self.client.post(
            "/api/mfa/enroll",
            headers=self.setup_headers(role="patient"),
        )
        self.assertEqual(response.status_code, 401)
        self.assertIsNone(self.state["users_by_id"][7]["mfa_secret"])

    def test_privileged_login_without_code_requires_mfa(self):
        self.enable_mfa()

        missing_code = self.login()
        wrong_password = self.login(password="incorrect-password")

        self.assertEqual(missing_code.status_code, 200)
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(
            missing_code.get_json()["status"], "mfa_required"
        )
        self.assertFalse(any(
            cookie.startswith("medilink_session=")
            and cookie.split("=", 1)[1].split(";", 1)[0]
            for cookie in missing_code.headers.getlist("Set-Cookie")
        ))

    def test_privileged_login_with_wrong_code_is_rejected_generically(self):
        self.enable_mfa()

        response = self.login(totp_code="not-a-code")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json()["message"], "Invalid email or password"
        )
        self.assertNotIn("totp", response.get_json()["message"].lower())

    def test_empty_stored_secret_does_not_bypass_mfa(self):
        self.state["users_by_id"][7]["mfa_secret"] = ""

        response = self.login()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["status"], "mfa_setup_required"
        )

    def test_admin_and_doctor_login_with_current_code_is_accepted(self):
        secret = self.enable_mfa()

        for role in ("admin", "doctor"):
            with self.subTest(role=role):
                self.state["users_by_id"][7]["role"] = role
                response = self.login(
                    totp_code=pyotp.TOTP(secret).now()
                )
                self.assertEqual(response.status_code, 200)

    def test_patient_login_remains_password_only(self):
        self.state["users_by_id"][7]["role"] = "patient"

        response = self.login()

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("totp_code", response.get_json())


if __name__ == "__main__":
    unittest.main()
