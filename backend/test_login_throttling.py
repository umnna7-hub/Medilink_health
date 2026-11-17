import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import app as backend


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.result = None
        self.executed = []

    def execute(self, query, params=None):
        normalized_query = " ".join(query.split())
        self.executed.append((normalized_query, params))
        self.result = None

        if normalized_query.startswith(
            "SELECT failed_count, locked_until FROM login_attempts"
        ):
            attempt = self.connection.attempts.get(params[0])
            self.result = dict(attempt) if attempt else None
        elif normalized_query.startswith(
            "SELECT user_id, full_name, email, password_hash"
        ):
            if params[0] == "patient@example.test":
                self.result = {
                    "user_id": 7,
                    "full_name": "Test Patient",
                    "email": "patient@example.test",
                    "password_hash": "test-hash",
                    "role": "patient",
                    "account_status": "active",
                }
        elif normalized_query.startswith("INSERT INTO login_attempts"):
            email = params[0]
            attempt = self.connection.attempts.get(email)
            if attempt is None:
                self.connection.attempts[email] = {
                    "failed_count": 1,
                    "locked_until": None,
                }
            else:
                attempt["failed_count"] += 1
        elif normalized_query.startswith(
            "UPDATE login_attempts SET locked_until = DATE_ADD"
        ):
            attempt = self.connection.attempts.get(params[0])
            if (
                attempt
                and attempt["failed_count"] >= 5
                and attempt["locked_until"] is None
            ):
                attempt["locked_until"] = (
                    datetime.now(timezone.utc).replace(tzinfo=None)
                    + timedelta(minutes=15)
                )
        elif normalized_query.startswith(
            "UPDATE login_attempts SET failed_count = 0"
        ):
            attempt = self.connection.attempts.get(params[0])
            if attempt:
                attempt["failed_count"] = 0
                attempt["locked_until"] = None

    def fetchone(self):
        return self.result

    def close(self):
        pass


class FakeConnection:
    def __init__(self):
        self.attempts = {}
        self.executed = []
        self.commits = 0

    def cursor(self, dictionary=False):
        cursor = FakeCursor(self)
        self.executed.append(cursor)
        return cursor

    def commit(self):
        self.commits += 1

    def close(self):
        pass


class LoginThrottlingTests(unittest.TestCase):
    def setUp(self):
        self.connection = FakeConnection()
        self.original_testing = backend.app.config["TESTING"]
        backend.app.config["TESTING"] = True
        self.client = backend.app.test_client()
        self.db_patch = patch.object(
            backend, "get_db_connection", return_value=self.connection
        )
        self.password_patch = patch.object(
            backend,
            "check_password_hash",
            side_effect=lambda password_hash, password: password == "correct",
        )
        self.audit_patch = patch.object(backend, "write_audit_log")
        self.db_patch.start()
        self.password_check = self.password_patch.start()
        self.audit_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.password_patch.stop()
        self.audit_patch.stop()
        backend.app.config["TESTING"] = self.original_testing

    def login(self, email, password):
        return self.client.post(
            "/api/login",
            json={"email": email, "password": password},
        )

    def test_five_failures_lock_unknown_email_with_generic_response(self):
        for _ in range(5):
            response = self.login("unknown@example.test", "wrong")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(
                response.get_json()["message"],
                "Invalid email or password",
            )

        attempt = self.connection.attempts["unknown@example.test"]
        self.assertEqual(attempt["failed_count"], 5)
        self.assertGreater(
            attempt["locked_until"],
            datetime.now(timezone.utc).replace(tzinfo=None),
        )

    def test_successful_login_resets_failed_attempts(self):
        for _ in range(4):
            response = self.login("patient@example.test", "wrong")
            self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/api/login",
            headers={"Origin": "http://localhost:5173"},
            json={
                "email": "patient@example.test",
                "password": "correct",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("token", response.get_json())
        cookie = response.headers["Set-Cookie"]
        self.assertIn("medilink_session=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertEqual(
            response.headers["Access-Control-Allow-Credentials"], "true"
        )
        self.assertEqual(
            response.headers["Content-Security-Policy"], "default-src 'self'"
        )
        attempt = self.connection.attempts["patient@example.test"]
        self.assertEqual(attempt["failed_count"], 0)
        self.assertIsNone(attempt["locked_until"])

        for _ in range(4):
            response = self.login("patient@example.test", "wrong")
            self.assertEqual(response.status_code, 401)

    def test_locked_email_returns_429_before_password_check(self):
        self.connection.attempts["patient@example.test"] = {
            "failed_count": 5,
            "locked_until": (
                datetime.now(timezone.utc).replace(tzinfo=None)
                + timedelta(minutes=15)
            ),
        }

        response = self.login("patient@example.test", "wrong")

        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.get_json()["message"],
            "Too many failed attempts. Try again later.",
        )
        self.password_check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
