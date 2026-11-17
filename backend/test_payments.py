import time
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import patch

import jwt

import app as backend


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.result = None
        self.rows = []
        self.lastrowid = None

    def execute(self, query, params=None):
        normalized_query = " ".join(query.split())
        self.connection.executed.append((normalized_query, params))
        self.result = None
        self.rows = []

        if "FROM revoked_tokens" in normalized_query:
            self.result = None
        elif "FROM users" in normalized_query:
            if "SELECT full_name, email" in normalized_query:
                self.result = {
                    "full_name": "Test Patient",
                    "email": "patient@example.test",
                    "account_status": "active",
                    "created_at": "2025-01-01T00:00:00",
                }
            else:
                self.result = {
                    "user_id": self.connection.user_id,
                    "role": self.connection.role,
                    "account_status": "active",
                }
        elif "FROM doctors d" in normalized_query and params is not None:
            doctor_id, hospital_id = params
            if (
                self.connection.doctor_is_active
                and self.connection.hospital_is_active
                and doctor_id == 3
                and hospital_id == self.connection.doctor_hospital_id
            ):
                self.result = {"doctor_id": doctor_id}
        elif "FROM payments" in normalized_query and "FOR UPDATE" in normalized_query:
            payment_id, patient_id = params
            if (
                payment_id == self.connection.payment_id
                and patient_id == self.connection.payment_owner
            ):
                self.result = {
                    "payment_id": payment_id,
                    "appointment_id": 31,
                    "amount": Decimal("1000.00"),
                    "currency": "PKR",
                    "status": self.connection.payment_status,
                }
        elif normalized_query.startswith("UPDATE payments"):
            self.connection.payment_status = params[0]
        elif normalized_query.startswith("SELECT p.payment_id"):
            self.rows = [{
                "payment_id": 41,
                "appointment_id": 31,
                "amount": "1000.00",
                "currency": "PKR",
                "status": "Pending",
                "provider": "simulation",
            }]
        elif normalized_query.startswith("INSERT INTO appointments"):
            self.lastrowid = 31
        elif normalized_query.startswith("INSERT INTO payments"):
            self.lastrowid = 41

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConnection:
    def __init__(
        self,
        user_id,
        role,
        payment_id,
        payment_owner,
        doctor_is_active=True,
        hospital_is_active=True,
        doctor_hospital_id=5,
    ):
        self.user_id = user_id
        self.role = role
        self.payment_id = payment_id
        self.payment_owner = payment_owner
        self.doctor_is_active = doctor_is_active
        self.hospital_is_active = hospital_is_active
        self.doctor_hospital_id = doctor_hospital_id
        self.payment_status = "Pending"
        self.executed = []
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, dictionary=False):
        return FakeCursor(self)

    def start_transaction(self):
        pass

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        pass


class PaymentRouteTests(unittest.TestCase):
    def setUp(self):
        self.user_id = 7
        self.payment_id = 41
        self.payment_owner = self.user_id
        self.role = "patient"
        self.doctor_is_active = True
        self.hospital_is_active = True
        self.doctor_hospital_id = 5
        self.connections = []
        self.app_context = backend.app.test_client()
        self.backend_testing = backend.app.config["TESTING"]
        self.demo_mode = backend.app.config["DEMO_MODE"]
        backend.app.config["TESTING"] = True
        self.db_patch = patch.object(
            backend, "get_db_connection", side_effect=self.fake_connection
        )
        self.audit_patch = patch.object(backend, "write_audit_log")
        self.db_patch.start()
        self.audit_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.audit_patch.stop()
        backend.app.config["TESTING"] = self.backend_testing
        backend.app.config["DEMO_MODE"] = self.demo_mode

    def fake_connection(self):
        connection = FakeConnection(
            self.user_id,
            self.role,
            self.payment_id,
            self.payment_owner,
            self.doctor_is_active,
            self.hospital_is_active,
            self.doctor_hospital_id,
        )
        self.connections.append(connection)
        return connection

    def authorization_headers(self):
        token = jwt.encode(
            {
                "sub": str(self.user_id),
                "role": self.role,
                "jti": "payment-test-token",
                "exp": int(time.time()) + 60,
            },
            backend.app.config["JWT_SECRET_KEY"],
            algorithm="HS256",
        )
        return {"Authorization": f"Bearer {token}"}

    def test_booking_creates_pending_payment_in_same_transaction(self):
        appointment_date = (
            datetime.now(timezone.utc) + timedelta(days=1)
        ).replace(microsecond=0).isoformat()

        response = self.app_context.post(
            "/api/appointments",
            headers=self.authorization_headers(),
            json={
                "doctor_id": 3,
                "hospital_id": 5,
                "appointment_date": appointment_date,
                "reason": "Consultation",
            },
        )

        self.assertEqual(response.status_code, 201)
        result = response.get_json()
        self.assertEqual(result["payment"]["status"], "Pending")
        self.assertEqual(result["payment"]["amount"], "1000.00")

        booking_connection = self.connections[-1]
        executed_queries = [query for query, _ in booking_connection.executed]
        self.assertTrue(any(query.startswith("INSERT INTO appointments") for query in executed_queries))
        self.assertTrue(any(query.startswith("INSERT INTO payments") for query in executed_queries))
        self.assertEqual(booking_connection.commits, 1)

    def test_booking_rejects_inactive_doctor_before_creating_records(self):
        self.doctor_is_active = False
        appointment_date = (
            datetime.now(timezone.utc) + timedelta(days=1)
        ).replace(microsecond=0).isoformat()

        response = self.app_context.post(
            "/api/appointments",
            headers=self.authorization_headers(),
            json={
                "doctor_id": 3,
                "hospital_id": 5,
                "appointment_date": appointment_date,
                "reason": "Consultation",
            },
        )

        self.assertEqual(response.status_code, 404)
        booking_connection = self.connections[-1]
        self.assertFalse(any(
            query.startswith("INSERT INTO appointments")
            for query, _ in booking_connection.executed
        ))
        self.assertEqual(booking_connection.commits, 0)

    def test_booking_rejects_hospital_not_associated_with_doctor(self):
        self.doctor_hospital_id = 8
        appointment_date = (
            datetime.now(timezone.utc) + timedelta(days=1)
        ).replace(microsecond=0).isoformat()

        response = self.app_context.post(
            "/api/appointments",
            headers=self.authorization_headers(),
            json={
                "doctor_id": 3,
                "hospital_id": 5,
                "appointment_date": appointment_date,
                "reason": "Consultation",
            },
        )

        self.assertEqual(response.status_code, 404)
        booking_connection = self.connections[-1]
        self.assertFalse(any(
            query.startswith("INSERT INTO appointments")
            for query, _ in booking_connection.executed
        ))

    def test_booking_rejects_inactive_hospital(self):
        self.hospital_is_active = False
        appointment_date = (
            datetime.now(timezone.utc) + timedelta(days=1)
        ).replace(microsecond=0).isoformat()

        response = self.app_context.post(
            "/api/appointments",
            headers=self.authorization_headers(),
            json={
                "doctor_id": 3,
                "hospital_id": 5,
                "appointment_date": appointment_date,
                "reason": "Consultation",
            },
        )

        self.assertEqual(response.status_code, 404)
        booking_connection = self.connections[-1]
        self.assertFalse(any(
            query.startswith("INSERT INTO appointments")
            for query, _ in booking_connection.executed
        ))

    def test_patient_profile_returns_only_safe_account_fields(self):
        response = self.app_context.get(
            "/api/patient/profile",
            headers=self.authorization_headers(),
        )

        self.assertEqual(response.status_code, 200)
        profile = response.get_json()["profile"]
        self.assertEqual(profile["full_name"], "Test Patient")
        self.assertNotIn("password_hash", profile)
        self.assertNotIn("user_id", profile)

    def test_patient_profile_accepts_session_cookie_without_authorization_header(self):
        token = self.authorization_headers()["Authorization"].split(" ", 1)[1]
        self.app_context.set_cookie("medilink_session", token)

        response = self.app_context.get("/api/patient/profile")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["profile"]["full_name"], "Test Patient"
        )

    def test_logout_clears_session_cookie(self):
        token = self.authorization_headers()["Authorization"].split(" ", 1)[1]
        self.app_context.set_cookie("medilink_session", token)

        response = self.app_context.post("/api/logout")

        self.assertEqual(response.status_code, 200)
        self.assertIn("medilink_session=;", response.headers["Set-Cookie"])
        self.assertIn("Max-Age=0", response.headers["Set-Cookie"])

    def test_public_directories_filter_inactive_facilities_and_doctors(self):
        expected_filters = {
            "/api/doctors": "WHERE d.is_active = TRUE AND h.is_active = TRUE",
            "/api/hospitals": "WHERE is_active = TRUE",
            "/api/laboratories": (
                "WHERE l.is_active = TRUE AND h.is_active = TRUE"
            ),
        }

        for route, expected_filter in expected_filters.items():
            with self.subTest(route=route):
                response = self.app_context.get(route)
                self.assertEqual(response.status_code, 200)
                query = self.connections[-1].executed[0][0]
                self.assertIn(expected_filter, query)

    def test_simulation_uses_server_result_and_rejects_client_result(self):
        backend.app.config["DEMO_MODE"] = True
        with patch.object(backend, "PAYMENT_SIMULATION_RESULT", "failed"):
            forged_response = self.app_context.post(
                f"/api/patient/payments/{self.payment_id}/simulate",
                headers=self.authorization_headers(),
                json={"status": "Successful"},
            )
            self.assertEqual(forged_response.status_code, 400)

            response = self.app_context.post(
                f"/api/patient/payments/{self.payment_id}/simulate",
                headers=self.authorization_headers(),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["payment"]["status"], "Failed")
        self.assertEqual(self.connections[-1].payment_status, "Failed")

    def test_simulation_is_disabled_when_demo_mode_is_off(self):
        backend.app.config["DEMO_MODE"] = False

        response = self.app_context.post(
            f"/api/patient/payments/{self.payment_id}/simulate",
            headers=self.authorization_headers(),
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json()["message"],
            "Payment simulation is disabled",
        )

    def test_patient_cannot_simulate_another_patients_payment(self):
        backend.app.config["DEMO_MODE"] = True
        self.payment_owner = self.user_id + 1

        response = self.app_context.post(
            f"/api/patient/payments/{self.payment_id}/simulate",
            headers=self.authorization_headers(),
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.connections[-1].payment_status, "Pending")

    def test_payment_history_query_is_scoped_to_authenticated_patient(self):
        response = self.app_context.get(
            "/api/patient/payments",
            headers=self.authorization_headers(),
        )

        self.assertEqual(response.status_code, 200)
        history_connection = self.connections[-1]
        history_query = next(
            (query, params)
            for query, params in history_connection.executed
            if query.startswith("SELECT p.payment_id")
        )
        self.assertIn("WHERE p.patient_id = %s", history_query[0])
        self.assertEqual(history_query[1], (self.user_id,))


if __name__ == "__main__":
    unittest.main()
