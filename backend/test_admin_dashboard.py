import time
import unittest
from unittest.mock import patch

import jwt

import app as backend


class AdminCursor:
    def __init__(self, connection):
        self.connection = connection
        self.result = None
        self.rows = []
        self.lastrowid = None

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        self.connection.state["queries"].append((normalized, params))
        self.result = None
        self.rows = []

        if "FROM revoked_tokens" in normalized:
            return
        if "FROM users" in normalized and "role = 'admin'" in normalized:
            self.rows = self.connection.state["admins"]
            return
        if "FROM users" in normalized and "FOR UPDATE" in normalized:
            user_id = params[0]
            self.result = self.connection.state["users"].get(user_id)
            return
        if "FROM users" in normalized and "WHERE user_id = %s" in normalized:
            self.result = self.connection.state["users"].get(params[0])
            return
        if "FROM appointments" in normalized and "FOR UPDATE" in normalized:
            self.result = {
                "status": self.connection.state["appointment_status"]
            }
            return
        if "FROM hospitals" in normalized:
            self.result = {"hospital_id": 5}
            return
        if normalized.startswith("INSERT INTO users"):
            self.lastrowid = 50
            return
        if normalized.startswith("INSERT INTO doctors"):
            self.lastrowid = 60
            return
        if normalized.startswith("UPDATE appointments"):
            self.connection.state["appointment_status"] = params[0]
            self.connection.state["updated_appointment"] = params[1]
            return
        if "FROM medical_records mr" in normalized:
            self.rows = [{
                "record_id": 11,
                "patient_id": 22,
                "patient_name": "Test Patient",
                "patient_email": "patient@example.test",
                "doctor_id": 33,
                "doctor_name": "Test Doctor",
                "specialty": "General",
                "record_date": "2025-01-01",
                "hospital_name": "Test Hospital",
            }]

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class AdminConnection:
    def __init__(self, state):
        self.state = state

    def cursor(self, dictionary=False):
        return AdminCursor(self)

    def start_transaction(self):
        self.state["transactions"] += 1

    def commit(self):
        self.state["commits"] += 1

    def rollback(self):
        self.state["rollbacks"] += 1

    def close(self):
        pass


class AdminDashboardRouteTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "users": {
                7: {"user_id": 7, "role": "admin", "account_status": "active"},
                8: {"user_id": 8, "role": "admin", "account_status": "active"},
                9: {"user_id": 9, "role": "patient", "account_status": "active"},
            },
            "admins": [
                {"user_id": 7, "account_status": "active"},
                {"user_id": 8, "account_status": "active"},
            ],
            "queries": [],
            "commits": 0,
            "rollbacks": 0,
            "transactions": 0,
            "appointment_status": "Pending",
        }
        self.role = "admin"
        self.user_id = 7
        self.client = backend.app.test_client()
        self.original_testing = backend.app.config["TESTING"]
        backend.app.config["TESTING"] = True
        self.db_patch = patch.object(
            backend,
            "get_db_connection",
            side_effect=lambda: AdminConnection(self.state),
        )
        self.audit_patch = patch.object(backend, "write_audit_log")
        self.db_patch.start()
        self.audit_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.audit_patch.stop()
        backend.app.config["TESTING"] = self.original_testing

    def headers(self, role=None, user_id=None):
        token = jwt.encode(
            {
                "sub": str(user_id or self.user_id),
                "role": role or self.role,
                "jti": "admin-dashboard-test",
                "exp": int(time.time()) + 60,
            },
            backend.app.config["JWT_SECRET_KEY"],
            algorithm="HS256",
        )
        return {"Authorization": f"Bearer {token}"}

    def test_patient_cannot_access_admin_overview(self):
        self.role = "patient"
        response = self.client.get(
            "/api/admin/overview",
            headers=self.headers(role="patient", user_id=9),
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(any(
            "FROM hospitals" in query for query, _ in self.state["queries"]
        ))

    def test_fractional_resource_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            backend._admin_id(5.5, "hospital_id")

    def test_last_active_admin_cannot_be_suspended(self):
        self.state["admins"] = [
            {"user_id": 8, "account_status": "active"}
        ]
        response = self.client.patch(
            "/api/admin/users/8/status",
            json={"account_status": "suspended"},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.state["commits"], 0)
        self.assertEqual(self.state["rollbacks"], 1)

    def test_appointment_status_transition_is_validated_on_backend(self):
        response = self.client.patch(
            "/api/admin/appointments/31/status",
            json={"status": "Completed"},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.state["commits"], 0)
        self.assertIsNone(self.state.get("updated_appointment"))

    def test_pending_appointment_can_be_confirmed_and_committed(self):
        response = self.client.patch(
            "/api/admin/appointments/31/status",
            json={"status": "Confirmed"},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.state["appointment_status"], "Confirmed")
        self.assertEqual(self.state["updated_appointment"], 31)
        self.assertEqual(self.state["commits"], 1)

    def test_admin_medical_record_view_omits_clinical_fields(self):
        response = self.client.get(
            "/api/admin/medical-records",
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 200)
        record = response.get_json()["medical_records"][0]
        self.assertNotIn("diagnosis", record)
        self.assertNotIn("treatment", record)
        self.assertNotIn("prescription", record)
        query = next(
            query for query, _ in self.state["queries"]
            if "FROM medical_records mr" in query
        )
        self.assertNotIn("mr.diagnosis", query)
        self.assertNotIn("mr.treatment", query)
        self.assertNotIn("mr.prescription", query)

    def test_payment_management_has_no_write_endpoint(self):
        response = self.client.patch(
            "/api/admin/payments",
            json={"status": "Successful"},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(self.state["commits"], 0)

    def test_admin_doctor_creation_assigns_doctor_role_server_side(self):
        response = self.client.post(
            "/api/admin/doctors",
            json={
                "full_name": "New Doctor",
                "specialty": "Cardiology",
                "email": "doctor@example.test",
                "password": "secure-test-password",
                "hospital_id": 5,
            },
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("password", response.get_json())
        user_insert = next(
            (query, params) for query, params in self.state["queries"]
            if query.startswith("INSERT INTO users")
        )
        self.assertIn("'doctor'", user_insert[0])
        self.assertNotIn("secure-test-password", user_insert[1])
        self.assertEqual(self.state["commits"], 1)

    def test_public_registration_ignores_requested_privileged_role(self):
        response = self.client.post(
            "/api/register",
            json={
                "full_name": "New Patient",
                "email": "new-patient@example.test",
                "password": "secure-test-password",
                "role": "admin",
            },
        )
        self.assertEqual(response.status_code, 201)
        user_insert = next(
            (query, params) for query, params in self.state["queries"]
            if query.startswith("INSERT INTO users")
        )
        self.assertEqual(user_insert[1][3], "patient")


if __name__ == "__main__":
    unittest.main()
