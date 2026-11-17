import sqlite3
import unittest
from unittest.mock import patch

import secure_app


class SecureSearchTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute(
            """
            CREATE TABLE patients (
                patient_id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                diagnosis TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            "INSERT INTO patients VALUES (?, ?, ?, ?)",
            (1, "Sample Patient", "sample@example.test", "Test diagnosis"),
        )
        self.connection.commit()
        self.database_patch = patch.object(
            secure_app, "get_lab_connection", return_value=self.connection
        )
        self.get_connection = self.database_patch.start()
        self.client = secure_app.app.test_client()

    def tearDown(self):
        self.database_patch.stop()
        self.connection.close()

    def test_search_rejects_non_numeric_and_non_positive_ids_before_database_access(self):
        for patient_id in ("not-a-number", "0", "-1"):
            with self.subTest(patient_id=patient_id):
                response = self.client.get(
                    "/secure-search", query_string={"id": patient_id}
                )
                self.assertEqual(response.status_code, 400)

        self.get_connection.assert_not_called()

    def test_search_returns_matching_sample_record(self):
        response = self.client.get(
            "/secure-search", query_string={"id": "1"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["patients"],
            [[1, "Sample Patient", "sample@example.test", "Test diagnosis"]],
        )


if __name__ == "__main__":
    unittest.main()
