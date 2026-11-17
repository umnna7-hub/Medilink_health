import tempfile
import unittest
from pathlib import Path

import sqli_comparison
from sqli_comparison import VARIANTS, build_comparison_db, create_app
from sqli_demo import CASES, classify, run_matrix

UNION_ID = "0 UNION SELECT staff_id, username, password_hash, role FROM staff_accounts"
UNION_NAME = "' UNION SELECT staff_id, username, password_hash, role FROM staff_accounts --"


class SqliComparisonTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db_path = Path(self.folder.name) / "lab.db"
        build_comparison_db(self.db_path)
        self.client = create_app(self.db_path).test_client()

    def tearDown(self):
        self.folder.cleanup()

    def get(self, variant, endpoint, **params):
        return self.client.get(f"/{variant}/{endpoint}", query_string=params)

    def test_all_variants_return_normal_record(self):
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                response = self.get(variant, "patient", id="1")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.get_json()["patients"]), 1)

    def test_vulnerable_variant_is_injectable(self):
        tautology = self.get("vulnerable", "patient", id="1 OR 1=1")
        self.assertEqual(len(tautology.get_json()["patients"]), 5)

        theft = self.get("vulnerable", "patient", id=UNION_ID)
        self.assertIn("FAKE_HASH", str(theft.get_json()["patients"]))

        name_theft = self.get("vulnerable", "search", name=UNION_NAME)
        self.assertIn("FAKE_HASH", str(name_theft.get_json()["patients"]))

    def test_vulnerable_variant_leaks_database_error_text(self):
        response = self.get("vulnerable", "patient", id="1'")
        self.assertIn("error_detail", response.get_json())

    def test_other_variants_never_leak_database_error_text(self):
        for variant in VARIANTS:
            if variant == "vulnerable":
                continue
            with self.subTest(variant=variant):
                response = self.get(variant, "patient", id="1'")
                self.assertNotIn("error_detail", response.get_json())

    def test_validation_only_blocks_attacks_but_rejects_valid_apostrophe_name(self):
        attack = self.get("validation_only", "patient", id="1 OR 1=1")
        self.assertEqual(attack.status_code, 400)
        self.assertEqual(attack.get_json()["blocked_by"], "validation")

        legit = self.get("validation_only", "search", name="Liam O'Brien")
        self.assertEqual(legit.status_code, 400)

    def test_parameterized_only_treats_attacks_as_data(self):
        for endpoint, param, value in (
            ("patient", "id", "1 OR 1=1"),
            ("patient", "id", UNION_ID),
            ("search", "name", "' OR '1'='1"),
            ("search", "name", UNION_NAME),
        ):
            with self.subTest(value=value):
                response = self.get("parameterized_only", endpoint, **{param: value})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["patients"], [])

        legit = self.get("parameterized_only", "search", name="Liam O'Brien")
        self.assertEqual(len(legit.get_json()["patients"]), 1)

    def test_least_privilege_alone_limits_damage_but_does_not_stop_injection(self):
        # Still injectable inside the tables the account may read.
        tautology = self.get("least_privilege_only", "patient", id="1 OR 1=1")
        self.assertEqual(len(tautology.get_json()["patients"]), 5)

        # But the staff table is out of reach.
        theft = self.get("least_privilege_only", "patient", id=UNION_ID)
        self.assertEqual(theft.get_json()["blocked_by"], "database_privileges")
        self.assertNotIn("FAKE_HASH", str(theft.get_json()))

    def test_least_privilege_connection_is_read_only(self):
        connection = sqli_comparison.connect_least_privilege(self.db_path)
        try:
            with self.assertRaises(Exception):
                connection.execute("DELETE FROM patients")
            with self.assertRaises(Exception):
                connection.execute("SELECT * FROM staff_accounts")
        finally:
            connection.close()

        check = sqli_comparison.connect_full_access(self.db_path)
        try:
            count = check.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
            self.assertEqual(count, 5)
        finally:
            check.close()

    def test_stacked_statement_does_not_drop_table_in_any_variant(self):
        for variant in VARIANTS:
            self.get(variant, "patient", id="1; DROP TABLE patients")
        connection = sqli_comparison.connect_full_access(self.db_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
            self.assertEqual(count, 5)
        finally:
            connection.close()

    def test_combined_variant_stops_every_attack_and_keeps_valid_names_working(self):
        for endpoint, param, value in (
            ("patient", "id", "1 OR 1=1"),
            ("patient", "id", UNION_ID),
            ("search", "name", "' OR '1'='1"),
            ("search", "name", UNION_NAME),
        ):
            with self.subTest(value=value):
                response = self.get("combined", endpoint, **{param: value})
                self.assertNotIn("FAKE_HASH", str(response.get_json()))
                self.assertEqual(response.get_json().get("patients", []), [])

        legit = self.get("combined", "search", name="Liam O'Brien")
        self.assertEqual(len(legit.get_json()["patients"]), 1)

    def test_unknown_variant_is_rejected(self):
        self.assertEqual(self.get("nope", "patient", id="1").status_code, 404)

    def test_demo_matrix_matches_expected_outcomes(self):
        results = {row[0]: dict(zip(["case", "kind"] + list(VARIANTS), row)) for row in run_matrix()}

        for case_name, row in results.items():
            self.assertEqual(row["case"], case_name)

        union = results["ID UNION theft"]
        self.assertEqual(union["vulnerable"], "STAFF LEAKED")
        self.assertEqual(union["parameterized_only"], "SAFE")
        self.assertEqual(union["least_privilege_only"], "BLOCKED-DB")
        self.assertEqual(union["combined"], "BLOCKED-VALID")

        self.assertEqual(results["ID tautology"]["least_privilege_only"], "ALL PATIENTS")
        self.assertEqual(results["Name with apostrophe"]["validation_only"], "REJECTED")
        self.assertEqual(results["Name with apostrophe"]["combined"], "OK")

    def test_every_case_is_listed_once_per_variant(self):
        self.assertEqual(len(run_matrix()), len(CASES))

    def test_classify_marks_staff_data_as_leak(self):
        body = {"status": "success", "patients": [[1, "u", "FAKE_HASH_x", "admin"]]}
        self.assertEqual(classify("attack", 200, body), "STAFF LEAKED")


if __name__ == "__main__":
    unittest.main()
