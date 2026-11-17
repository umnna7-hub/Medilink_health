import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet
from unittest.mock import Mock, patch

from mysql.connector import Error

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import apply_migrations


class ApplyMigrationsTests(unittest.TestCase):
    def test_reads_migration_files_in_requested_order(self):
        migrations = apply_migrations._read_migrations()

        self.assertEqual(
            [filename for filename, _ in migrations],
            [
                "payments.sql",
                "patient_dashboard.sql",
                "login_attempts.sql",
                "mfa_setup.sql",
                "user_invites.sql",
                "mfa_security.sql",
            ],
        )

    def test_skips_existing_objects_and_continues(self):
        statements = [
            ("payments.sql", ["create payment table"]),
            (
                "patient_dashboard.sql",
                ["existing column", "add doctor relationship"],
            ),
            ("login_attempts.sql", ["create login attempts"]),
            ("mfa_setup.sql", ["add mfa column"]),
            ("user_invites.sql", ["create user invites"]),
            ("mfa_security.sql", ["add mfa security"]),
        ]
        executed = []
        cursor = Mock()

        def execute(statement):
            executed.append(statement)
            if statement == "existing column":
                raise Error(msg="Duplicate column", errno=1060)

        cursor.execute.side_effect = execute
        connection = Mock()
        connection.cursor.return_value = cursor

        with patch.object(
            apply_migrations, "_read_migrations", return_value=statements
        ):
            with patch.object(
                apply_migrations,
                "get_db_connection",
                return_value=connection,
            ):
                with patch.object(
                    apply_migrations, "_encrypt_legacy_mfa_secrets"
                ):
                    apply_migrations.apply_migrations()

        self.assertEqual(
            executed,
            [
                "create payment table",
                "existing column",
                "add doctor relationship",
                "create login attempts",
                "add mfa column",
                "create user invites",
                "add mfa security",
            ],
        )
        self.assertEqual(connection.commit.call_count, 6)
        cursor.close.assert_called_once()
        connection.close.assert_called_once()

    def test_legacy_mfa_secret_is_encrypted_in_place(self):
        secret = "LEGACY_BASE32_SECRET"
        row = {"user_id": 7, "mfa_secret": secret}

        class LegacyCursor:
            rowcount = 0

            def execute(self, query, params=None):
                if query.lstrip().startswith("SELECT user_id, mfa_secret"):
                    return
                if "SET mfa_secret = %s" in query:
                    self.encrypted_secret = params[0]
                    row["mfa_secret"] = params[0]
                    row["mfa_secret_format"] = "fernet"
                    self.rowcount = 1

            def fetchall(self):
                return [row] if row.get("mfa_secret_format") is None else []

            def close(self):
                pass

        class LegacyConnection:
            def __init__(self):
                self.cursor_instance = LegacyCursor()

            def cursor(self, dictionary=False):
                return self.cursor_instance

            def start_transaction(self):
                pass

            def commit(self):
                pass

            def rollback(self):
                raise AssertionError("Unexpected migration rollback")

        key = Fernet.generate_key()
        connection = LegacyConnection()
        with patch.dict(os.environ, {"MFA_ENCRYPTION_KEY": key.decode()}):
            apply_migrations._encrypt_legacy_mfa_secrets(connection)

        self.assertNotEqual(row["mfa_secret"], secret)
        self.assertEqual(row["mfa_secret_format"], "fernet")
        self.assertEqual(
            Fernet(key).decrypt(row["mfa_secret"].encode()).decode(),
            secret,
        )

    def test_refuses_drop_and_delete_statements(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            (directory / "unsafe.sql").write_text(
                "-- Migration\nDELETE FROM users;\n",
                encoding="utf-8",
            )
            with patch.object(apply_migrations, "PROJECT_ROOT", directory):
                with patch.object(
                    apply_migrations,
                    "MIGRATION_FILES",
                    ("unsafe.sql",),
                ):
                    with self.assertRaisesRegex(ValueError, "forbidden"):
                        apply_migrations._read_migrations()

    def test_does_not_skip_non_duplicate_mysql_errors(self):
        cursor = Mock()
        cursor.execute.side_effect = Error(
            msg="Table does not exist", errno=1146
        )
        connection = Mock()
        connection.cursor.return_value = cursor

        with patch.object(
            apply_migrations,
            "_read_migrations",
            return_value=[("payments.sql", ["alter missing table"])],
        ):
            with patch.object(
                apply_migrations,
                "get_db_connection",
                return_value=connection,
            ):
                with self.assertRaises(Error):
                    apply_migrations.apply_migrations()

        cursor.close.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
