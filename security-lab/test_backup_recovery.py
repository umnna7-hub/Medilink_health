import contextlib
import hashlib
import hmac
import io
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

import backup_recovery


class BackupRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.original = self.directory / "source.txt"
        self.backup_folder = self.directory / "backups"
        self.original_bytes = b"known-good sample\n"
        self.original.write_bytes(self.original_bytes)
        self.backup_key = Fernet.generate_key()
        self.manifest_key = secrets.token_bytes(32)
        self.environment_patch = patch.dict(
            os.environ,
            {
                "BACKUP_KEY": self.backup_key.decode("ascii"),
                "BACKUP_MANIFEST_KEY": self.manifest_key.hex(),
                "BACKUP_DIR": str(self.backup_folder),
            },
        )
        self.environment_patch.start()
        self.original_patch = patch.object(
            backup_recovery, "ORIGINAL_FILE", self.original
        )
        self.original_patch.start()
        self.backup, self.manifest = backup_recovery.get_backup_paths()

    def tearDown(self):
        self.original_patch.stop()
        self.environment_patch.stop()
        self.temporary_directory.cleanup()

    def test_backup_is_encrypted_signed_and_restored(self):
        self.assertTrue(backup_recovery.create_backup())
        self.assertNotIn(self.original_bytes, self.backup.read_bytes())

        manifest_data = json.loads(self.manifest.read_text(encoding="utf-8"))
        ciphertext_hash = hashlib.sha256(self.backup.read_bytes()).hexdigest()
        self.assertEqual(manifest_data["ciphertext_sha256"], ciphertext_hash)
        payload = {"ciphertext_sha256": ciphertext_hash}
        canonical_payload = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        expected_hmac = hmac.new(
            self.manifest_key.hex().encode("utf-8"),
            canonical_payload,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(manifest_data["hmac_sha256"], expected_hmac)

        self.original.write_bytes(b"changed source\n")
        self.assertTrue(backup_recovery.restore_backup())
        self.assertEqual(self.original.read_bytes(), self.original_bytes)

    def test_restore_refuses_corrupted_ciphertext(self):
        self.assertTrue(backup_recovery.create_backup())
        self.backup.write_bytes(self.backup.read_bytes() + b"corruption")
        current_source = b"current source\n"
        self.original.write_bytes(current_source)

        self.assertFalse(backup_recovery.restore_backup())
        self.assertEqual(self.original.read_bytes(), current_source)

    def test_manifest_hmac_is_checked_before_decryption(self):
        self.assertTrue(backup_recovery.create_backup())
        manifest_data = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest_data["hmac_sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(manifest_data), encoding="utf-8")

        with patch.object(Fernet, "decrypt") as decrypt:
            self.assertFalse(backup_recovery.restore_backup())

        decrypt.assert_not_called()

    def test_restore_refuses_when_manifest_is_missing(self):
        self.assertTrue(backup_recovery.create_backup())
        self.manifest.unlink()

        self.assertFalse(backup_recovery.restore_backup())

    def test_backup_fails_clearly_when_fernet_key_is_missing(self):
        environment = {
            "BACKUP_KEY": "",
            "BACKUP_MANIFEST_KEY": self.manifest_key.hex(),
            "BACKUP_DIR": str(self.backup_folder),
        }
        output = io.StringIO()
        with patch.dict(os.environ, environment, clear=True):
            with contextlib.redirect_stdout(output):
                self.assertFalse(backup_recovery.create_backup())

        self.assertIn("BACKUP_KEY is required", output.getvalue())

    def test_backup_fails_clearly_when_manifest_key_is_missing(self):
        environment = {
            "BACKUP_KEY": self.backup_key.decode("ascii"),
            "BACKUP_MANIFEST_KEY": "",
            "BACKUP_DIR": str(self.backup_folder),
        }
        output = io.StringIO()
        with patch.dict(os.environ, environment, clear=True):
            with contextlib.redirect_stdout(output):
                self.assertFalse(backup_recovery.create_backup())

        self.assertIn("BACKUP_MANIFEST_KEY is required", output.getvalue())


if __name__ == "__main__":
    unittest.main()
