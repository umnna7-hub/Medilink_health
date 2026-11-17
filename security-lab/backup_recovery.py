import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

LAB_DIR = Path(__file__).resolve().parent
ORIGINAL_FILE = LAB_DIR / "sample_report.txt"
DEFAULT_BACKUP_DIR = LAB_DIR / "secure_backups"


class BackupConfigurationError(ValueError):
    pass


def get_backup_dir():
    # BACKUP_DIR can point to offline storage, but this path is not immutable storage.
    configured_directory = os.environ.get("BACKUP_DIR")
    if configured_directory:
        return Path(configured_directory).expanduser()
    return DEFAULT_BACKUP_DIR


def get_backup_paths():
    backup_directory = get_backup_dir()
    backup_file = backup_directory / f"{ORIGINAL_FILE.name}.fernet"
    manifest_file = backup_directory / f"{ORIGINAL_FILE.name}.manifest.json"
    return backup_file, manifest_file


def _get_keys():
    backup_key = os.environ.get("BACKUP_KEY")
    if not backup_key:
        raise BackupConfigurationError(
            "BACKUP_KEY is required and must contain a valid Fernet key."
        )

    manifest_key = os.environ.get("BACKUP_MANIFEST_KEY")
    if not manifest_key:
        raise BackupConfigurationError("BACKUP_MANIFEST_KEY is required.")

    try:
        fernet = Fernet(backup_key.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as error:
        raise BackupConfigurationError(
            "BACKUP_KEY must contain a valid Fernet key."
        ) from error

    hmac_key = manifest_key.encode("utf-8")
    if hmac.compare_digest(backup_key.encode("ascii"), hmac_key):
        raise BackupConfigurationError(
            "BACKUP_KEY and BACKUP_MANIFEST_KEY must be different keys."
        )

    return fernet, hmac_key


def _manifest_payload(ciphertext_hash):
    return {"ciphertext_sha256": ciphertext_hash}


def _canonical_manifest_bytes(payload):
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _is_sha256_hex(value):
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def create_backup():
    if not ORIGINAL_FILE.is_file():
        print("ERROR: Source file not found.")
        return False

    try:
        fernet, hmac_key = _get_keys()
    except BackupConfigurationError as error:
        print(f"ERROR: {error}")
        return False

    backup_file, manifest_file = get_backup_paths()
    backup_file.parent.mkdir(parents=True, exist_ok=True)

    ciphertext = fernet.encrypt(ORIGINAL_FILE.read_bytes())
    ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
    payload = _manifest_payload(ciphertext_hash)
    signature = hmac.new(
        hmac_key, _canonical_manifest_bytes(payload), hashlib.sha256
    ).hexdigest()
    manifest = {**payload, "hmac_sha256": signature}

    temporary_backup = backup_file.with_name(backup_file.name + ".tmp")
    temporary_manifest = manifest_file.with_name(manifest_file.name + ".tmp")
    temporary_backup.write_bytes(ciphertext)
    temporary_manifest.write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_backup.replace(backup_file)
    temporary_manifest.replace(manifest_file)

    print("Encrypted backup created successfully.")
    print("Ciphertext hash and signed manifest saved.")
    return True


def restore_backup():
    backup_file, manifest_file = get_backup_paths()
    if not backup_file.is_file() or not manifest_file.is_file():
        print("ERROR: Backup file or signed manifest not found.")
        return False

    try:
        fernet, hmac_key = _get_keys()
    except BackupConfigurationError as error:
        print(f"ERROR: {error}")
        return False

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("WARNING: Signed manifest could not be read.")
        print("Recovery cancelled.")
        return False

    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"ciphertext_sha256", "hmac_sha256"}
        or not isinstance(manifest.get("ciphertext_sha256"), str)
        or not isinstance(manifest.get("hmac_sha256"), str)
        or not _is_sha256_hex(manifest["ciphertext_sha256"])
        or not _is_sha256_hex(manifest["hmac_sha256"])
    ):
        print("WARNING: Signed manifest is invalid.")
        print("Recovery cancelled.")
        return False

    payload = _manifest_payload(manifest["ciphertext_sha256"])
    expected_signature = hmac.new(
        hmac_key, _canonical_manifest_bytes(payload), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(manifest["hmac_sha256"], expected_signature):
        print("WARNING: Manifest HMAC verification failed!")
        print("Recovery cancelled.")
        return False

    ciphertext = backup_file.read_bytes()
    ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
    if not hmac.compare_digest(ciphertext_hash, manifest["ciphertext_sha256"]):
        print("WARNING: Backup ciphertext hash verification failed!")
        print("Recovery cancelled.")
        return False

    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        print("WARNING: Backup decryption failed!")
        print("Recovery cancelled.")
        return False

    ORIGINAL_FILE.write_bytes(plaintext)
    print("Manifest HMAC and ciphertext hash verified.")
    print("Medical report restored successfully!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "restore"))
    args = parser.parse_args()
    succeeded = create_backup() if args.action == "create" else restore_backup()
    raise SystemExit(0 if succeeded else 1)
