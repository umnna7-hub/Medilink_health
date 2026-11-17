import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import backup_recovery


def main():
    if not backup_recovery.ORIGINAL_FILE.is_file():
        print("DRILL FAILED: Source file not found.")
        return 1

    backup_root = backup_recovery.get_backup_dir()
    backup_root.mkdir(parents=True, exist_ok=True)
    original_bytes = backup_recovery.ORIGINAL_FILE.read_bytes()

    with tempfile.TemporaryDirectory(
        prefix="backup-drill-", dir=backup_root
    ) as temporary_directory:
        drill_directory = Path(temporary_directory)
        drill_source = drill_directory / backup_recovery.ORIGINAL_FILE.name
        drill_source.write_bytes(original_bytes)
        drill_backup_directory = drill_directory / "backups"

        with patch.object(backup_recovery, "ORIGINAL_FILE", drill_source):
            with patch.dict(
                os.environ, {"BACKUP_DIR": str(drill_backup_directory)}
            ):
                if not backup_recovery.create_backup():
                    print("DRILL FAILED: Could not create the first backup.")
                    return 1

                backup_file, _ = backup_recovery.get_backup_paths()
                backup_file.write_bytes(backup_file.read_bytes() + b"\x00")

                if backup_recovery.restore_backup():
                    print("DRILL FAILED: Corrupted backup was restored.")
                    return 1
                print("Corrupted backup was refused.")

                if not backup_recovery.create_backup():
                    print("DRILL FAILED: Could not create a fresh backup.")
                    return 1

                drill_source.write_bytes(b"Changed data for restore drill.\n")
                if not backup_recovery.restore_backup():
                    print("DRILL FAILED: Fresh backup could not be restored.")
                    return 1

                if drill_source.read_bytes() != original_bytes:
                    print("DRILL FAILED: Restored bytes differ from original.")
                    return 1

                print("Restored bytes match original.")
                print("DRILL PASSED")
                return 0


if __name__ == "__main__":
    raise SystemExit(main())
