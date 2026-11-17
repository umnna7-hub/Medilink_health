import re
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_ROOT / "backend"
MIGRATION_FILES = (
    "payments.sql",
    "patient_dashboard.sql",
    "login_attempts.sql",
    "mfa_setup.sql",
)
OBJECT_ALREADY_EXISTS_ERRNOS = {1050, 1060, 1061, 1826}

load_dotenv(BACKEND_DIR / ".env")
sys.path.insert(0, str(BACKEND_DIR))

from database import get_db_connection  # noqa: E402
from mysql.connector import Error  # noqa: E402


def _strip_leading_comments(statement):
    remaining = statement.lstrip()
    while remaining:
        if remaining.startswith("--") or remaining.startswith("#"):
            newline = remaining.find("\n")
            if newline == -1:
                return ""
            remaining = remaining[newline + 1:].lstrip()
        elif remaining.startswith("/*"):
            end_comment = remaining.find("*/", 2)
            if end_comment == -1:
                raise ValueError("Unterminated SQL block comment.")
            remaining = remaining[end_comment + 2:].lstrip()
        else:
            break
    return remaining


def _read_migrations():
    migrations = []
    for filename in MIGRATION_FILES:
        path = PROJECT_ROOT / filename
        contents = path.read_text(encoding="utf-8")
        statements = [
            statement.strip()
            for statement in contents.split(";")
            if statement.strip()
        ]
        for statement in statements:
            sql = _strip_leading_comments(statement)
            if re.match(r"^(DROP|DELETE)\b", sql, re.IGNORECASE):
                raise ValueError(
                    f"Refusing forbidden statement in {filename}."
                )
        migrations.append((filename, statements))
    return migrations


def apply_migrations():
    migrations = _read_migrations()
    connection = get_db_connection()
    cursor = None

    try:
        cursor = connection.cursor()
        for filename, statements in migrations:
            print(f"Applying {filename}...")
            applied_count = 0
            skipped_count = 0
            for index, statement in enumerate(statements, start=1):
                try:
                    cursor.execute(statement)
                    connection.commit()
                    applied_count += 1
                except Error as error:
                    if error.errno not in OBJECT_ALREADY_EXISTS_ERRNOS:
                        raise
                    skipped_count += 1
                    print(
                        f"  Skipped statement {index}: object already exists "
                        f"(MySQL error {error.errno})."
                    )

            print(
                f"  Done ({applied_count} applied, {skipped_count} skipped)."
            )
    finally:
        if cursor:
            cursor.close()
        connection.close()


if __name__ == "__main__":
    apply_migrations()
