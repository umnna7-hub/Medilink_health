import re
from getpass import getpass

from mysql.connector import IntegrityError
from werkzeug.security import generate_password_hash

from app import get_db_connection, write_audit_log


def create_first_admin():
    full_name = input("Administrator name: ").strip()
    email = input("Administrator email: ").strip().lower()
    password = getpass("Administrator password: ")
    confirmation = getpass("Confirm password: ")

    if not full_name or len(full_name) > 100:
        raise ValueError("Name must contain 1 to 100 characters.")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")
    if len(email) > 150:
        raise ValueError("Email must be 150 characters or fewer.")
    if not 8 <= len(password) <= 128:
        raise ValueError("Password must be between 8 and 128 characters.")
    if password != confirmation:
        raise ValueError("Passwords do not match.")

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor()
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            connection.rollback()
            raise ValueError("That email address already exists.")

        cursor.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
        if cursor.fetchone():
            connection.rollback()
            raise ValueError("An administrator already exists.")

        cursor.execute(
            """
            INSERT INTO users
                (full_name, email, password_hash, role, account_status)
            VALUES (%s, %s, %s, 'admin', 'active')
            """,
            (full_name, email, generate_password_hash(password))
        )
        admin_id = cursor.lastrowid
        connection.commit()
    except IntegrityError as error:
        if connection:
            connection.rollback()
        raise ValueError("That email address already exists.") from error
    except Exception:
        if connection:
            connection.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    if not write_audit_log(
        admin_id,
        "FIRST_ADMIN_CREATED",
        "user",
        admin_id,
        "The first administrator account was created by the CLI."
    ):
        raise RuntimeError(
            "The admin account was created, but its audit event could not be "
            "written. Check the audit log before continuing."
        )
    print("Administrator created. Complete MFA setup at the next sign-in.")


if __name__ == "__main__":
    try:
        create_first_admin()
    except (RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from error
