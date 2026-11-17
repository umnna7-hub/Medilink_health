"""SQL injection fix comparison lab (Task 3).

ISOLATED LAB ONLY. Uses a throw-away SQLite file with synthetic data and
binds to 127.0.0.1. Do not connect it to hospital systems or real records.

The same two lookups (by patient ID and by patient name) are served by five
variants so each defence can be judged on its own:

    vulnerable            string concatenation, full database access
    validation_only       strict allow-list validation, still concatenates
    parameterized_only    bound parameters, no validation
    least_privilege_only  still concatenates, but the DB connection is
                          read-only and may only read the `patients` table
    combined              format checks + bound parameters + least privilege
                          (IDs must be digits; free-text names are only length
                          checked, because the bound parameter is what makes
                          a name safe, so "O'Brien" keeps working)

Least privilege is simulated with a read-only SQLite connection plus an
authorizer callback, because SQLite has no user accounts. On MySQL the same
idea is expressed with GRANT SELECT on the needed tables only (see
create_app_user.sql).
"""

import os
import re
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

LAB_DIR = Path(__file__).resolve().parent
DEFAULT_DB = LAB_DIR / "sqli_comparison.db"

# validate: False (none), "strict" (allow-list for every field) or
# "format" (allow-list for IDs, length/control-character check for names).
VARIANTS = {
    "vulnerable": {"validate": False, "parameterize": False, "least_privilege": False},
    "validation_only": {"validate": "strict", "parameterize": False, "least_privilege": False},
    "parameterized_only": {"validate": False, "parameterize": True, "least_privilege": False},
    "least_privilege_only": {"validate": False, "parameterize": False, "least_privilege": True},
    "combined": {"validate": "format", "parameterize": True, "least_privilege": True},
}

# Allow-lists. fullmatch is used so a trailing newline cannot slip through.
ID_PATTERN = re.compile(r"[0-9]{1,9}")
NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z .-]{0,99}")

# Columns/tables the application account is allowed to read.
ALLOWED_TABLES = {"patients"}

PATIENT_COLUMNS = "patient_id, full_name, email, diagnosis"


# ---------------------------------------------------------------------------
# Synthetic lab data
# ---------------------------------------------------------------------------

def build_comparison_db(db_path):
    """Create a fresh lab database containing only synthetic records."""
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()

    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE patients (
                patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                diagnosis TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE staff_accounts (
                staff_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO patients (full_name, email, diagnosis) VALUES (?, ?, ?)",
            [
                ("Ali Ahmed", "ali@example.test", "Flu"),
                ("Sara Ahmed", "sara@example.test", "Migraine"),
                ("Usman Khan", "usman@example.test", "Allergy"),
                ("Liam O'Brien", "liam@example.test", "Asthma"),
                ("Ayesha Noor", "ayesha@example.test", "Fracture"),
            ],
        )
        connection.executemany(
            "INSERT INTO staff_accounts (username, password_hash, role) VALUES (?, ?, ?)",
            [
                ("lab_admin", "FAKE_HASH_synthetic_1", "admin"),
                ("lab_doctor", "FAKE_HASH_synthetic_2", "doctor"),
            ],
        )
        connection.commit()
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Connections: full access vs least privilege
# ---------------------------------------------------------------------------

def _least_privilege_authorizer(action, arg1, arg2, dbname, source):
    """Permit only SELECT statements that read the allowed tables."""
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and arg1 in ALLOWED_TABLES:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def connect_full_access(db_path):
    return sqlite3.connect(db_path)


def connect_least_privilege(db_path):
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.set_authorizer(_least_privilege_authorizer)
    return connection


# ---------------------------------------------------------------------------
# Query handling
# ---------------------------------------------------------------------------

def _is_valid(mode, field, value):
    if field == "id":
        return ID_PATTERN.fullmatch(value) is not None
    if mode == "strict":
        return NAME_PATTERN.fullmatch(value) is not None
    # "format": length and control characters only; safety comes from binding.
    return 1 <= len(value) <= 100 and value.isprintable()


def run_lookup(variant, field, value, db_path):
    """Run one lookup and return (http_status, json_payload).

    `field` is "id" or "name". The payload includes `blocked_by` so the demo
    can show which layer stopped a request. Only the deliberately vulnerable
    variant returns raw database error text.
    """
    options = VARIANTS[variant]
    value = value or ""

    if options["validate"] and not _is_valid(options["validate"], field, value):
        return 400, {
            "status": "error",
            "blocked_by": "validation",
            "message": "Invalid input.",
        }

    if options["parameterize"]:
        if field == "id":
            sql = f"SELECT {PATIENT_COLUMNS} FROM patients WHERE patient_id = ?"
        else:
            sql = f"SELECT {PATIENT_COLUMNS} FROM patients WHERE full_name = ?"
        params = (value,)
    else:
        # INTENTIONALLY UNSAFE in every variant that does not parameterize.
        if field == "id":
            sql = f"SELECT {PATIENT_COLUMNS} FROM patients WHERE patient_id = " + value
        else:
            sql = f"SELECT {PATIENT_COLUMNS} FROM patients WHERE full_name = '" + value + "'"
        params = ()

    connect = (
        connect_least_privilege if options["least_privilege"] else connect_full_access
    )
    connection = connect(db_path)
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return 200, {"status": "success", "patients": rows}
    except (sqlite3.Error, sqlite3.Warning) as error:
        text = str(error)
        # SQLite words an authorizer denial as "not authorized" or
        # "access to <table.column> is prohibited" depending on the version.
        if "not authorized" in text or "prohibited" in text:
            return 403, {
                "status": "error",
                "blocked_by": "database_privileges",
                "message": "Request could not be processed.",
            }
        payload = {"status": "error", "message": "Request could not be processed."}
        if variant == "vulnerable":
            payload["error_detail"] = text  # information leak, on purpose
        return 400, payload
    finally:
        cursor.close()
        connection.close()


# ---------------------------------------------------------------------------
# Flask app (loopback only)
# ---------------------------------------------------------------------------

def create_app(db_path=DEFAULT_DB):
    app = Flask(__name__)

    @app.route("/")
    def home():
        return "MediLink SQL Injection Fix Comparison Lab"

    @app.route("/<variant>/patient")
    def patient_by_id(variant):
        if variant not in VARIANTS:
            return jsonify({"status": "error", "message": "Unknown variant"}), 404
        status, payload = run_lookup(variant, "id", request.args.get("id", ""), db_path)
        return jsonify(payload), status

    @app.route("/<variant>/search")
    def patient_by_name(variant):
        if variant not in VARIANTS:
            return jsonify({"status": "error", "message": "Unknown variant"}), 404
        status, payload = run_lookup(
            variant, "name", request.args.get("name", ""), db_path
        )
        return jsonify(payload), status

    return app


if __name__ == "__main__":
    database = Path(os.environ.get("SQLI_LAB_DB", DEFAULT_DB))
    build_comparison_db(database)
    create_app(database).run(host="127.0.0.1", port=5004, debug=False)
