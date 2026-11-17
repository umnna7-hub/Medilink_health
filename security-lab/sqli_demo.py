"""Run the same SQL injection payloads against every lab variant.

ISOLATED LAB ONLY: uses a temporary SQLite database with synthetic data and
Flask's in-process test client. No network port is opened.

    python sqli_demo.py             # plain-text table
    python sqli_demo.py --markdown  # Markdown table for the report
"""

import sys
import tempfile
from pathlib import Path

from sqli_comparison import VARIANTS, build_comparison_db, create_app

# (label, field, value, kind) where kind is "legit" or "attack"
CASES = [
    ("Normal ID lookup", "id", "1", "legit"),
    ("ID tautology", "id", "1 OR 1=1", "attack"),
    ("ID UNION theft", "id", "0 UNION SELECT staff_id, username, password_hash, role FROM staff_accounts", "attack"),
    ("ID error probe", "id", "1'", "attack"),
    ("ID stacked statement", "id", "1; DROP TABLE patients", "attack"),
    ("Name with apostrophe", "name", "Liam O'Brien", "legit"),
    ("Name tautology", "name", "' OR '1'='1", "attack"),
    ("Name UNION theft", "name", "' UNION SELECT staff_id, username, password_hash, role FROM staff_accounts --", "attack"),
]

ENDPOINT = {"id": "patient", "name": "search"}
PARAM = {"id": "id", "name": "name"}

LEGEND = {
    "OK": "legitimate request returned the expected record",
    "REJECTED": "legitimate request wrongly refused (false positive)",
    "FAILED": "legitimate request failed (e.g. apostrophe broke the SQL)",
    "STAFF LEAKED": "attacker read the staff_accounts table",
    "ALL PATIENTS": "attacker dumped every patient record",
    "ERROR+LEAK": "attack caused an error and the DB error text was exposed",
    "ERROR": "attack caused a generic error, nothing leaked",
    "SAFE": "attack was treated as plain data, 0 rows",
    "BLOCKED-VALID": "stopped by input validation",
    "BLOCKED-DB": "stopped by database privileges",
}


def classify(kind, status, body):
    blocked_by = body.get("blocked_by")
    rows = body.get("patients") or []

    if kind == "legit":
        if status == 200 and len(rows) == 1:
            return "OK"
        if blocked_by == "validation":
            return "REJECTED"
        return "FAILED"

    if blocked_by == "validation":
        return "BLOCKED-VALID"
    if blocked_by == "database_privileges":
        return "BLOCKED-DB"
    if body.get("status") == "error":
        return "ERROR+LEAK" if "error_detail" in body else "ERROR"
    if any("FAKE_HASH" in str(cell) for row in rows for cell in row):
        return "STAFF LEAKED"
    if rows:
        return "ALL PATIENTS"
    return "SAFE"


def run_matrix():
    with tempfile.TemporaryDirectory() as folder:
        db_path = Path(folder) / "sqli_comparison.db"
        build_comparison_db(db_path)
        client = create_app(db_path).test_client()

        results = []
        for label, field, value, kind in CASES:
            row = [label, kind]
            for variant in VARIANTS:
                response = client.get(
                    f"/{variant}/{ENDPOINT[field]}",
                    query_string={PARAM[field]: value},
                )
                row.append(classify(kind, response.status_code, response.get_json()))
            results.append(row)
        return results


def format_plain(results):
    headers = ["Case", "Kind"] + list(VARIANTS)
    widths = [max(len(str(r[i])) for r in [headers] + results) for i in range(len(headers))]
    lines = [" | ".join(h.ljust(w) for h, w in zip(headers, widths))]
    lines.append("-+-".join("-" * w for w in widths))
    for r in results:
        lines.append(" | ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(lines)


def format_markdown(results):
    headers = ["Case", "Kind"] + list(VARIANTS)
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in results:
        lines.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(lines)


def main():
    results = run_matrix()
    print("LAB ONLY: synthetic data, temporary database, no network port.\n")
    print(format_markdown(results) if "--markdown" in sys.argv else format_plain(results))
    print("\nLegend:")
    for key, text in LEGEND.items():
        print(f"  {key:<14} {text}")


if __name__ == "__main__":
    main()
