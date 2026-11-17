
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path(__file__).parent / "vendor_audit_log.jsonl"


def calculate_hash(record):
    record_text = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    )
    return hashlib.sha256(record_text.encode("utf-8")).hexdigest()


def log_event(vendor_id, action, decision):
    previous_hash = "GENESIS"

    if LOG_FILE.exists():
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()

        if lines:
            previous_record = json.loads(lines[-1])
            previous_hash = previous_record["record_hash"]

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor_id": vendor_id,
        "action": action,
        "decision": decision,
        "previous_hash": previous_hash
    }

    record["record_hash"] = calculate_hash(record)

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")

    print(f"LOGGED: {vendor_id} | {action} | {decision}")


def verify_logs():
    if not LOG_FILE.exists():
        print("No audit log found.")
        return

    previous_hash = "GENESIS"

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            record = json.loads(line)

            saved_hash = record.pop("record_hash")

            if record["previous_hash"] != previous_hash:
                print(f"WARNING: Log chain broken at entry {line_number}")
                return

            calculated_hash = calculate_hash(record)

            if saved_hash != calculated_hash:
                print(f"WARNING: Log modified at entry {line_number}")
                return

            previous_hash = saved_hash

    print("AUDIT VERIFIED: All log entries are intact.")


if __name__ == "__main__":

    print("=== MediLink Vendor Audit Logging Demo ===\n")

    vendor = "MSP_Admin_01"

    # Simulate vendor activities
    log_event(vendor, "Login", "Successful")
    log_event(vendor, "Access Patient Database", "Denied")
    log_event(vendor, "Access Server", "Approved")
    log_event(vendor, "Logout", "Successful")

    print("\nVerifying audit records...")
    verify_logs()
