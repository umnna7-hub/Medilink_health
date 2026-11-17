
from datetime import datetime, timedelta, timezone

# Simulated vendor access records
access_grants = {}


def grant_access(vendor_id, approved, duration_minutes=30):
    if not approved:
        print("ACCESS DENIED: Approval is required.")
        return

    expiry_time = datetime.now(timezone.utc) + timedelta(
        minutes=duration_minutes
    )

    access_grants[vendor_id] = expiry_time

    print(f"ACCESS GRANTED to {vendor_id}")
    print(f"Access expires at: {expiry_time.isoformat()}")


def check_access(vendor_id, current_time=None):
    if current_time is None:
        current_time = datetime.now(timezone.utc)

    expiry_time = access_grants.get(vendor_id)

    if expiry_time is None:
        print("ACCESS DENIED: No access grant found.")
        return False

    if current_time >= expiry_time:
        print("ACCESS DENIED: Temporary access has expired.")
        return False

    print("ACCESS ALLOWED: Vendor access is active.")
    return True


if __name__ == "__main__":

    vendor = "MSP_Admin_01"

    print("=== MediLink JIT Vendor Access Demo ===\n")

    # Test 1: Access without approval
    print("TEST 1: Unapproved access request")
    grant_access(vendor, approved=False)

    # Test 2: Approved temporary access
    print("\nTEST 2: Approved access request")
    grant_access(vendor, approved=True, duration_minutes=30)

    # Test 3: Check access while active
    print("\nTEST 3: Check active access")
    check_access(vendor)

    # Test 4: Simulate checking after expiry
    print("\nTEST 4: Check access after expiry")
    future_time = datetime.now(timezone.utc) + timedelta(minutes=31)
    check_access(vendor, current_time=future_time)
