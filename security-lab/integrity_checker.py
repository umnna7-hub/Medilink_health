
import hashlib
import os

FILE_NAME = "sample_report.txt"
HASH_FILE = "baseline_hash.txt"


def calculate_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        for data in iter(lambda: file.read(4096), b""):
            sha256.update(data)

    return sha256.hexdigest()


def verify_integrity():
    # Create a fictional medical report if it does not exist
    if not os.path.exists(FILE_NAME):
        with open(FILE_NAME, "w") as file:
            file.write("MediLink Health - Dummy Patient Report\n")
            file.write("Patient: Ali Ahmed\n")
            file.write("Diagnosis: Flu\n")

        print("Sample medical report created.")

    current_hash = calculate_hash(FILE_NAME)

    # Save baseline on first run
    if not os.path.exists(HASH_FILE):
        with open(HASH_FILE, "w") as file:
            file.write(current_hash)

        print("Original file hash saved successfully.")
        print("Run again to verify against the saved baseline.")
        return False

    with open(HASH_FILE, "r") as file:
        original_hash = file.read().strip()

    if current_hash == original_hash:
        print("INTEGRITY VERIFIED: File has not been modified.")
        return True

    print("WARNING: File integrity compromised!")
    print("The file has been changed.")
    return False


if __name__ == "__main__":
    verify_integrity()
