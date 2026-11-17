
import sqlite3
from pathlib import Path

DATABASE_FILE = Path(__file__).resolve().parent / "security_lab.db"

def get_lab_connection():
    connection = sqlite3.connect(DATABASE_FILE)
    return connection


def setup_database():
    connection = get_lab_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            diagnosis TEXT NOT NULL
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM patients")
    count = cursor.fetchone()[0]

    if count == 0:
        sample_patients = [
            ("Ali Ahmed", "ali@example.com", "Flu"),
            ("Sara Ahmed", "sara@example.com", "Migraine"),
            ("Usman Khan", "usman@example.com", "Allergy")
        ]

        cursor.executemany("""
            INSERT INTO patients (full_name, email, diagnosis)
            VALUES (?, ?, ?)
        """, sample_patients)

    connection.commit()
    connection.close()


if __name__ == "__main__":
    setup_database()
    print("Security lab database created successfully!")
