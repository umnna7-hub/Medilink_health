from database import get_db_connection


def main():
    connection = get_db_connection()
    cursor = None
    try:
        cursor = connection.cursor()
        cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
        row = cursor.fetchone()
        cipher = row[1] if row and len(row) > 1 else ""

        if not cipher:
            print("TLS NOT ACTIVE")
            return 1

        print(f"TLS ACTIVE: {cipher}")
        return 0
    finally:
        if cursor:
            cursor.close()
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
