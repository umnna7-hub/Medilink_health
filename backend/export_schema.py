# export_schema.py
# Exports table structure only (no row data) from the database in backend/.env.
from database import get_db_connection

OUT_FILE = "../schema.sql"  # writes to the project root


def main():
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")
    tables = [row[0] for row in cursor.fetchall()]

    lines = [
        "-- MediLink Health schema, exported from the working database.",
        "-- Structure only. Contains no patient or user data.",
        "SET FOREIGN_KEY_CHECKS=0;",
        "",
    ]

    for table in tables:
        cursor.execute(f"SHOW CREATE TABLE `{table}`")
        _, ddl = cursor.fetchone()
        ddl = ddl.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)
        lines.append(ddl + ";")
        lines.append("")

    lines.append("SET FOREIGN_KEY_CHECKS=1;")

    with open(OUT_FILE, "w", encoding="utf-8", newline="\n") as file:
        file.write("\n".join(lines))

    cursor.close()
    connection.close()
    print(f"Exported {len(tables)} tables to {OUT_FILE}")
    print("Tables:", ", ".join(tables))


if __name__ == "__main__":
    main()