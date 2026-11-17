
from flask import Flask, request, jsonify
from lab_database import get_lab_connection, setup_database

app = Flask(__name__)


@app.route("/")
def home():
    return "MediLink Secure SQL Injection Lab"


@app.route("/secure-search", methods=["GET"])
def secure_search():

    # Step 1: Get and validate the patient ID
    try:
        patient_id = int(request.args.get("id", ""))

        if patient_id <= 0:
            return jsonify({
                "status": "error",
                "message": "Patient ID must be a positive number"
            }), 400

    except ValueError:
        return jsonify({
            "status": "error",
            "message": "Invalid patient ID. Enter a number only."
        }), 400

    # Step 2: Connect to database
    connection = get_lab_connection()
    cursor = connection.cursor()

    try:
        # Step 3: Parameterized SQL query
        cursor.execute(
            """
            SELECT patient_id, full_name, email, diagnosis
            FROM patients
            WHERE patient_id = ?
            """,
            (patient_id,)
        )

        results = cursor.fetchall()

        return jsonify({
            "status": "success",
            "patients": results
        })

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    setup_database()
    app.run(host="127.0.0.1", port=5002, debug=False)
