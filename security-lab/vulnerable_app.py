
from flask import Flask, request, jsonify
from lab_database import get_lab_connection, setup_database

app = Flask(__name__)

@app.route("/")
def home():
    return "MediLink SQL Injection Vulnerability Lab"


@app.route("/vulnerable-search", methods=["GET"])
def vulnerable_search():

    patient_id = request.args.get("id", "")

    connection = get_lab_connection()
    cursor = connection.cursor()

    # INTENTIONALLY VULNERABLE: user input is joined into SQL
    query = "SELECT * FROM patients WHERE patient_id = " + patient_id

    try:
        cursor.execute(query)
        results = cursor.fetchall()

        return jsonify({
            "status": "success",
            "patients": results
        })

    except Exception as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    setup_database()
    app.run(host="127.0.0.1", port=5001, debug=False)
