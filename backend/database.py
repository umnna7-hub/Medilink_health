
import os
import mysql.connector
from dotenv import load_dotenv

# Load database settings from .env
load_dotenv()


def get_db_connection():
    ssl_options = {}
    if os.getenv("DB_SSL", "false").strip().lower() == "true":
        ssl_options["ssl_disabled"] = False
        ca_path = os.getenv("DB_SSL_CA", "").strip()
        if ca_path:
            ssl_options["ssl_ca"] = ca_path

    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        **ssl_options
    )
