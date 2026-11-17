from flask import Flask, jsonify, request
from flask_cors import CORS
from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import IntegrityError
from functools import wraps
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import json
import logging
import jwt
import os
import pyotp
import re
import time
import uuid
from pathlib import Path
from urllib.parse import unquote_plus

app = Flask(__name__)

if not any(
    isinstance(handler, logging.FileHandler)
    for handler in app.logger.handlers
):
    log_file = Path(
        os.getenv("LOG_FILE") or Path(__file__).with_name("app.log")
    ).expanduser()
    if not log_file.is_absolute():
        log_file = Path(__file__).parent / log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"
    )
    file_formatter.converter = time.gmtime
    file_handler.setFormatter(file_formatter)
    app.logger.addHandler(file_handler)

# Only allow the local React frontend during development.
CORS(
    app,
    resources={r"/api/*": {
        "origins": [os.getenv("CORS_ORIGIN", "http://localhost:5173")]
    }},
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True
)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["DEMO_MODE"] = os.getenv(
    "DEMO_MODE", "false"
).strip().lower() in {"1", "true", "yes", "on"}

# Do not start the application with an unset or weak JWT secret.
if not app.config["JWT_SECRET_KEY"] or len(app.config["JWT_SECRET_KEY"]) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY is missing or too short. "
        "Set a random secret of at least 32 characters in your environment."
    )

try:
    APPOINTMENT_FEE = Decimal(
        os.getenv("APPOINTMENT_FEE", "1000.00")
    ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
except InvalidOperation as error:
    raise RuntimeError("APPOINTMENT_FEE must be a valid decimal amount.") from error

if (
    not APPOINTMENT_FEE.is_finite()
    or APPOINTMENT_FEE <= 0
    or APPOINTMENT_FEE > Decimal("99999999.99")
):
    raise RuntimeError(
        "APPOINTMENT_FEE must be between 0.01 and 99999999.99."
    )

PAYMENT_CURRENCY = os.getenv("PAYMENT_CURRENCY", "PKR").strip().upper()
if not re.fullmatch(r"[A-Z]{3}", PAYMENT_CURRENCY):
    raise RuntimeError("PAYMENT_CURRENCY must be a three-letter currency code.")

PAYMENT_SIMULATION_RESULT = os.getenv(
    "PAYMENT_SIMULATION_RESULT", "successful"
).strip().lower()
if PAYMENT_SIMULATION_RESULT not in {"successful", "failed"}:
    raise RuntimeError(
        "PAYMENT_SIMULATION_RESULT must be 'successful' or 'failed'."
    )

SQL_META_PATTERN = re.compile(r"'|--|\bunion\b", re.IGNORECASE)


@app.before_request
def log_sql_metacharacter_request():
    decoded_target = unquote_plus(request.full_path)
    match = SQL_META_PATTERN.search(decoded_target)
    if match:
        marker = match.group(0).lower()
        marker_name = {
            "'": "quote",
            "--": "comment",
            "union": "union",
        }[marker]
        app.logger.warning(
            "SQL_META_REQUEST ip=%s method=%s marker=%s",
            request.remote_addr or "unknown",
            request.method,
            marker_name,
        )


@app.after_request
def log_http_429(response):
    if response.status_code == 429:
        app.logger.warning(
            "HTTP_429 ip=%s method=%s",
            request.remote_addr or "unknown",
            request.method,
        )
    return response


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def api_error(message, status_code):
    return jsonify({"status": "error", "message": message}), status_code


def record_failed_login(cursor, connection, email):
    cursor.execute(
        """
        INSERT INTO login_attempts (email, failed_count, locked_until)
        VALUES (%s, 1, NULL)
        ON DUPLICATE KEY UPDATE
            failed_count = failed_count + 1
        """,
        (email,)
    )
    cursor.execute(
        """
        UPDATE login_attempts
        SET locked_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)
        WHERE email = %s
          AND failed_count >= 5
          AND locked_until IS NULL
        """,
        (email,)
    )
    connection.commit()


def log_failed_login_attempt(email):
    app.logger.warning(
        "AUTH_FAILURE email=%s",
        json.dumps(email[:254], ensure_ascii=True),
    )


def write_audit_log(
    actor_user_id,
    action,
    target_type=None,
    target_id=None,
    event_details=None
):
    """
    Write an audit event in its own short transaction.
    Never include passwords, JWTs, or other authentication secrets.
    """
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs
                (actor_user_id, action, target_type, target_id,
                 event_details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                actor_user_id,
                action,
                target_type,
                str(target_id) if target_id is not None else None,
                event_details,
                request.remote_addr
            )
        )
        connection.commit()
        return True
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Unable to write security audit event")
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def role_required(*allowed_roles):
    """Role check to use after @token_required."""
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if request.current_user.get("role") not in allowed_roles:
                return api_error("You are not authorized to perform this action", 403)
            return function(*args, **kwargs)
        return wrapper
    return decorator


def token_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if auth_header is None:
            token = request.cookies.get("medilink_session", "")
        elif auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        else:
            token = ""

        if not token:
            return api_error("Authentication token is required", 401)

        connection = None
        cursor = None

        try:
            payload = jwt.decode(
                token,
                app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
                options={"require": ["sub", "role", "jti", "exp"]}
            )

            # The subject is issued as a string user ID at login.
            try:
                user_id = int(payload["sub"])
            except (TypeError, ValueError):
                return api_error("Invalid authentication token", 401)

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            # Check revocation AND current account status/role on every
            # protected request. This invalidates old tokens after changes.
            cursor.execute(
                """
                SELECT token_id
                FROM revoked_tokens
                WHERE token_id = %s
                """,
                (payload["jti"],)
            )
            if cursor.fetchone():
                return api_error(
                    "Session has been revoked. Please log in again.", 401
                )

            cursor.execute(
                """
                SELECT user_id, role, account_status
                FROM users
                WHERE user_id = %s
                """,
                (user_id,)
            )
            account = cursor.fetchone()

            if not account:
                return api_error("Account not found", 401)

            if account["account_status"] != "active":
                return api_error(
                    "Your account is inactive. Please contact the administrator.",
                    403
                )

            # Do not trust an old role claim if an administrator changed
            # the user's role after the token was issued.
            if account["role"] != payload["role"]:
                return api_error(
                    "Your account permissions have changed. Please log in again.",
                    401
                )

            request.current_user = {
                "sub": str(account["user_id"]),
                "role": account["role"],
                "jti": payload["jti"],
                "exp": payload["exp"]
            }

        except jwt.ExpiredSignatureError:
            return api_error("Token has expired", 401)
        except jwt.InvalidTokenError:
            return api_error("Invalid authentication token", 401)
        except Exception:
            app.logger.exception("Authentication session verification failed")
            return api_error("Unable to verify authentication session", 503)
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        return function(*args, **kwargs)

    return wrapper


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ---------------------------------------------------------------------------
# Health and public information
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return jsonify({
        "message": "Welcome to MediLink Health",
        "status": "Backend is running"
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "healthy", "project": "MediLink Health"})


@app.route("/api/db-health")
def database_health():
    connection = None
    try:
        connection = get_db_connection()
        return jsonify({
            "status": "success",
            "message": "MediLink MySQL database connected!"
        })
    except Exception:
        app.logger.exception("Database health check failed")
        return api_error("Database connection failed. Check configuration.", 500)
    finally:
        if connection:
            connection.close()


@app.route("/api/doctors", methods=["GET"])
def get_doctors():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                d.doctor_id,
                d.full_name,
                d.specialty,
                d.hospital_id,
                h.hospital_name,
                h.city AS hospital_city,
                d.is_active
            FROM doctors d
            INNER JOIN hospitals h ON h.hospital_id = d.hospital_id
            WHERE d.is_active = TRUE AND h.is_active = TRUE
            ORDER BY d.full_name
            """
        )
        return jsonify({"status": "success", "doctors": cursor.fetchall()})
    except Exception:
        app.logger.exception("Unable to retrieve doctors")
        return api_error("Unable to retrieve doctors", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/hospitals", methods=["GET"])
def get_hospitals():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                hospital_id, branch_code, hospital_name, city, address,
                is_active
            FROM hospitals
            WHERE is_active = TRUE
            ORDER BY hospital_name
            """
        )
        return jsonify({"status": "success", "hospitals": cursor.fetchall()})
    except Exception:
        app.logger.exception("Unable to retrieve hospitals")
        return api_error("Unable to retrieve hospitals", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/laboratories", methods=["GET"])
def get_laboratories():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                l.lab_id, l.lab_code, l.lab_name, l.city,
                l.hospital_id, h.hospital_name, l.is_active
            FROM diagnostic_labs l
            INNER JOIN hospitals h ON h.hospital_id = l.hospital_id
            WHERE l.is_active = TRUE AND h.is_active = TRUE
            ORDER BY l.lab_name
            """
        )
        return jsonify({
            "status": "success",
            "laboratories": cursor.fetchall()
        })
    except Exception:
        app.logger.exception("Unable to retrieve laboratories")
        return api_error("Unable to retrieve laboratories", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Patient registration and login
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register_patient():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("Valid JSON data is required", 400)

    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")

    if not all(isinstance(value, str) for value in (full_name, email, password)):
        return api_error("All fields must contain valid text", 400)

    full_name = full_name.strip()
    email = email.strip().lower()

    if not full_name or not email or not password:
        return api_error("All fields are required", 400)
    if len(full_name) > 100 or len(email) > 150:
        return api_error("Name or email exceeds the allowed length", 400)
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return api_error("Please enter a valid email address", 400)
    if len(password) < 8 or len(password) > 128:
        return api_error("Password must be between 8 and 128 characters", 400)

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO users
                (full_name, email, password_hash, role, account_status)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                full_name,
                email,
                generate_password_hash(password),
                "patient",
                "active"
            )
        )
        new_user_id = cursor.lastrowid
        connection.commit()

        write_audit_log(
            new_user_id, "PATIENT_REGISTERED", "user", new_user_id,
            "A patient account was registered."
        )
        return jsonify({
            "status": "success",
            "message": "Patient registered successfully"
        }), 201

    except IntegrityError:
        if connection:
            connection.rollback()
        return api_error("This email is already registered", 409)
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Patient registration failed")
        return api_error("Registration failed", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/login", methods=["POST"])
def login_patient():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("JSON data is required", 400)

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return api_error("Email and password are required", 400)

    email = email.strip().lower()
    if not email or not password:
        return api_error("Email and password are required", 400)

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT failed_count, locked_until
            FROM login_attempts
            WHERE email = %s
            """,
            (email,)
        )
        login_attempt = cursor.fetchone()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if login_attempt and login_attempt["locked_until"]:
            if login_attempt["locked_until"] > now:
                return api_error(
                    "Too many failed attempts. Try again later.",
                    429
                )
            cursor.execute(
                """
                UPDATE login_attempts
                SET failed_count = 0, locked_until = NULL
                WHERE email = %s
                """,
                (email,)
            )

        cursor.execute(
            """
            SELECT user_id, full_name, email, password_hash,
                   role, account_status, mfa_secret
            FROM users
            WHERE email = %s
            """,
            (email,)
        )
        user = cursor.fetchone()
        # Use the same message for unknown email and incorrect password.
        account_found = user is not None
        password_matches = (
             check_password_hash(user["password_hash"], password)
            if account_found else False
        )

        if not account_found or not password_matches:
            record_failed_login(cursor, connection, email)
            log_failed_login_attempt(email)
            return api_error("Invalid email or password", 401)

        if user["account_status"] != "active":
            return api_error(
                "Your account is inactive. Please contact the administrator.",
                403
            )

        mfa_secret = user.get("mfa_secret")
        if (
            user["role"] in {"admin", "doctor"}
            and mfa_secret is not None
        ):
            totp_code = data.get("totp_code")
            try:
                valid_totp = (
                    isinstance(totp_code, str)
                    and pyotp.TOTP(mfa_secret).verify(
                        totp_code.strip(), valid_window=1
                    )
                )
            except (TypeError, ValueError):
                valid_totp = False

            if not valid_totp:
                record_failed_login(cursor, connection, email)
                log_failed_login_attempt(email)
                return api_error("Invalid email or password", 401)

        cursor.execute(
            """
            UPDATE login_attempts
            SET failed_count = 0, locked_until = NULL
            WHERE email = %s
            """,
            (email,)
        )
        connection.commit()

        token = jwt.encode(
            {
                "sub": str(user["user_id"]),
                "role": user["role"],
                "jti": str(uuid.uuid4()),
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
            },
            app.config["JWT_SECRET_KEY"],
            algorithm="HS256"
        )

        write_audit_log(
            user["user_id"], "LOGIN_SUCCESS", "user", user["user_id"],
            "User authenticated successfully."
        )

        response = jsonify({
            "status": "success",
            "message": "Login successful",
            "user": {
                "user_id": user["user_id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "role": user["role"]
            }
        })
        response.set_cookie(
            "medilink_session",
            token,
            max_age=30 * 60,
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        return response, 200

    except Exception:
        app.logger.exception("Login failed")
        return api_error("Login failed", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/mfa/enroll", methods=["POST"])
@token_required
@role_required("admin", "doctor")
def enroll_mfa():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        user_id = int(request.current_user["sub"])
        cursor.execute(
            """
            SELECT email, mfa_secret
            FROM users
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user_id,)
        )
        user = cursor.fetchone()
        if not user:
            connection.rollback()
            return api_error("Account not found", 404)

        if user["mfa_secret"] is not None:
            connection.rollback()
            return api_error("MFA is already enrolled", 409)

        secret = pyotp.random_base32()
        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=user["email"],
            issuer_name="MediLink Health"
        )
        cursor.execute(
            """
            UPDATE users
            SET mfa_secret = %s
            WHERE user_id = %s AND mfa_secret IS NULL
            """,
            (secret, user_id)
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return api_error("MFA is already enrolled", 409)

        connection.commit()
        write_audit_log(
            user_id,
            "MFA_ENROLL",
            "user",
            user_id,
            "Authenticator-app MFA enrolled."
        )

        response = jsonify({
            "status": "success",
            "provisioning_uri": provisioning_uri
        })
        response.headers["Cache-Control"] = "no-store"
        return response, 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.error("MFA enrollment failed")
        return api_error("Unable to enroll in MFA", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Logout and patient profile
# ---------------------------------------------------------------------------

@app.route("/api/logout", methods=["POST"])
@token_required
def logout_patient():
    token_id = request.current_user["jti"]
    expires_at = datetime.fromtimestamp(
        request.current_user["exp"], timezone.utc
    ).replace(tzinfo=None)

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO revoked_tokens (token_id, expires_at)
            VALUES (%s, %s)
            """,
            (token_id, expires_at)
        )
        connection.commit()

        user_id = int(request.current_user["sub"])
        write_audit_log(
            user_id, "LOGOUT", "user", user_id,
            "User logged out and token was revoked."
        )
        response = jsonify({
            "status": "success",
            "message": "Logged out successfully"
        })
        response.delete_cookie(
            "medilink_session",
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        return response, 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Logout failed")
        return api_error("Unable to complete logout", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/patient/profile", methods=["GET"])
@token_required
@role_required("patient")
def patient_profile():
    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT full_name, email, account_status, created_at
            FROM users
            WHERE user_id = %s AND role = 'patient'
            """,
            (patient_id,)
        )
        profile = cursor.fetchone()
        if not profile:
            return api_error("Patient profile not found", 404)

        return jsonify({"status": "success", "profile": profile}), 200
    except Exception:
        app.logger.exception("Unable to retrieve patient profile")
        return api_error("Unable to retrieve patient profile", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Patient appointments
# ---------------------------------------------------------------------------

@app.route("/api/patient/payment-config", methods=["GET"])
@token_required
@role_required("patient")
def patient_payment_config():
    return jsonify({
        "status": "success",
        "payment_mode": "simulation",
        "appointment_fee": format(APPOINTMENT_FEE, ".2f"),
        "currency": PAYMENT_CURRENCY,
        "notice": "Payment simulation only. No real payment will be charged."
    }), 200


@app.route("/api/appointments", methods=["POST"])
@token_required
@role_required("patient")
def book_appointment():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("JSON data is required", 400)

    doctor_id = data.get("doctor_id")
    hospital_id = data.get("hospital_id")
    appointment_date = data.get("appointment_date")
    reason = data.get("reason")

    if (
        isinstance(doctor_id, bool)
        or isinstance(hospital_id, bool)
        or not isinstance(reason, str)
        or not isinstance(appointment_date, str)
    ):
        return api_error(
            "Hospital, doctor, appointment date, and reason are required", 400
        )
    reason = reason.strip()
    if not reason or len(reason) > 255:
        return api_error("Reason must be between 1 and 255 characters", 400)

    try:
        doctor_id = int(doctor_id)
        hospital_id = int(hospital_id)
        if doctor_id <= 0 or hospital_id <= 0:
            raise ValueError()
        appointment_datetime = datetime.fromisoformat(appointment_date)
        if appointment_datetime.tzinfo is not None:
            appointment_datetime = appointment_datetime.astimezone(
                timezone.utc
            ).replace(tzinfo=None)
        current_utc_time = datetime.now(timezone.utc).replace(tzinfo=None)
        if appointment_datetime <= current_utc_time:
            return api_error(
                "Please select a future appointment date and time", 400
            )
    except (ValueError, TypeError):
        return api_error("Invalid doctor ID or appointment date", 400)

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT d.doctor_id
            FROM doctors d
            INNER JOIN hospitals h ON h.hospital_id = d.hospital_id
            WHERE d.doctor_id = %s
              AND d.hospital_id = %s
              AND d.is_active = TRUE
              AND h.is_active = TRUE
            """,
            (doctor_id, hospital_id)
        )
        if not cursor.fetchone():
            return api_error(
                "Selected doctor or hospital is unavailable", 404
            )

        # Patient ID comes from the verified JWT, never from request JSON.
        patient_id = int(request.current_user["sub"])
        cursor.execute(
            """
            INSERT INTO appointments
                (patient_id, doctor_id, appointment_date, reason, status)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                patient_id, doctor_id, appointment_datetime,
                reason, "Pending"
            )
        )
        appointment_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO payments
                (patient_id, appointment_id, amount, currency, status, provider)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                patient_id,
                appointment_id,
                APPOINTMENT_FEE,
                PAYMENT_CURRENCY,
                "Pending",
                "simulation"
            )
        )
        payment_id = cursor.lastrowid
        connection.commit()

        write_audit_log(
            patient_id, "APPOINTMENT_BOOKED", "appointment", appointment_id,
            "Patient booked an appointment."
        )
        write_audit_log(
            patient_id, "PAYMENT_PENDING", "payment", payment_id,
            (
                f"Payment created for appointment {appointment_id}: "
                f"{format(APPOINTMENT_FEE, '.2f')} {PAYMENT_CURRENCY}. "
                "Payment simulation only."
            )
        )
        return jsonify({
            "status": "success",
            "message": "Appointment booked successfully",
            "appointment_id": appointment_id,
            "payment": {
                "payment_id": payment_id,
                "amount": format(APPOINTMENT_FEE, ".2f"),
                "currency": PAYMENT_CURRENCY,
                "status": "Pending",
                "provider": "simulation"
            }
        }), 201
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Appointment booking failed")
        return api_error("Unable to book appointment", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/patient/payments", methods=["GET"])
@token_required
@role_required("patient")
def get_patient_payments():
    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                p.payment_id,
                p.appointment_id,
                CAST(p.amount AS CHAR) AS amount,
                p.currency,
                p.status,
                p.provider,
                p.created_at,
                a.appointment_date,
                d.full_name AS doctor_name,
                d.specialty AS doctor_specialty
            FROM payments p
            INNER JOIN appointments a
                ON a.appointment_id = p.appointment_id
            INNER JOIN doctors d ON d.doctor_id = a.doctor_id
            WHERE p.patient_id = %s
            ORDER BY p.created_at DESC, p.payment_id DESC
            """,
            (patient_id,)
        )
        return jsonify({
            "status": "success",
            "payments": cursor.fetchall()
        }), 200
    except Exception:
        app.logger.exception("Unable to retrieve patient payment history")
        return api_error("Unable to retrieve payment history", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/patient/payments/<int:payment_id>/simulate",
    methods=["POST"]
)
@token_required
@role_required("patient")
def simulate_patient_payment(payment_id):
    if not app.config["DEMO_MODE"]:
        return api_error("Payment simulation is disabled", 403)

    if request.get_data(cache=False):
        return api_error(
            "The payment simulation does not accept a client-supplied result",
            400
        )

    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT payment_id, appointment_id, amount, currency, status
            FROM payments
            WHERE payment_id = %s AND patient_id = %s
            FOR UPDATE
            """,
            (payment_id, patient_id)
        )
        payment = cursor.fetchone()
        if not payment:
            connection.rollback()
            return api_error("Payment not found", 404)

        if payment["status"] == "Successful":
            connection.rollback()
            return api_error("This payment has already succeeded", 409)

        payment_status = (
            "Successful"
            if PAYMENT_SIMULATION_RESULT == "successful"
            else "Failed"
        )
        cursor.execute(
            """
            UPDATE payments
            SET status = %s
            WHERE payment_id = %s AND patient_id = %s
            """,
            (payment_status, payment_id, patient_id)
        )
        connection.commit()

        write_audit_log(
            patient_id, "PAYMENT_SIMULATION_RESULT", "payment", payment_id,
            (
                f"Payment simulation returned {payment_status} for "
                f"{format(Decimal(payment['amount']), '.2f')} "
                f"{payment['currency']}."
            )
        )
        return jsonify({
            "status": "success",
            "message": "Payment simulation completed",
            "payment": {
                "payment_id": payment_id,
                "appointment_id": payment["appointment_id"],
                "amount": format(Decimal(payment["amount"]), ".2f"),
                "currency": payment["currency"],
                "status": payment_status,
                "provider": "simulation"
            }
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Payment simulation failed")
        return api_error("Unable to complete payment simulation", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/patient/appointments", methods=["GET"])
@token_required
@role_required("patient")
def get_patient_appointments():
    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                a.appointment_id, a.appointment_date, a.reason, a.status,
                d.full_name AS doctor_name,
                d.specialty AS doctor_specialty,
                h.hospital_name,
                h.city AS hospital_city
            FROM appointments a
            INNER JOIN doctors d ON a.doctor_id = d.doctor_id
            LEFT JOIN hospitals h ON d.hospital_id = h.hospital_id
            WHERE a.patient_id = %s
            ORDER BY a.appointment_date DESC
            """,
            (patient_id,)
        )
        return jsonify({
            "status": "success",
            "appointments": cursor.fetchall()
        }), 200
    except Exception:
        app.logger.exception("Unable to retrieve patient appointments")
        return api_error("Unable to retrieve appointments", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/patient/appointments/<int:appointment_id>/cancel",
    methods=["PATCH"]
)
@token_required
@role_required("patient")
def cancel_appointment(appointment_id):
    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE appointments
            SET status = %s
            WHERE appointment_id = %s
              AND patient_id = %s
              AND status IN ('Pending', 'Confirmed')
            """,
            ("Cancelled", appointment_id, patient_id)
        )
        if cursor.rowcount == 0:
            connection.rollback()
            return api_error(
                "Appointment not found or cannot be cancelled", 404
            )
        connection.commit()

        write_audit_log(
            patient_id, "APPOINTMENT_CANCELLED", "appointment",
            appointment_id, "Patient cancelled an appointment."
        )
        return jsonify({
            "status": "success",
            "message": "Appointment cancelled successfully"
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Appointment cancellation failed")
        return api_error("Unable to cancel appointment", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Patient medical records and lab reports
# ---------------------------------------------------------------------------

@app.route("/api/patient/medical-records", methods=["GET"])
@token_required
@role_required("patient")
def get_patient_medical_records():
    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                mr.record_id, mr.diagnosis, mr.treatment,
                mr.prescription, mr.record_date,
                d.full_name AS doctor_name,
                d.specialty AS doctor_specialty
            FROM medical_records mr
            INNER JOIN doctors d ON mr.doctor_id = d.doctor_id
            WHERE mr.patient_id = %s
            ORDER BY mr.record_date DESC
            """,
            (patient_id,)
        )
        return jsonify({
            "status": "success",
            "medical_records": cursor.fetchall()
        }), 200
    except Exception:
        app.logger.exception("Unable to retrieve medical records")
        return api_error("Unable to retrieve medical records", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/patient/lab-reports", methods=["GET"])
@token_required
@role_required("patient")
def get_patient_lab_reports():
    connection = None
    cursor = None
    try:
        patient_id = int(request.current_user["sub"])
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                lr.report_id, lr.test_name, lr.test_result,
                lr.notes, lr.report_date,
                d.full_name AS doctor_name,
                d.specialty AS doctor_specialty,
                l.lab_name,
                h.hospital_name
            FROM lab_reports lr
            INNER JOIN doctors d ON lr.doctor_id = d.doctor_id
            LEFT JOIN diagnostic_labs l ON lr.lab_id = l.lab_id
            LEFT JOIN hospitals h ON l.hospital_id = h.hospital_id
            WHERE lr.patient_id = %s
            ORDER BY lr.report_date DESC
            """,
            (patient_id,)
        )
        return jsonify({
            "status": "success",
            "lab_reports": cursor.fetchall()
        }), 200
    except Exception:
        app.logger.exception("Unable to retrieve lab reports")
        return api_error("Unable to retrieve lab reports", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Administrator account management
# ---------------------------------------------------------------------------

@app.route("/api/admin/users", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_users():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        role_filter = request.args.get("role", "").strip().lower()
        status_filter = request.args.get("status", "").strip().lower()
        if role_filter not in {"", "patient", "doctor", "admin"}:
            return api_error("role is invalid", 400)
        if status_filter not in {"", "active", "suspended", "deactivated"}:
            return api_error("status is invalid", 400)

        conditions = []
        params = []
        if query:
            like = f"%{query}%"
            conditions.append(
                "(full_name LIKE %s OR email LIKE %s OR role LIKE %s)"
            )
            params.extend((like, like, like))
        if role_filter:
            conditions.append("role = %s")
            params.append(role_filter)
        if status_filter:
            conditions.append("account_status = %s")
            params.append(status_filter)
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                user_id, full_name, email, role,
                account_status, created_at, status_changed_at
            FROM users
            WHERE {where_sql}
            ORDER BY user_id
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "users": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Administrator could not list users")
        return api_error("Unable to retrieve users", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def _set_admin_user_status(user_id, new_status, admin_id, soft_delete=False):
    if user_id == admin_id and new_status != "active":
        return api_error("You cannot suspend or deactivate your own account", 400)

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT user_id, account_status
            FROM users
            WHERE role = 'admin'
            ORDER BY user_id
            FOR UPDATE
            """
        )
        admin_rows = cursor.fetchall()
        cursor.execute(
            """
            SELECT user_id, role, account_status
            FROM users WHERE user_id = %s FOR UPDATE
            """,
            (user_id,)
        )
        target = cursor.fetchone()
        if not target:
            connection.rollback()
            return api_error("User not found", 404)

        if target["role"] == "admin" and target["account_status"] == "active" \
                and new_status != "active":
            remaining_active_admins = sum(
                row["user_id"] != user_id and row["account_status"] == "active"
                for row in admin_rows
            )
            if remaining_active_admins == 0:
                connection.rollback()
                return api_error(
                    "The last active administrator cannot be deactivated", 409
                )

        cursor.execute(
            """
            UPDATE users
            SET account_status = %s,
                status_changed_at = CURRENT_TIMESTAMP
            WHERE user_id = %s
            """,
            (new_status, user_id)
        )
        if target["role"] == "doctor":
            cursor.execute(
                "UPDATE doctors SET is_active = %s WHERE user_id = %s",
                (new_status == "active", user_id)
            )
        connection.commit()

        action = "USER_SOFT_DELETED" if soft_delete else "USER_STATUS_CHANGED"
        details = (
            "Administrator deactivated the account. Medical history retained."
            if soft_delete else
            "Account status changed to " + new_status + "."
        )
        write_audit_log(admin_id, action, "user", user_id, details)
        message = (
            "User account deactivated. Medical records and appointment "
            "history have been preserved."
            if soft_delete else "User account status updated"
        )
        return jsonify({
            "status": "success",
            "message": message,
            "user_id": user_id,
            "account_status": new_status
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Administrator account-status update failed")
        return api_error("Unable to update account status", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/users/<int:user_id>/status", methods=["PATCH"])
@token_required
@role_required("admin")
def admin_update_user_status(user_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("Valid JSON data is required", 400)

    new_status = data.get("account_status")
    allowed_statuses = {"active", "suspended", "deactivated"}

    if new_status not in allowed_statuses:
        return api_error(
            "account_status must be active, suspended, or deactivated", 400
        )

    admin_id = int(request.current_user["sub"])
    return _set_admin_user_status(user_id, new_status, admin_id)


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@token_required
@role_required("admin")
def admin_deactivate_user(user_id):
    """
    This DELETE endpoint performs a SAFE SOFT DELETE:
    it marks the account deactivated and preserves medical/appointment history.
    It does not physically delete the database row.
    """
    admin_id = int(request.current_user["sub"])
    return _set_admin_user_status(
        user_id, "deactivated", admin_id, soft_delete=True
    )


def _admin_limit():
    try:
        limit = int(request.args.get("limit", "200"))
    except (TypeError, ValueError):
        raise ValueError("limit must be a whole number")
    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    return limit


def _admin_search():
    value = request.args.get("q", "").strip()
    if len(value) > 150:
        raise ValueError("Search text is too long")
    return value


def _admin_text(value, field, max_length, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    value = value.strip()
    if not value:
        if optional:
            return None
        raise ValueError(f"{field} is required")
    if len(value) > max_length or "\x00" in value:
        raise ValueError(f"{field} is invalid or too long")
    return value


def _admin_id(value, field):
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a positive ID")
    if isinstance(value, int):
        identifier = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        identifier = int(value.strip())
    else:
        raise ValueError(f"{field} must be a positive ID")
    if identifier <= 0:
        raise ValueError(f"{field} must be a positive ID")
    return identifier


def _admin_active(value):
    if not isinstance(value, bool):
        raise ValueError("is_active must be a boolean")
    return value


def _admin_body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("A JSON object is required")
    return body


@app.route("/api/admin/overview", methods=["GET"])
@token_required
@role_required("admin")
def admin_overview():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT COUNT(*) AS total, COALESCE(SUM(is_active = TRUE), 0) AS active
            FROM hospitals
            """
        )
        hospital_counts = cursor.fetchone()
        cursor.execute(
            """
            SELECT COUNT(*) AS total, COALESCE(SUM(is_active = TRUE), 0) AS active
            FROM diagnostic_labs
            """
        )
        laboratory_counts = cursor.fetchone()
        cursor.execute("SELECT COUNT(*) AS total FROM users")
        user_count = cursor.fetchone()["total"]
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM doctors d
            INNER JOIN hospitals h ON h.hospital_id = d.hospital_id
            LEFT JOIN users u ON u.user_id = d.user_id
            WHERE d.is_active = TRUE
              AND h.is_active = TRUE
              AND (d.user_id IS NULL OR (
                    u.role = 'doctor' AND u.account_status = 'active'
              ))
            """
        )
        active_doctor_count = cursor.fetchone()["total"]
        cursor.execute(
            "SELECT status, COUNT(*) AS total FROM appointments GROUP BY status"
        )
        appointment_statuses = {
            row["status"]: int(row["total"]) for row in cursor.fetchall()
        }
        cursor.execute(
            "SELECT status, COUNT(*) AS total FROM payments GROUP BY status"
        )
        payment_statuses = {
            row["status"]: int(row["total"]) for row in cursor.fetchall()
        }
        cursor.execute(
            """
            SELECT
                al.log_id, al.action, al.target_type, al.target_id,
                al.event_details, al.ip_address, al.created_at,
                u.full_name AS actor_name
            FROM audit_logs al
            LEFT JOIN users u ON u.user_id = al.actor_user_id
            ORDER BY al.created_at DESC, al.log_id DESC
            LIMIT 10
            """
        )
        recent_activities = cursor.fetchall()

        overview = {
            "total_hospitals": int(hospital_counts["total"]),
            "active_hospitals": int(hospital_counts["active"]),
            "total_laboratories": int(laboratory_counts["total"]),
            "active_laboratories": int(laboratory_counts["active"]),
            "total_users": int(user_count),
            "active_doctors": int(active_doctor_count),
            "total_appointments": sum(appointment_statuses.values()),
            "appointment_statuses": appointment_statuses,
            "total_payments": sum(payment_statuses.values()),
            "payment_statuses": payment_statuses,
        }
        return jsonify({
            "status": "success",
            "overview": overview,
            "recent_activities": recent_activities,
        }), 200
    except Exception:
        app.logger.exception("Unable to retrieve administrator overview")
        return api_error("Unable to retrieve dashboard overview", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/hospitals", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_hospitals():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        status_filter = request.args.get("status", "").strip().lower()
        if status_filter not in {"", "active", "inactive"}:
            return api_error("status must be active or inactive", 400)

        conditions = []
        params = []
        if query:
            like = f"%{query}%"
            conditions.append(
                "(h.hospital_name LIKE %s OR h.city LIKE %s "
                "OR h.branch_code LIKE %s)"
            )
            params.extend((like, like, like))
        if status_filter:
            conditions.append("h.is_active = %s")
            params.append(1 if status_filter == "active" else 0)
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                h.hospital_id, h.branch_code, h.hospital_name,
                h.city, h.address, h.is_active,
                (SELECT COUNT(*) FROM doctors d
                 WHERE d.hospital_id = h.hospital_id) AS doctor_count,
                (SELECT COUNT(*) FROM diagnostic_labs l
                 WHERE l.hospital_id = h.hospital_id) AS laboratory_count,
                (SELECT COUNT(*) FROM appointments a
                 INNER JOIN doctors d ON d.doctor_id = a.doctor_id
                 WHERE d.hospital_id = h.hospital_id) AS appointment_count
            FROM hospitals h
            WHERE {where_sql}
            ORDER BY h.hospital_name, h.hospital_id
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "hospitals": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve hospital management data")
        return api_error("Unable to retrieve hospitals", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/hospitals", methods=["POST"])
@token_required
@role_required("admin")
def admin_create_hospital():
    try:
        data = _admin_body()
        branch_code = _admin_text(data.get("branch_code"), "branch_code", 20)
        hospital_name = _admin_text(
            data.get("hospital_name"), "hospital_name", 150
        )
        city = _admin_text(data.get("city"), "city", 100)
        address = _admin_text(
            data.get("address"), "address", 255, optional=True
        )
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO hospitals
                (branch_code, hospital_name, city, address, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
            """,
            (branch_code, hospital_name, city, address)
        )
        hospital_id = cursor.lastrowid
        connection.commit()
        write_audit_log(
            admin_id, "HOSPITAL_CREATED", "hospital", hospital_id,
            f"Created hospital {branch_code}."
        )
        return jsonify({
            "status": "success",
            "message": "Hospital created",
            "hospital_id": hospital_id,
        }), 201
    except IntegrityError:
        if connection:
            connection.rollback()
        return api_error("Hospital branch code is already in use", 409)
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Hospital creation failed")
        return api_error("Unable to create hospital", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/hospitals/<int:hospital_id>", methods=["PATCH"])
@token_required
@role_required("admin")
def admin_update_hospital(hospital_id):
    try:
        data = _admin_body()
        branch_code = _admin_text(data.get("branch_code"), "branch_code", 20)
        hospital_name = _admin_text(
            data.get("hospital_name"), "hospital_name", 150
        )
        city = _admin_text(data.get("city"), "city", 100)
        address = _admin_text(
            data.get("address"), "address", 255, optional=True
        )
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE hospitals
            SET branch_code = %s, hospital_name = %s, city = %s, address = %s
            WHERE hospital_id = %s
            """,
            (branch_code, hospital_name, city, address, hospital_id)
        )
        if cursor.rowcount == 0:
            cursor.execute(
                "SELECT hospital_id FROM hospitals WHERE hospital_id = %s",
                (hospital_id,)
            )
            if not cursor.fetchone():
                connection.rollback()
                return api_error("Hospital not found", 404)
        connection.commit()
        write_audit_log(
            admin_id, "HOSPITAL_UPDATED", "hospital", hospital_id,
            "Updated hospital directory details."
        )
        return jsonify({"status": "success", "message": "Hospital updated"}), 200
    except IntegrityError:
        if connection:
            connection.rollback()
        return api_error("Hospital branch code is already in use", 409)
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Hospital update failed")
        return api_error("Unable to update hospital", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/admin/hospitals/<int:hospital_id>/status",
    methods=["PATCH"]
)
@token_required
@role_required("admin")
def admin_update_hospital_status(hospital_id):
    try:
        is_active = _admin_active(_admin_body().get("is_active"))
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE hospitals SET is_active = %s WHERE hospital_id = %s",
            (is_active, hospital_id)
        )
        if cursor.rowcount == 0:
            cursor.execute(
                "SELECT hospital_id FROM hospitals WHERE hospital_id = %s",
                (hospital_id,)
            )
            if not cursor.fetchone():
                connection.rollback()
                return api_error("Hospital not found", 404)
        connection.commit()
        write_audit_log(
            admin_id, "HOSPITAL_STATUS_CHANGED", "hospital", hospital_id,
            "Hospital activated." if is_active else "Hospital deactivated."
        )
        return jsonify({
            "status": "success",
            "message": "Hospital status updated",
            "is_active": is_active,
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Hospital status update failed")
        return api_error("Unable to update hospital status", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/laboratories", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_laboratories():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        status_filter = request.args.get("status", "").strip().lower()
        if status_filter not in {"", "active", "inactive"}:
            return api_error("status must be active or inactive", 400)

        conditions = []
        params = []
        if query:
            like = f"%{query}%"
            conditions.append(
                "(l.lab_name LIKE %s OR l.lab_code LIKE %s OR "
                "l.city LIKE %s OR h.hospital_name LIKE %s)"
            )
            params.extend((like, like, like, like))
        if status_filter:
            conditions.append("l.is_active = %s")
            params.append(1 if status_filter == "active" else 0)
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                l.lab_id, l.lab_code, l.lab_name, l.city, l.hospital_id,
                l.is_active, h.hospital_name, h.is_active AS hospital_is_active
            FROM diagnostic_labs l
            LEFT JOIN hospitals h ON h.hospital_id = l.hospital_id
            WHERE {where_sql}
            ORDER BY l.lab_name, l.lab_id
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "laboratories": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve laboratory management data")
        return api_error("Unable to retrieve laboratories", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/laboratories", methods=["POST"])
@token_required
@role_required("admin")
def admin_create_laboratory():
    try:
        data = _admin_body()
        lab_code = _admin_text(data.get("lab_code"), "lab_code", 20)
        lab_name = _admin_text(data.get("lab_name"), "lab_name", 150)
        city = _admin_text(data.get("city"), "city", 100)
        hospital_id = _admin_id(data.get("hospital_id"), "hospital_id")
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT hospital_id FROM hospitals "
            "WHERE hospital_id = %s AND is_active = TRUE",
            (hospital_id,)
        )
        if not cursor.fetchone():
            return api_error("Select an active hospital", 400)
        cursor.execute(
            """
            INSERT INTO diagnostic_labs
                (lab_code, lab_name, city, hospital_id, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
            """,
            (lab_code, lab_name, city, hospital_id)
        )
        lab_id = cursor.lastrowid
        connection.commit()
        write_audit_log(
            admin_id, "LABORATORY_CREATED", "laboratory", lab_id,
            f"Created laboratory {lab_code}."
        )
        return jsonify({
            "status": "success",
            "message": "Laboratory created",
            "lab_id": lab_id,
        }), 201
    except IntegrityError:
        if connection:
            connection.rollback()
        return api_error("Laboratory code is already in use", 409)
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Laboratory creation failed")
        return api_error("Unable to create laboratory", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/laboratories/<int:lab_id>", methods=["PATCH"])
@token_required
@role_required("admin")
def admin_update_laboratory(lab_id):
    try:
        data = _admin_body()
        lab_code = _admin_text(data.get("lab_code"), "lab_code", 20)
        lab_name = _admin_text(data.get("lab_name"), "lab_name", 150)
        city = _admin_text(data.get("city"), "city", 100)
        hospital_id = _admin_id(data.get("hospital_id"), "hospital_id")
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT hospital_id FROM hospitals "
            "WHERE hospital_id = %s AND is_active = TRUE",
            (hospital_id,)
        )
        if not cursor.fetchone():
            return api_error("Select an active hospital", 400)
        cursor.execute(
            """
            UPDATE diagnostic_labs
            SET lab_code = %s, lab_name = %s, city = %s, hospital_id = %s
            WHERE lab_id = %s
            """,
            (lab_code, lab_name, city, hospital_id, lab_id)
        )
        if cursor.rowcount == 0:
            cursor.execute(
                "SELECT lab_id FROM diagnostic_labs WHERE lab_id = %s",
                (lab_id,)
            )
            if not cursor.fetchone():
                connection.rollback()
                return api_error("Laboratory not found", 404)
        connection.commit()
        write_audit_log(
            admin_id, "LABORATORY_UPDATED", "laboratory", lab_id,
            "Updated laboratory directory details."
        )
        return jsonify({
            "status": "success",
            "message": "Laboratory updated"
        }), 200
    except IntegrityError:
        if connection:
            connection.rollback()
        return api_error("Laboratory code is already in use", 409)
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Laboratory update failed")
        return api_error("Unable to update laboratory", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/admin/laboratories/<int:lab_id>/status",
    methods=["PATCH"]
)
@token_required
@role_required("admin")
def admin_update_laboratory_status(lab_id):
    try:
        is_active = _admin_active(_admin_body().get("is_active"))
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT l.lab_id, h.is_active AS hospital_is_active
            FROM diagnostic_labs l
            LEFT JOIN hospitals h ON h.hospital_id = l.hospital_id
            WHERE l.lab_id = %s
            """,
            (lab_id,)
        )
        laboratory = cursor.fetchone()
        if not laboratory:
            return api_error("Laboratory not found", 404)
        if is_active and not laboratory["hospital_is_active"]:
            return api_error(
                "A laboratory cannot be activated under an inactive hospital",
                409
            )
        cursor.execute(
            "UPDATE diagnostic_labs SET is_active = %s WHERE lab_id = %s",
            (is_active, lab_id)
        )
        connection.commit()
        write_audit_log(
            admin_id, "LABORATORY_STATUS_CHANGED", "laboratory", lab_id,
            "Laboratory activated." if is_active else "Laboratory deactivated."
        )
        return jsonify({
            "status": "success",
            "message": "Laboratory status updated",
            "is_active": is_active,
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Laboratory status update failed")
        return api_error("Unable to update laboratory status", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/doctors", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_doctors():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        status_filter = request.args.get("status", "").strip().lower()
        if status_filter not in {"", "active", "inactive"}:
            return api_error("status must be active or inactive", 400)

        conditions = []
        params = []
        if query:
            like = f"%{query}%"
            conditions.append(
                "(d.full_name LIKE %s OR d.specialty LIKE %s "
                "OR h.hospital_name LIKE %s OR u.email LIKE %s)"
            )
            params.extend((like, like, like, like))
        if status_filter == "active":
            conditions.append(
                "d.is_active = TRUE AND h.is_active = TRUE "
                "AND (d.user_id IS NULL OR u.account_status = 'active')"
            )
        elif status_filter == "inactive":
            conditions.append(
                "(d.is_active = FALSE OR h.is_active = FALSE "
                "OR (d.user_id IS NOT NULL AND u.account_status <> 'active'))"
            )
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                d.doctor_id, d.full_name, d.specialty, d.hospital_id,
                d.is_active, d.user_id, h.hospital_name,
                h.is_active AS hospital_is_active,
                u.email, u.account_status,
                CASE WHEN d.is_active = TRUE AND h.is_active = TRUE
                       AND (d.user_id IS NULL OR u.account_status = 'active')
                     THEN TRUE ELSE FALSE END AS available_for_booking,
                (SELECT COUNT(*) FROM appointments a
                 WHERE a.doctor_id = d.doctor_id) AS appointment_count
            FROM doctors d
            LEFT JOIN hospitals h ON h.hospital_id = d.hospital_id
            LEFT JOIN users u ON u.user_id = d.user_id
            WHERE {where_sql}
            ORDER BY d.full_name, d.doctor_id
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "doctors": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve doctor management data")
        return api_error("Unable to retrieve doctors", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/doctors", methods=["POST"])
@token_required
@role_required("admin")
def admin_create_doctor():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)

    try:
        full_name = _admin_text(data.get("full_name"), "full_name", 100)
        specialty = _admin_text(data.get("specialty"), "specialty", 100)
        email = _admin_text(data.get("email"), "email", 150).lower()
        password = data.get("password")
        hospital_id = _admin_id(data.get("hospital_id"), "hospital_id")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Please enter a valid email address")
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            raise ValueError("Password must be between 8 and 128 characters")
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT hospital_id FROM hospitals
            WHERE hospital_id = %s AND is_active = TRUE
            FOR UPDATE
            """,
            (hospital_id,)
        )
        if not cursor.fetchone():
            connection.rollback()
            return api_error("Select an active hospital", 400)
        cursor.execute(
            """
            INSERT INTO users
                (full_name, email, password_hash, role, account_status)
            VALUES (%s, %s, %s, 'doctor', 'active')
            """,
            (full_name, email, generate_password_hash(password))
        )
        user_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO doctors
                (full_name, specialty, hospital_id, is_active, user_id)
            VALUES (%s, %s, %s, TRUE, %s)
            """,
            (full_name, specialty, hospital_id, user_id)
        )
        doctor_id = cursor.lastrowid
        connection.commit()
        write_audit_log(
            admin_id, "DOCTOR_ACCOUNT_CREATED", "doctor", doctor_id,
            f"Created doctor account for hospital {hospital_id}."
        )
        return jsonify({
            "status": "success",
            "message": "Doctor account created",
            "doctor_id": doctor_id,
            "user_id": user_id
        }), 201
    except IntegrityError:
        if connection:
            connection.rollback()
        return api_error("That email address is already in use", 409)
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Doctor account creation failed")
        return api_error("Unable to create doctor account", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/doctors/<int:doctor_id>", methods=["PATCH"])
@token_required
@role_required("admin")
def admin_update_doctor(doctor_id):
    try:
        data = _admin_body()
        full_name = _admin_text(data.get("full_name"), "full_name", 100)
        specialty = _admin_text(data.get("specialty"), "specialty", 100)
        hospital_id = _admin_id(data.get("hospital_id"), "hospital_id")
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT hospital_id FROM hospitals
            WHERE hospital_id = %s AND is_active = TRUE
            FOR UPDATE
            """,
            (hospital_id,)
        )
        if not cursor.fetchone():
            connection.rollback()
            return api_error("Select an active hospital", 400)
        cursor.execute(
            """
            SELECT doctor_id, user_id FROM doctors
            WHERE doctor_id = %s FOR UPDATE
            """,
            (doctor_id,)
        )
        doctor = cursor.fetchone()
        if not doctor:
            connection.rollback()
            return api_error("Doctor not found", 404)
        cursor.execute(
            """
            UPDATE doctors
            SET full_name = %s, specialty = %s, hospital_id = %s
            WHERE doctor_id = %s
            """,
            (full_name, specialty, hospital_id, doctor_id)
        )
        if doctor["user_id"] is not None:
            cursor.execute(
                "UPDATE users SET full_name = %s WHERE user_id = %s",
                (full_name, doctor["user_id"])
            )
        connection.commit()
        write_audit_log(
            admin_id, "DOCTOR_UPDATED", "doctor", doctor_id,
            f"Updated doctor profile and hospital assignment to {hospital_id}."
        )
        return jsonify({"status": "success", "message": "Doctor updated"}), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Doctor update failed")
        return api_error("Unable to update doctor", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/admin/doctors/<int:doctor_id>/status",
    methods=["PATCH"]
)
@token_required
@role_required("admin")
def admin_update_doctor_status(doctor_id):
    try:
        is_active = _admin_active(_admin_body().get("is_active"))
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT doctor_id, user_id FROM doctors
            WHERE doctor_id = %s FOR UPDATE
            """,
            (doctor_id,)
        )
        doctor = cursor.fetchone()
        if not doctor:
            connection.rollback()
            return api_error("Doctor not found", 404)
        cursor.execute(
            "UPDATE doctors SET is_active = %s WHERE doctor_id = %s",
            (is_active, doctor_id)
        )
        if doctor["user_id"] is not None:
            cursor.execute(
                """
                UPDATE users
                SET account_status = %s,
                    status_changed_at = CURRENT_TIMESTAMP
                WHERE user_id = %s AND role = 'doctor'
                """,
                ("active" if is_active else "deactivated", doctor["user_id"])
            )
        connection.commit()
        write_audit_log(
            admin_id, "DOCTOR_STATUS_CHANGED", "doctor", doctor_id,
            "Doctor activated." if is_active else "Doctor deactivated."
        )
        return jsonify({
            "status": "success",
            "message": "Doctor status updated",
            "is_active": is_active,
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Doctor status update failed")
        return api_error("Unable to update doctor status", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/admin/doctors/<int:doctor_id>/appointments",
    methods=["GET"]
)
@token_required
@role_required("admin")
def admin_doctor_appointments(doctor_id):
    connection = None
    cursor = None
    try:
        limit = _admin_limit()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                a.appointment_id, a.appointment_date, a.reason, a.status,
                a.patient_id, p.full_name AS patient_name,
                p.email AS patient_email,
                d.full_name AS doctor_name, h.hospital_name
            FROM appointments a
            INNER JOIN users p ON p.user_id = a.patient_id
            INNER JOIN doctors d ON d.doctor_id = a.doctor_id
            LEFT JOIN hospitals h ON h.hospital_id = d.hospital_id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_date DESC
            LIMIT %s
            """,
            (doctor_id, limit)
        )
        appointments = cursor.fetchall()
        if not appointments:
            cursor.execute(
                "SELECT doctor_id FROM doctors WHERE doctor_id = %s",
                (doctor_id,)
            )
            if not cursor.fetchone():
                return api_error("Doctor not found", 404)
        write_audit_log(
            int(request.current_user["sub"]), "DOCTOR_APPOINTMENTS_VIEWED",
            "doctor", doctor_id,
            f"Viewed {len(appointments)} associated appointments."
        )
        return jsonify({
            "status": "success",
            "appointments": appointments
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve doctor appointments")
        return api_error("Unable to retrieve doctor appointments", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/appointments", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_appointments():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        status_filter = request.args.get("status", "").strip()
        allowed_statuses = {"Pending", "Confirmed", "Completed", "Cancelled"}
        if status_filter and status_filter not in allowed_statuses:
            return api_error("status is invalid", 400)
        hospital_id = request.args.get("hospital_id", "").strip()
        doctor_id = request.args.get("doctor_id", "").strip()
        patient_id = request.args.get("patient_id", "").strip()
        appointment_date = request.args.get("date", "").strip()

        conditions = []
        params = []
        for value, field, expression in (
            (hospital_id, "hospital_id", "h.hospital_id = %s"),
            (doctor_id, "doctor_id", "d.doctor_id = %s"),
            (patient_id, "patient_id", "a.patient_id = %s"),
        ):
            if value:
                try:
                    params.append(_admin_id(value, field))
                except ValueError as error:
                    return api_error(str(error), 400)
                conditions.append(expression)
        if appointment_date:
            try:
                parsed_date = datetime.strptime(appointment_date, "%Y-%m-%d").date()
            except ValueError:
                return api_error("date must use YYYY-MM-DD format", 400)
            conditions.append("DATE(a.appointment_date) = %s")
            params.append(parsed_date)
        if status_filter:
            conditions.append("a.status = %s")
            params.append(status_filter)
        if query:
            like = f"%{query}%"
            conditions.append(
                "(p.full_name LIKE %s OR p.email LIKE %s "
                "OR d.full_name LIKE %s OR h.hospital_name LIKE %s)"
            )
            params.extend((like, like, like, like))
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                a.appointment_id, a.patient_id, p.full_name AS patient_name,
                p.email AS patient_email, a.doctor_id, d.full_name AS doctor_name,
                d.specialty AS doctor_specialty, h.hospital_id, h.hospital_name,
                a.appointment_date, a.reason, a.status
            FROM appointments a
            INNER JOIN users p ON p.user_id = a.patient_id
            INNER JOIN doctors d ON d.doctor_id = a.doctor_id
            LEFT JOIN hospitals h ON h.hospital_id = d.hospital_id
            WHERE {where_sql}
            ORDER BY a.appointment_date DESC, a.appointment_id DESC
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "appointments": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve appointment management data")
        return api_error("Unable to retrieve appointments", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/admin/appointments/<int:appointment_id>/status",
    methods=["PATCH"]
)
@token_required
@role_required("admin")
def admin_update_appointment_status(appointment_id):
    try:
        new_status = _admin_text(
            _admin_body().get("status"), "status", 20
        )
    except ValueError as error:
        return api_error(str(error), 400)
    if new_status not in {"Pending", "Confirmed", "Completed", "Cancelled"}:
        return api_error("status is invalid", 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    allowed_transitions = {
        "Pending": {"Confirmed", "Cancelled"},
        "Confirmed": {"Completed", "Cancelled"},
        "Completed": set(),
        "Cancelled": set(),
    }
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT status FROM appointments
            WHERE appointment_id = %s FOR UPDATE
            """,
            (appointment_id,)
        )
        appointment = cursor.fetchone()
        if not appointment:
            connection.rollback()
            return api_error("Appointment not found", 404)
        current_status = appointment["status"]
        if new_status != current_status and \
                new_status not in allowed_transitions.get(current_status, set()):
            connection.rollback()
            return api_error(
                f"Cannot change appointment from {current_status} to {new_status}",
                409
            )
        cursor.execute(
            "UPDATE appointments SET status = %s WHERE appointment_id = %s",
            (new_status, appointment_id)
        )
        connection.commit()
        write_audit_log(
            admin_id, "APPOINTMENT_STATUS_CHANGED", "appointment",
            appointment_id,
            f"Appointment status changed from {current_status} to {new_status}."
        )
        return jsonify({
            "status": "success",
            "message": "Appointment status updated",
            "appointment_status": new_status
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Appointment status update failed")
        return api_error("Unable to update appointment status", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/medical-records", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_medical_records():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        params = []
        where_sql = "1 = 1"
        if query:
            like = f"%{query}%"
            where_sql = (
                "p.full_name LIKE %s OR p.email LIKE %s "
                "OR d.full_name LIKE %s"
            )
            params.extend((like, like, like))

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                mr.record_id, mr.patient_id, p.full_name AS patient_name,
                p.email AS patient_email, mr.doctor_id,
                d.full_name AS doctor_name, d.specialty,
                mr.record_date, h.hospital_name
            FROM medical_records mr
            INNER JOIN users p ON p.user_id = mr.patient_id
            INNER JOIN doctors d ON d.doctor_id = mr.doctor_id
            LEFT JOIN hospitals h ON h.hospital_id = d.hospital_id
            WHERE {where_sql}
            ORDER BY mr.record_date DESC, mr.record_id DESC
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        records = cursor.fetchall()
        write_audit_log(
            int(request.current_user["sub"]), "MEDICAL_RECORDS_VIEWED",
            "medical_records", None,
            f"Viewed metadata for {len(records)} medical records; clinical details were not returned."
        )
        return jsonify({
            "status": "success",
            "medical_records": records
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve medical-record metadata")
        return api_error("Unable to retrieve medical records", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/lab-reports", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_lab_reports():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        params = []
        where_sql = "1 = 1"
        if query:
            like = f"%{query}%"
            where_sql = (
                "lr.test_name LIKE %s OR p.full_name LIKE %s "
                "OR p.email LIKE %s OR d.full_name LIKE %s "
                "OR l.lab_name LIKE %s"
            )
            params.extend((like, like, like, like, like))

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                lr.report_id, lr.appointment_id, lr.patient_id,
                p.full_name AS patient_name, p.email AS patient_email,
                lr.doctor_id, d.full_name AS doctor_name,
                lr.lab_id, l.lab_name, h.hospital_name,
                lr.test_name, lr.report_date
            FROM lab_reports lr
            INNER JOIN users p ON p.user_id = lr.patient_id
            INNER JOIN doctors d ON d.doctor_id = lr.doctor_id
            LEFT JOIN diagnostic_labs l ON l.lab_id = lr.lab_id
            LEFT JOIN hospitals h ON h.hospital_id = l.hospital_id
            WHERE {where_sql}
            ORDER BY lr.report_date DESC, lr.report_id DESC
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        reports = cursor.fetchall()
        write_audit_log(
            int(request.current_user["sub"]), "LAB_REPORTS_VIEWED",
            "lab_reports", None,
            f"Viewed metadata for {len(reports)} lab reports; results and notes were not returned."
        )
        return jsonify({
            "status": "success",
            "lab_reports": reports
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve lab-report metadata")
        return api_error("Unable to retrieve lab reports", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route(
    "/api/admin/lab-reports/<int:report_id>",
    methods=["PATCH"]
)
@token_required
@role_required("admin")
def admin_update_lab_report_metadata(report_id):
    try:
        data = _admin_body()
        test_name = _admin_text(data.get("test_name"), "test_name", 150)
        lab_id = _admin_id(data.get("lab_id"), "lab_id")
        report_date_text = _admin_text(
            data.get("report_date"), "report_date", 10
        )
        try:
            report_date = datetime.strptime(
                report_date_text, "%Y-%m-%d"
            ).date()
        except ValueError:
            return api_error("report_date must use YYYY-MM-DD format", 400)
    except ValueError as error:
        return api_error(str(error), 400)

    connection = None
    cursor = None
    admin_id = int(request.current_user["sub"])
    try:
        connection = get_db_connection()
        connection.start_transaction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT l.lab_id
            FROM diagnostic_labs l
            INNER JOIN hospitals h ON h.hospital_id = l.hospital_id
            WHERE l.lab_id = %s
              AND l.is_active = TRUE
              AND h.is_active = TRUE
            FOR UPDATE
            """,
            (lab_id,)
        )
        if not cursor.fetchone():
            connection.rollback()
            return api_error("Select an active laboratory", 400)
        cursor.execute(
            """
            SELECT report_id FROM lab_reports
            WHERE report_id = %s FOR UPDATE
            """,
            (report_id,)
        )
        if not cursor.fetchone():
            connection.rollback()
            return api_error("Lab report not found", 404)
        cursor.execute(
            """
            UPDATE lab_reports
            SET test_name = %s, lab_id = %s, report_date = %s
            WHERE report_id = %s
            """,
            (test_name, lab_id, report_date, report_id)
        )
        connection.commit()
        write_audit_log(
            admin_id, "LAB_REPORT_METADATA_UPDATED", "lab_report", report_id,
            "Updated report name, laboratory assignment, or report date."
        )
        return jsonify({
            "status": "success",
            "message": "Lab report metadata updated"
        }), 200
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Lab report metadata update failed")
        return api_error("Unable to update lab report metadata", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/payments", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_payments():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        status_filter = request.args.get("status", "").strip()
        if status_filter not in {"", "Pending", "Successful", "Failed"}:
            return api_error("status is invalid", 400)

        conditions = []
        params = []
        if status_filter:
            conditions.append("p.status = %s")
            params.append(status_filter)
        if query:
            like = f"%{query}%"
            conditions.append(
                "(p.payment_id LIKE %s OR p.appointment_id LIKE %s "
                "OR p.patient_id LIKE %s OR p.status LIKE %s "
                "OR p.provider LIKE %s OR p.patient_id IN "
                "(SELECT user_id FROM users WHERE full_name LIKE %s "
                "OR email LIKE %s) OR CONCAT('SIM-', p.payment_id) LIKE %s)"
            )
            params.extend((like, like, like, like, like, like, like, like))
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                p.payment_id, p.appointment_id, p.patient_id,
                u.full_name AS patient_name, u.email AS patient_email,
                CAST(p.amount AS CHAR) AS amount, p.currency, p.status,
                p.provider, CONCAT('SIM-', p.payment_id) AS transaction_reference,
                p.created_at, a.appointment_date, a.status AS appointment_status,
                a.reason, d.full_name AS doctor_name, h.hospital_name
            FROM payments p
            INNER JOIN appointments a ON a.appointment_id = p.appointment_id
            INNER JOIN users u ON u.user_id = p.patient_id
            INNER JOIN doctors d ON d.doctor_id = a.doctor_id
            LEFT JOIN hospitals h ON h.hospital_id = d.hospital_id
            WHERE {where_sql}
            ORDER BY p.created_at DESC, p.payment_id DESC
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "payment_workflow": "simulated",
            "payments": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve payment management data")
        return api_error("Unable to retrieve payments", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/admin/audit-logs", methods=["GET"])
@token_required
@role_required("admin")
def admin_list_audit_logs():
    connection = None
    cursor = None
    try:
        query = _admin_search()
        limit = _admin_limit()
        action_filter = request.args.get("action", "").strip()
        if len(action_filter) > 80:
            return api_error("action is too long", 400)

        conditions = []
        params = []
        if action_filter:
            conditions.append("al.action = %s")
            params.append(action_filter)
        if query:
            like = f"%{query}%"
            conditions.append(
                "(al.action LIKE %s OR al.target_type LIKE %s "
                "OR al.target_id LIKE %s OR al.event_details LIKE %s "
                "OR u.full_name LIKE %s OR u.email LIKE %s)"
            )
            params.extend((like, like, like, like, like, like))
        where_sql = " AND ".join(conditions) if conditions else "1 = 1"

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT
                al.log_id, al.actor_user_id, u.full_name AS actor_name,
                al.action, al.target_type, al.target_id,
                al.event_details, al.ip_address, al.created_at
            FROM audit_logs al
            LEFT JOIN users u ON u.user_id = al.actor_user_id
            WHERE {where_sql}
            ORDER BY al.created_at DESC, al.log_id DESC
            LIMIT %s
            """,
            tuple(params + [limit])
        )
        return jsonify({
            "status": "success",
            "audit_logs": cursor.fetchall()
        }), 200
    except ValueError as error:
        return api_error(str(error), 400)
    except Exception:
        app.logger.exception("Unable to retrieve audit logs")
        return api_error("Unable to retrieve audit logs", 500)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# Run development server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Keep debug disabled so the interactive debugger is not exposed.
    app.run(host="127.0.0.1", port=5000, debug=False)
