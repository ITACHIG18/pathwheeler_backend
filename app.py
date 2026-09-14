import os
import re
import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import jwt


# ============================================================
# ENVIRONMENT
# ============================================================



app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:3000",
                "http://127.0.0.1:3000"
            ],
            "methods": [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS"
            ],
            "allow_headers": [
                "Content-Type",
                "Authorization"
            ]
        }
    }
)


@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        return "", 200



# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        ".env"
    )
)

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "pathwheelers-2-0-change-this-secret-key"
)

JWT_EXPIRATION_HOURS = int(
    os.getenv("JWT_EXPIRATION_HOURS", "24")
)

DB_HOST = os.getenv(
    "DB_HOST",
    "mysql-warren.alwaysdata.net"
)

DB_PORT = int(
    os.getenv(
        "DB_PORT",
        "3306"
    )
)

DB_NAME = os.getenv(
    "DB_NAME",
    "warren_pathwheelers2"
)

DB_USER = os.getenv(
    "DB_USER",
    "warren"
)

DB_PASSWORD = os.getenv(
    "DB_PASSWORD",
    "Dekuh_G18"
)

print("DB HOST:", DB_HOST)
print("DB USER:", DB_USER)
print("DB NAME:", DB_NAME)
print("DB PASSWORD LOADED:", bool(DB_PASSWORD))

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("warinevi@gmail.com", "")
SMTP_PASSWORD = os.getenv("qgab jlgt orgz qqbp", "")


# ============================================================
# DATABASE CONNECTION
# ============================================================

# Add this import at the top of your file
import pymysql

def get_db():
    """
    Creates a fresh MySQL connection using pure-Python PyMySQL to prevent crashes.
    """
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        autocommit=False,
        cursorclass=pymysql.cursors.DictCursor # This replaces dictionary=True
    )



def fetch_one(query, params=()):
    conn = get_db()
    cursor = conn.cursor()


    try:
        cursor.execute(query, params)
        return cursor.fetchone()

    finally:
        cursor.close()
        conn.close()


def fetch_all(query, params=()):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(query, params)
        return cursor.fetchall()

    finally:
        cursor.close()
        conn.close()


def execute_query(query, params=(), fetch=False):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(query, params)

        result = None

        if fetch:
            result = cursor.fetchall()

        conn.commit()

        return result

    except Exception:
        conn.rollback()
        raise

    finally:
        cursor.close()
        conn.close()


# ============================================================
# HELPERS
# ============================================================

def json_error(message, status=400):
    return jsonify({
        "success": False,
        "message": message
    }), status


def json_success(data=None, message="Success", status=200):
    response = {
        "success": True,
        "message": message
    }

    if data is not None:
        response["data"] = data

    return jsonify(response), status


def utc_now():
    return datetime.now(timezone.utc)


def clean_email(email):
    if not email:
        return ""

    return email.strip().lower()


def is_valid_email(email):
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(pattern, email or "") is not None


def make_jwt(user):
    now = datetime.now(timezone.utc)

    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "employee_id": user.get("employee_id"),
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS)
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )


def decode_jwt(token):
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

    except jwt.ExpiredSignatureError:
        return None

    except jwt.InvalidTokenError:
        return None


def get_token_from_request():
    header = request.headers.get("Authorization", "")

    if not header:
        return None

    if not header.startswith("Bearer "):
        return None

    return header.replace("Bearer ", "", 1).strip()


def get_current_user():
    token = get_token_from_request()

    if not token:
        return None

    payload = decode_jwt(token)

    if not payload:
        return None

    user = fetch_one(
        """
        SELECT
            id,
            full_name,
            email,
            role,
            employee_id,
            google_id,
            is_active,
            created_at,
            updated_at
        FROM users
        WHERE id = %s
        LIMIT 1
        """,
        (payload["user_id"],)
    )

    if not user:
        return None

    if not user["is_active"]:
        return None

    return user


def require_auth():
    user = get_current_user()

    if not user:
        return None, json_error(
            "Authentication required.",
            401
        )

    return user, None


def require_admin():
    user = get_current_user()

    if not user:
        return None, json_error(
            "Authentication required.",
            401
        )

    if user["role"] != "admin":
        return None, json_error(
            "Administrator access required.",
            403
        )

    return user, None


def user_to_dict(user):
    if not user:
        return None

    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
        "employee_id": user["employee_id"],
        "google_id": user.get("google_id"),
        "is_active": bool(user["is_active"]),
        "created_at": (
            user["created_at"].isoformat()
            if user.get("created_at")
            else None
        ),
        "updated_at": (
            user["updated_at"].isoformat()
            if user.get("updated_at")
            else None
        )
    }


# ============================================================
# EMAIL / OTP
# ============================================================

def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, code, purpose="login"):
    """
    Sends OTP through Gmail SMTP when SMTP credentials exist.

    If SMTP credentials are not configured, the OTP is printed
    to the terminal during local development.
    """

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("\n========================================")
        print("PATHWHEELERS DEVELOPMENT OTP")
        print("Email:", email)
        print("Code:", code)
        print("Purpose:", purpose)
        print("========================================\n")
        return True

    try:
        message = EmailMessage()

        message["Subject"] = "PathWheelers Verification Code"
        message["From"] = SMTP_EMAIL
        message["To"] = email

        message.set_content(
            f"""
PathWheelers

Your verification code is:

{code}

This code will expire in 10 minutes.

If you did not request this code, you can safely ignore this email.

PathWheelers
            """.strip()
        )

        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT
        ) as server:

            server.starttls()

            server.login(
                SMTP_EMAIL,
                SMTP_PASSWORD
            )

            server.send_message(message)

        return True

    except Exception as error:
        print("Email sending error:", error)

        return False


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "success": True,
        "message": "PathWheelers 2.0 API is running.",
        "version": "2.0"
    })


@app.route("/api/health", methods=["GET"])
def health():
    try:
        conn = get_db()

        if conn.is_connected():
            conn.close()

            return jsonify({
                "success": True,
                "message": "Backend and database are connected.",
                "database": DB_NAME
            })

        return json_error(
            "Database connection failed.",
            500
        )

    except Exception as error:
        return jsonify({
            "success": False,
            "message": "Database connection failed.",
            "error": str(error)
        }), 500


# ============================================================
# AUTH — SEND OTP
# ============================================================

@app.route("/api/auth/send-code", methods=["POST"])
def send_code():

    try:
        data = request.get_json(silent=True) or {}

        email = clean_email(
            data.get("email")
        )

        if not email:
            return json_error(
                "Email is required."
            )

        if not is_valid_email(email):
            return json_error(
                "Please enter a valid email address."
            )

        purpose = data.get(
            "purpose",
            "login"
        )

        if purpose not in [
            "login",
            "registration",
            "password_reset"
        ]:
            purpose = "login"

        user = fetch_one(
            """
            SELECT
                id,
                full_name,
                email,
                role,
                employee_id,
                google_id,
                is_active
            FROM users
            WHERE email = %s
            LIMIT 1
            """,
            (email,)
        )

        # ----------------------------------------------------
        # LOGIN
        # ----------------------------------------------------

        if purpose == "login":

            if not user:
                return json_error(
                    "No PathWheelers account exists with this email.",
                    404
                )

            if not user["is_active"]:
                return json_error(
                    "This account is inactive.",
                    403
                )

        # ----------------------------------------------------
        # REGISTRATION
        # ----------------------------------------------------

        if purpose == "registration":

            if user:
                return json_error(
                    "An account with this email already exists.",
                    409
                )

        # ----------------------------------------------------
        # PASSWORD RESET
        # ----------------------------------------------------

        if purpose == "password_reset":

            if not user:
                return json_error(
                    "No account exists with this email.",
                    404
                )

        code = generate_otp()

        expires_at = datetime.utcnow() + timedelta(
            minutes=10
        )

        # Invalidate previous unused OTPs
        execute_query(
            """
            UPDATE otp_codes
            SET used_at = NOW()
            WHERE email = %s
              AND purpose = %s
              AND used_at IS NULL
            """,
            (email, purpose)
        )

        execute_query(
            """
            INSERT INTO otp_codes
            (
                email,
                code,
                purpose,
                expires_at,
                attempts
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                0
            )
            """,
            (
                email,
                code,
                purpose,
                expires_at
            )
        )

        sent = send_otp_email(
            email,
            code,
            purpose
        )

        if not sent:
            return json_error(
                "Unable to send verification code.",
                500
            )

        return jsonify({
            "success": True,
            "message": "Verification code sent.",
            "email": email,
            "purpose": purpose
        })

    except Exception as error:

        print("SEND CODE ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to send verification code.",
            "error": str(error)
        }), 500


# ============================================================
# AUTH — VERIFY OTP
# ============================================================

@app.route("/api/auth/verify-code", methods=["POST"])
def verify_code():

    try:
        data = request.get_json(silent=True) or {}

        email = clean_email(
            data.get("email")
        )

        code = str(
            data.get("code", "")
        ).strip()

        purpose = data.get(
            "purpose",
            "login"
        )

        if not email:
            return json_error(
                "Email is required."
            )

        if not code:
            return json_error(
                "Verification code is required."
            )

        if len(code) != 6 or not code.isdigit():
            return json_error(
                "Verification code must contain 6 digits."
            )

        otp = fetch_one(
            """
            SELECT
                id,
                email,
                code,
                purpose,
                expires_at,
                used_at,
                attempts,
                created_at
            FROM otp_codes
            WHERE email = %s
              AND purpose = %s
              AND used_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (email, purpose)
        )

        if not otp:
            return json_error(
                "No active verification code found.",
                404
            )

        if otp["expires_at"] < datetime.utcnow():
            execute_query(
                """
                UPDATE otp_codes
                SET used_at = NOW()
                WHERE id = %s
                """,
                (otp["id"],)
            )

            return json_error(
                "Verification code has expired.",
                400
            )

        if otp["attempts"] >= 5:
            return json_error(
                "Too many incorrect attempts. Please request a new code.",
                429
            )

        if otp["code"] != code:

            execute_query(
                """
                UPDATE otp_codes
                SET attempts = attempts + 1
                WHERE id = %s
                """,
                (otp["id"],)
            )

            return json_error(
                "Incorrect verification code.",
                400
            )

        # Mark OTP as used
        execute_query(
            """
            UPDATE otp_codes
            SET used_at = NOW()
            WHERE id = %s
            """,
            (otp["id"],)
        )

        # ----------------------------------------------------
        # LOGIN
        # ----------------------------------------------------

        if purpose == "login":

            user = fetch_one(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    role,
                    employee_id,
                    google_id,
                    is_active,
                    created_at,
                    updated_at
                FROM users
                WHERE email = %s
                LIMIT 1
                """,
                (email,)
            )

            if not user:
                return json_error(
                    "Account not found.",
                    404
                )

            if not user["is_active"]:
                return json_error(
                    "This account is inactive.",
                    403
                )

            token = make_jwt(user)

            return jsonify({
                "success": True,
                "message": "Login successful.",
                "token": token,
                "user": user_to_dict(user)
            })

        # ----------------------------------------------------
        # PASSWORD RESET
        # ----------------------------------------------------

        if purpose == "password_reset":

            user = fetch_one(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    role,
                    employee_id,
                    google_id,
                    is_active,
                    created_at,
                    updated_at
                FROM users
                WHERE email = %s
                LIMIT 1
                """,
                (email,)
            )

            if not user:
                return json_error(
                    "Account not found.",
                    404
                )

            return jsonify({
                "success": True,
                "message": "Code verified.",
                "reset_verified": True,
                "email": email,
                "user": user_to_dict(user)
            })

        # ----------------------------------------------------
        # REGISTRATION
        # ----------------------------------------------------

        if purpose == "registration":

            return jsonify({
                "success": True,
                "message": "Code verified.",
                "registration_verified": True,
                "email": email
            })

        return json_error(
            "Unsupported verification purpose."
        )

    except Exception as error:

        print("VERIFY CODE ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to verify code.",
            "error": str(error)
        }), 500


# ============================================================
# AUTH — LOGIN WITH PASSWORD
# ADMIN = EMAIL + PASSWORD
# EMPLOYEE = USERNAME + PASSWORD
# ============================================================

# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/api/auth/login",
    methods=["POST"]
)
def password_login():

    try:

        data = request.get_json() or {}

        # ----------------------------------------------------
        # LOGIN TYPE
        #
        # admin
        # employee
        # ----------------------------------------------------

        login_type = (
            data.get("login_type")
            or data.get("type")
            or "admin"
        ).strip().lower()

        # ----------------------------------------------------
        # ADMIN LOGIN
        # ----------------------------------------------------

        if login_type == "admin":

            email = clean_email(
                data.get("email")
            )

            password = (
                data.get("password")
                or ""
            )

            if not email:

                return json_error(
                    "Email is required."
                )

            if not is_valid_email(email):

                return json_error(
                    "Please enter a valid email address."
                )

            if not password:

                return json_error(
                    "Password is required."
                )

            user = fetch_one(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    password_hash,
                    role,
                    employee_id,
                    google_id,
                    is_active,
                    created_at,
                    updated_at
                FROM users
                WHERE LOWER(email) = %s
                LIMIT 1
                """,
                (email,)
            )

            if not user:

                return json_error(
                    "Invalid email or password.",
                    401
                )

            if user["role"] != "admin":

                return json_error(
                    "This account is not an administrator account.",
                    403
                )

            if not user["is_active"]:

                return json_error(
                    "This account is inactive.",
                    403
                )

            if not user["password_hash"]:

                return json_error(
                    "This account does not have a password. Please reset your password.",
                    401
                )

            if not check_password_hash(
                user["password_hash"],
                password
            ):

                return json_error(
                    "Invalid email or password.",
                    401
                )

        # ----------------------------------------------------
        # EMPLOYEE LOGIN
        # ----------------------------------------------------

        elif login_type == "employee":

            username = str(
                data.get("username")
                or data.get("name")
                or ""
            ).strip()

            password = (
                data.get("password")
                or ""
            )

            if not username:

                return json_error(
                    "Employee username is required."
                )

            if not password:

                return json_error(
                    "Password is required."
                )

            # ------------------------------------------------
            # Employee username is the employee's name.
            #
            # Example:
            #
            # John
            # John Kamau
            #
            # Case does not matter.
            # ------------------------------------------------

            user = fetch_one(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    password_hash,
                    role,
                    employee_id,
                    google_id,
                    is_active,
                    created_at,
                    updated_at
                FROM users
                WHERE LOWER(TRIM(full_name)) = LOWER(TRIM(%s))
                  AND role = 'employee'
                LIMIT 1
                """,
                (username,)
            )

            if not user:

                return json_error(
                    "Employee username or password is incorrect.",
                    401
                )

            if not user["is_active"]:

                return json_error(
                    "This employee account is inactive.",
                    403
                )

            if not user["password_hash"]:

                return json_error(
                    "This employee account does not have a password.",
                    401
                )

            if not check_password_hash(
                user["password_hash"],
                password
            ):

                return json_error(
                    "Employee username or password is incorrect.",
                    401
                )

        # ----------------------------------------------------
        # INVALID LOGIN TYPE
        # ----------------------------------------------------

        else:

            return json_error(
                "Invalid login type. Choose Admin or Employee.",
                400
            )

        # ----------------------------------------------------
        # CREATE JWT
        # ----------------------------------------------------

        token = make_jwt(user)

        # ----------------------------------------------------
        # RETURN LOGIN RESPONSE
        # ----------------------------------------------------

        return jsonify({
            "success": True,

            "message": "Login successful.",

            "token": token,

            "user": user_to_dict(user)

        }), 200

    except Exception as error:

        print(
            "LOGIN ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Login failed.",
            "error": str(error)
        }), 500
    
# ============================================================
# AUTH — CURRENT USER
# ============================================================

@app.route("/api/auth/me", methods=["GET"])
def auth_me():

    user, error_response = require_auth()

    if error_response:
        return error_response

    return jsonify({
        "success": True,
        "user": user_to_dict(user)
    })


# ============================================================
# AUTH — LOGOUT
# ============================================================

@app.route("/api/auth/logout", methods=["POST"])
def logout():

    # JWT is stateless.
    # The frontend removes the token.
    # A future token blacklist can be added if needed.

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })


# ============================================================
# CREATE ADMIN ACCOUNT
# ============================================================

@app.route("/api/auth/register-admin", methods=["POST"])
def register_admin():

    try:
        data = request.get_json(silent=True) or {}

        full_name = str(
            data.get("full_name", "")
        ).strip()

        email = clean_email(
            data.get("email")
        )

        password = str(
            data.get("password", "")
        )

        if not full_name:
            return json_error(
                "Full name is required."
            )

        if not is_valid_email(email):
            return json_error(
                "A valid email is required."
            )

        if len(password) < 6:
            return json_error(
                "Password must be at least 6 characters."
            )

        existing = fetch_one(
            """
            SELECT id
            FROM users
            WHERE email = %s
            LIMIT 1
            """,
            (email,)
        )

        if existing:
            return json_error(
                "An account with this email already exists.",
                409
            )

        code = generate_otp()

        expires_at = datetime.utcnow() + timedelta(
            minutes=10
        )

        password_hash = generate_password_hash(
            password
        )

        execute_query(
            """
            UPDATE otp_codes
            SET used_at = NOW()
            WHERE email = %s
              AND purpose = 'registration'
              AND used_at IS NULL
            """,
            (email,)
        )

        execute_query(
            """
            INSERT INTO otp_codes
            (
                email,
                code,
                purpose,
                expires_at,
                attempts,
                registration_name,
                registration_password_hash
            )
            VALUES
            (
                %s,
                %s,
                'registration',
                %s,
                0,
                %s,
                %s
            )
            """,
            (
                email,
                code,
                expires_at,
                full_name,
                password_hash
            )
        )

        sent = send_otp_email(
            email,
            code,
            "registration"
        )

        if not sent:

            execute_query(
                """
                UPDATE otp_codes
                SET used_at = NOW()
                WHERE email = %s
                  AND purpose = 'registration'
                  AND code = %s
                  AND used_at IS NULL
                """,
                (
                    email,
                    code
                )
            )

            return json_error(
                "Unable to send verification code. "
                "Please check your email configuration.",
                500
            )

        return jsonify({
            "success": True,
            "message": "Verification code sent to your email.",
            "email": email,
            "purpose": "registration"
        }), 200

    except Exception as error:

        print(
            "REGISTER ADMIN ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to start administrator registration.",
            "error": str(error)
        }), 500
# ============================================================
# START SERVER
# ============================================================


    # ============================================================
# YEARS
# ============================================================

@app.route("/api/years", methods=["GET"])
def get_years():
    user, error_response = require_auth()

    if error_response:
        return error_response

    try:
        years = fetch_all("""
            SELECT
                id,
                year,
                is_current,
                created_at,
                updated_at
            FROM academic_years
            ORDER BY year DESC
        """)

        for item in years:

            item["is_current"] = bool(
                item["is_current"]
            )

            if item.get("created_at"):
                item["created_at"] = (
                    item["created_at"].isoformat()
                )

            if item.get("updated_at"):
                item["updated_at"] = (
                    item["updated_at"].isoformat()
                )

            # --------------------------------------------------
            # LOAD TERMS FOR THIS YEAR
            # --------------------------------------------------

            terms = fetch_all("""
                SELECT
                    id,
                    academic_year_id,
                    name,
                    term_number,
                    is_current,
                    start_date,
                    end_date,
                    created_at,
                    updated_at
                FROM terms
                WHERE academic_year_id = %s
                ORDER BY term_number ASC
            """, (item["id"],))

            for term in terms:

                term["is_current"] = bool(
                    term["is_current"]
                )

                if term.get("start_date"):
                    term["start_date"] = (
                        term["start_date"].isoformat()
                    )

                if term.get("end_date"):
                    term["end_date"] = (
                        term["end_date"].isoformat()
                    )

                if term.get("created_at"):
                    term["created_at"] = (
                        term["created_at"].isoformat()
                    )

                if term.get("updated_at"):
                    term["updated_at"] = (
                        term["updated_at"].isoformat()
                    )

            item["terms"] = terms

        return jsonify({
            "success": True,
            "years": years,
            "data": years
        }), 200

    except Exception as error:

        print(
            "GET YEARS ERROR:",
            str(error)
        )

        return jsonify({
            "success": False,
            "message": "Failed to load years."
        }), 500
    
@app.route("/api/years/<int:year_id>", methods=["GET"])
def get_single_year(year_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        year = fetch_one(
            """
            SELECT
                id,
                year,
                is_current,
                created_at,
                updated_at
            FROM academic_years
            WHERE id = %s
            LIMIT 1
            """,
            (year_id,)
        )

        if not year:
            return json_error(
                "Academic year not found.",
                404
            )

        terms = fetch_all(
            """
            SELECT
                id,
                academic_year_id,
                term_number,
                name,
                is_current,
                start_date,
                end_date,
                created_at,
                updated_at
            FROM terms
            WHERE academic_year_id = %s
            ORDER BY term_number ASC
            """,
            (year_id,)
        )

        year["is_current"] = bool(
            year["is_current"]
        )

        if year.get("created_at"):
            year["created_at"] = (
                year["created_at"].isoformat()
            )

        if year.get("updated_at"):
            year["updated_at"] = (
                year["updated_at"].isoformat()
            )

        for term in terms:

            term["is_current"] = bool(
                term["is_current"]
            )

            if term.get("start_date"):
                term["start_date"] = (
                    term["start_date"].isoformat()
                )

            if term.get("end_date"):
                term["end_date"] = (
                    term["end_date"].isoformat()
                )

            if term.get("created_at"):
                term["created_at"] = (
                    term["created_at"].isoformat()
                )

            if term.get("updated_at"):
                term["updated_at"] = (
                    term["updated_at"].isoformat()
                )

        year["terms"] = terms

        return jsonify({
            "success": True,
            "year": year,
            "terms": terms,
            "data": year
        })

    except Exception as error:

        print("GET SINGLE YEAR ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to load academic year.",
            "error": str(error)
        }), 500


# ============================================================
# CREATE NEW ACADEMIC YEAR
# ============================================================

@app.route("/api/years", methods=["POST"])
def create_year():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        requested_year = data.get("year")

        if requested_year in [
            None,
            ""
        ]:
            requested_year = datetime.now().year

        try:
            requested_year = int(
                requested_year
            )

        except (ValueError, TypeError):

            return json_error(
                "Year must be a valid number."
            )

        if requested_year < 2000 or requested_year > 2100:

            return json_error(
                "Please enter a valid academic year."
            )

        existing_year = fetch_one(
            """
            SELECT
                id,
                year
            FROM academic_years
            WHERE year = %s
            LIMIT 1
            """,
            (requested_year,)
        )

        if existing_year:

            return json_error(
                f"Academic year {requested_year} already exists.",
                409
            )

        conn = get_db()
        cursor = conn.cursor()


        try:

            # Make every previous year non-current
            cursor.execute(
                """
                UPDATE academic_years
                SET is_current = 0
                """
            )

            # Create the new year
            cursor.execute(
                """
                INSERT INTO academic_years
                (
                    year,
                    is_current
                )
                VALUES
                (
                    %s,
                    1
                )
                """,
                (requested_year,)
            )

            year_id = cursor.lastrowid

            # Automatically create all three terms
            cursor.execute(
                """
                INSERT INTO terms
                (
                    academic_year_id,
                    term_number,
                    name,
                    is_current
                )
                VALUES
                (
                    %s,
                    1,
                    'Term 1',
                    1
                ),
                (
                    %s,
                    2,
                    'Term 2',
                    0
                ),
                (
                    %s,
                    3,
                    'Term 3',
                    0
                )
                """,
                (
                    year_id,
                    year_id,
                    year_id
                )
            )

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        created_year = fetch_one(
            """
            SELECT
                id,
                year,
                is_current,
                created_at,
                updated_at
            FROM academic_years
            WHERE id = %s
            LIMIT 1
            """,
            (year_id,)
        )

        terms = fetch_all(
            """
            SELECT
                id,
                academic_year_id,
                term_number,
                name,
                is_current,
                start_date,
                end_date,
                created_at,
                updated_at
            FROM terms
            WHERE academic_year_id = %s
            ORDER BY term_number ASC
            """,
            (year_id,)
        )

        created_year["is_current"] = bool(
            created_year["is_current"]
        )

        for term in terms:

            term["is_current"] = bool(
                term["is_current"]
            )

        created_year["terms"] = terms

        return jsonify({
            "success": True,
            "message": (
                f"Academic year {requested_year} created successfully."
            ),
            "year": created_year,
            "terms": terms,
            "data": created_year
        }), 201

    except mysql.connector.IntegrityError:

        return json_error(
            "That academic year already exists.",
            409
        )

    except Exception as error:

        print("CREATE YEAR ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to create academic year.",
            "error": str(error)
        }), 500


# ============================================================
# GET TERM
# ============================================================

@app.route("/api/terms/<int:term_id>", methods=["GET"])
def get_term(term_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        term = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                t.is_current,
                t.start_date,
                t.end_date,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        term["is_current"] = bool(
            term["is_current"]
        )

        if term.get("start_date"):
            term["start_date"] = (
                term["start_date"].isoformat()
            )

        if term.get("end_date"):
            term["end_date"] = (
                term["end_date"].isoformat()
            )

        return jsonify({
            "success": True,
            "term": term,
            "data": term
        })

    except Exception as error:

        print("GET TERM ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to load term.",
            "error": str(error)
        }), 500


# ============================================================
# UPDATE TERM
# ============================================================

@app.route("/api/terms/<int:term_id>", methods=["PUT"])
def update_term(term_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        term = fetch_one(
            """
            SELECT
                id,
                academic_year_id,
                term_number,
                name,
                is_current,
                start_date,
                end_date
            FROM terms
            WHERE id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        name = data.get(
            "name",
            term["name"]
        )

        start_date = data.get(
            "start_date",
            term["start_date"]
        )

        end_date = data.get(
            "end_date",
            term["end_date"]
        )

        is_current = data.get(
            "is_current",
            term["is_current"]
        )

        conn = get_db()
        cursor = conn.cursor()

        try:

            if is_current:

                cursor.execute(
                    """
                    UPDATE terms
                    SET is_current = 0
                    WHERE academic_year_id = %s
                    """,
                    (
                        term["academic_year_id"],
                    )
                )

            cursor.execute(
                """
                UPDATE terms
                SET
                    name = %s,
                    start_date = %s,
                    end_date = %s,
                    is_current = %s
                WHERE id = %s
                """,
                (
                    name,
                    start_date if start_date else None,
                    end_date if end_date else None,
                    1 if is_current else 0,
                    term_id
                )
            )

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        updated = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                t.is_current,
                t.start_date,
                t.end_date,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        updated["is_current"] = bool(
            updated["is_current"]
        )

        if updated.get("start_date"):
            updated["start_date"] = (
                updated["start_date"].isoformat()
            )

        if updated.get("end_date"):
            updated["end_date"] = (
                updated["end_date"].isoformat()
            )

        return jsonify({
            "success": True,
            "message": "Term updated successfully.",
            "term": updated,
            "data": updated
        })

    except Exception as error:

        print("UPDATE TERM ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to update term.",
            "error": str(error)
        }), 500


# ============================================================
# EMPLOYEES — LIST
# ============================================================

@app.route("/api/employees", methods=["GET"])
def get_employees():

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        employees = fetch_all(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active,
                created_at,
                updated_at
            FROM employees
            WHERE is_active = 1
            ORDER BY full_name ASC
            """
        )

        for employee in employees:

            employee["is_active"] = bool(
                employee["is_active"]
            )

            if employee.get("daily_rate") is not None:
                employee["daily_rate"] = float(
                    employee["daily_rate"]
                )

            if employee.get("created_at"):
                employee["created_at"] = (
                    employee["created_at"].isoformat()
                )

            if employee.get("updated_at"):
                employee["updated_at"] = (
                    employee["updated_at"].isoformat()
                )

        return jsonify({
            "success": True,
            "employees": employees,
            "data": employees
        })

    except Exception as error:

        print("GET EMPLOYEES ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to load employees.",
            "error": str(error)
        }), 500


# ============================================================
# EMPLOYEE — SINGLE
# ============================================================

@app.route("/api/employees/<int:employee_id>", methods=["GET"])
def get_employee(employee_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active,
                created_at,
                updated_at
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        employee["is_active"] = bool(
            employee["is_active"]
        )

        if employee.get("daily_rate") is not None:
            employee["daily_rate"] = float(
                employee["daily_rate"]
            )

        if employee.get("created_at"):
            employee["created_at"] = (
                employee["created_at"].isoformat()
            )

        if employee.get("updated_at"):
            employee["updated_at"] = (
                employee["updated_at"].isoformat()
            )

        return jsonify({
            "success": True,
            "employee": employee,
            "data": employee
        })

    except Exception as error:

        print("GET EMPLOYEE ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to load employee.",
            "error": str(error)
        }), 500


# ============================================================
# CREATE / REPAIR EMPLOYEE LOGIN ACCOUNT
# ============================================================

@app.route(
    "/api/employees/<int:employee_id>/account",
    methods=["POST"]
)
def create_employee_account(employee_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        # ----------------------------------------------------
        # GET EMPLOYEE
        # ----------------------------------------------------

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                email,
                is_active
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:
            return json_error(
                "Employee not found.",
                404
            )

        if not employee["is_active"]:
            return json_error(
                "This employee is inactive.",
                403
            )

        # ----------------------------------------------------
        # USERNAME
        # ----------------------------------------------------

        username = str(
            employee["full_name"]
        ).strip()

        if not username:
            return json_error(
                "Employee name is required."
            )

        # ----------------------------------------------------
        # CREATE FIXED DEFAULT PASSWORD
        #
        # John
        # -> john.pathwheelers
        #
        # John Kamau
        # -> johnkamau.pathwheelers
        # ----------------------------------------------------

        password_username = re.sub(
            r"[^a-zA-Z0-9]",
            "",
            username
        ).lower()

        if not password_username:
            return json_error(
                "A valid employee name is required to create the password."
            )

        temporary_password = (
            password_username
            + ".pathwheelers"
        )

        password_hash = generate_password_hash(
            temporary_password
        )

        # ----------------------------------------------------
        # CHECK EXISTING ACCOUNT
        # ----------------------------------------------------

        existing = fetch_one(
            """
            SELECT
                id,
                full_name,
                email,
                password_hash,
                role,
                employee_id,
                is_active
            FROM users
            WHERE employee_id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        # ----------------------------------------------------
        # ACCOUNT ALREADY EXISTS
        # ----------------------------------------------------

        if existing:

            # -----------------------------------------------
            # Make sure this really is an employee account
            # -----------------------------------------------

            if existing["role"] != "employee":

                return json_error(
                    "This employee is linked to another type of user account.",
                    409
                )

            # -----------------------------------------------
            # ACCOUNT HAS NO PASSWORD
            #
            # Repair old accounts created before the new
            # password system was implemented.
            # -----------------------------------------------

            if not existing["password_hash"]:

                conn = get_db()
                cursor = conn.cursor()

                try:

                    cursor.execute(
                        """
                        UPDATE users
                        SET
                            full_name = %s,
                            email = %s,
                            password_hash = %s,
                            is_active = 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s
                        """,
                        (
                            username,
                            employee["email"],
                            password_hash,
                            existing["id"]
                        )
                    )

                    conn.commit()

                except Exception:

                    conn.rollback()
                    raise

                finally:

                    cursor.close()
                    conn.close()

                repaired_user = fetch_one(
                    """
                    SELECT
                        id,
                        full_name,
                        email,
                        role,
                        employee_id,
                        google_id,
                        is_active,
                        created_at,
                        updated_at
                    FROM users
                    WHERE id = %s
                    LIMIT 1
                    """,
                    (existing["id"],)
                )

                return jsonify({
                    "success": True,
                    "message": (
                        "Employee login account repaired successfully."
                    ),
                    "account": {
                        "username": username,
                        "password": temporary_password
                    },
                    "user": user_to_dict(
                        repaired_user
                    )
                }), 200

            # -----------------------------------------------
            # ACCOUNT ALREADY HAS A PASSWORD
            # -----------------------------------------------

            return json_error(
                "This employee already has a login account.",
                409
            )

        # ----------------------------------------------------
        # CREATE NEW ACCOUNT
        # ----------------------------------------------------

        employee_email = (
            employee["email"]
            if employee["email"]
            else None
        )

        conn = get_db()
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                INSERT INTO users
                (
                    full_name,
                    email,
                    password_hash,
                    role,
                    employee_id,
                    is_active
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    'employee',
                    %s,
                    1
                )
                """,
                (
                    username,
                    employee_email,
                    password_hash,
                    employee_id
                )
            )

            user_id = cursor.lastrowid

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        # ----------------------------------------------------
        # GET CREATED ACCOUNT
        # ----------------------------------------------------

        created_user = fetch_one(
            """
            SELECT
                id,
                full_name,
                email,
                role,
                employee_id,
                google_id,
                is_active,
                created_at,
                updated_at
            FROM users
            WHERE id = %s
            LIMIT 1
            """,
            (user_id,)
        )

        return jsonify({
            "success": True,
            "message": (
                "Employee login account created successfully."
            ),
            "account": {
                "username": username,
                "password": temporary_password
            },
            "user": user_to_dict(
                created_user
            )
        }), 201

    except Exception as error:

        print(
            "CREATE / REPAIR EMPLOYEE ACCOUNT ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": (
                "Failed to create or repair employee account."
            ),
            "error": str(error)
        }), 500
    
# ============================================================
# CREATE EMPLOYEE + EMPLOYEE LOGIN ACCOUNT
# ============================================================

@app.route(
    "/api/employees",
    methods=["POST"]
)
def create_employee():

    user, error_response = require_admin()

    if error_response:
        return error_response

    conn = None
    cursor = None

    try:

        data = request.get_json(
            silent=True
        ) or {}

        # ----------------------------------------------------
        # EMPLOYEE DETAILS
        # ----------------------------------------------------

        full_name = str(
            data.get("full_name", "")
        ).strip()

        phone = str(
            data.get("phone", "")
        ).strip()

        email = data.get("email")

        if email is not None:
            email = str(email).strip()

        profile_picture = data.get(
            "profile_picture"
        )

        daily_rate = data.get(
            "daily_rate",
            0
        )

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if not full_name:
            return json_error(
                "Employee name is required."
            )

        try:
            daily_rate = float(
                daily_rate
            )
        except (ValueError, TypeError):
            return json_error(
                "Daily rate must be a valid number."
            )

        if daily_rate < 0:
            return json_error(
                "Daily rate cannot be negative."
            )

        # ----------------------------------------------------
        # CHECK DUPLICATE EMPLOYEE NAME
        # ----------------------------------------------------

        existing_employee = fetch_one(
            """
            SELECT
                id
            FROM employees
            WHERE LOWER(TRIM(full_name))
                = LOWER(TRIM(%s))
            LIMIT 1
            """,
            (full_name,)
        )

        if existing_employee:

            return json_error(
                "An employee with this name already exists.",
                409
            )

        # ----------------------------------------------------
        # CREATE DEFAULT EMPLOYEE PASSWORD
        #
        # John
        # -> john.pathwheelers
        #
        # John Kamau
        # -> johnkamau.pathwheelers
        # ----------------------------------------------------

        password_username = re.sub(
            r"[^a-zA-Z0-9]",
            "",
            full_name
        ).lower()

        if not password_username:

            return json_error(
                "A valid employee name is required."
            )

        default_password = (
            password_username
            + ".pathwheelers"
        )

        password_hash = generate_password_hash(
            default_password
        )

        # ----------------------------------------------------
        # START TRANSACTION
        # ----------------------------------------------------

        conn = get_db()
        cursor = conn.cursor()

        # ----------------------------------------------------
        # CREATE EMPLOYEE
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO employees
            (
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                1
            )
            """,
            (
                full_name,
                phone or None,
                email or None,
                profile_picture,
                daily_rate
            )
        )

        employee_id = cursor.lastrowid

        # ----------------------------------------------------
        # INTERNAL USER EMAIL
        #
        # Employee does not need a real email to log in.
        # This exists only because users.email is NOT NULL.
        #
        # Example:
        # employee_5@pathwheelers.local
        # ----------------------------------------------------

        user_email = (
            f"employee_{employee_id}@pathwheelers.local"
        )

        # ----------------------------------------------------
        # CREATE EMPLOYEE LOGIN ACCOUNT
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO users
            (
                full_name,
                email,
                password_hash,
                role,
                employee_id,
                is_active
            )
            VALUES
            (
                %s,
                %s,
                %s,
                'employee',
                %s,
                1
            )
            """,
            (
                full_name,
                user_email,
                password_hash,
                employee_id
            )
        )

        user_id = cursor.lastrowid

        # ----------------------------------------------------
        # COMMIT BOTH RECORDS
        # ----------------------------------------------------

        conn.commit()

        # ----------------------------------------------------
        # GET CREATED EMPLOYEE
        # ----------------------------------------------------

        created_employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active,
                created_at,
                updated_at
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if created_employee:

            created_employee["is_active"] = bool(
                created_employee["is_active"]
            )

            if created_employee.get(
                "daily_rate"
            ) is not None:

                created_employee["daily_rate"] = float(
                    created_employee["daily_rate"]
                )

            if created_employee.get(
                "created_at"
            ):

                created_employee["created_at"] = (
                    created_employee["created_at"].isoformat()
                )

            if created_employee.get(
                "updated_at"
            ):

                created_employee["updated_at"] = (
                    created_employee["updated_at"].isoformat()
                )

        # ----------------------------------------------------
        # GET CREATED USER
        # ----------------------------------------------------

        created_user = fetch_one(
            """
            SELECT
                id,
                full_name,
                email,
                role,
                employee_id,
                google_id,
                is_active,
                created_at,
                updated_at
            FROM users
            WHERE id = %s
            LIMIT 1
            """,
            (user_id,)
        )

        # ----------------------------------------------------
        # RETURN RESULT
        # ----------------------------------------------------

        return jsonify({
            "success": True,

            "message": (
                "Employee and login account created successfully."
            ),

            "employee": created_employee,

            "account": {
                "username": full_name,
                "password": default_password
            },

            "user": user_to_dict(
                created_user
            )

        }), 201

    except Exception as error:

        if conn:

            try:
                conn.rollback()
            except Exception:
                pass

        print(
            "CREATE EMPLOYEE + ACCOUNT ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": (
                "Failed to create employee and login account."
            ),
            "error": str(error)
        }), 500

    finally:

        if cursor:

            try:
                cursor.close()
            except Exception:
                pass

        if conn:

            try:
                conn.close()
            except Exception:
                pass
                            
# ============================================================
# EMPLOYEES — UPDATE
# ============================================================

@app.route("/api/employees/<int:employee_id>", methods=["PUT"])
def update_employee(employee_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        data = request.get_json(
            silent=True
        ) or {}

        full_name = str(
            data.get(
                "full_name",
                employee["full_name"]
            )
        ).strip()

        phone = str(
            data.get(
                "phone",
                employee["phone"]
            )
        ).strip()

        email = clean_email(
            data.get(
                "email",
                employee["email"] or ""
            )
        )

        profile_picture = data.get(
            "profile_picture",
            employee["profile_picture"]
        )

        daily_rate = data.get(
            "daily_rate",
            employee["daily_rate"]
        )

        is_active = data.get(
            "is_active",
            employee["is_active"]
        )

        if not full_name:

            return json_error(
                "Employee name is required."
            )

        if not phone:

            return json_error(
                "Employee phone number is required."
            )

        try:

            daily_rate = float(
                daily_rate
            )

        except (ValueError, TypeError):

            return json_error(
                "Daily rate must be a valid number."
            )

        if daily_rate < 0:

            return json_error(
                "Daily rate cannot be negative."
            )

        duplicate_phone = fetch_one(
            """
            SELECT id
            FROM employees
            WHERE phone = %s
              AND id != %s
            LIMIT 1
            """,
            (
                phone,
                employee_id
            )
        )

        if duplicate_phone:

            return json_error(
                "Another employee already uses this phone number.",
                409
            )

        if email:

            duplicate_email = fetch_one(
                """
                SELECT id
                FROM employees
                WHERE email = %s
                  AND id != %s
                LIMIT 1
                """,
                (
                    email,
                    employee_id
                )
            )

            if duplicate_email:

                return json_error(
                    "Another employee already uses this email.",
                    409
                )

        conn = get_db()
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                UPDATE employees
                SET
                    full_name = %s,
                    phone = %s,
                    email = %s,
                    profile_picture = %s,
                    daily_rate = %s,
                    is_active = %s
                WHERE id = %s
                """,
                (
                    full_name,
                    phone,
                    email if email else None,
                    profile_picture,
                    daily_rate,
                    1 if is_active else 0,
                    employee_id
                )
            )

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        updated = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active,
                created_at,
                updated_at
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        updated["is_active"] = bool(
            updated["is_active"]
        )

        updated["daily_rate"] = float(
            updated["daily_rate"]
        )

        if updated.get("created_at"):
            updated["created_at"] = (
                updated["created_at"].isoformat()
            )

        if updated.get("updated_at"):
            updated["updated_at"] = (
                updated["updated_at"].isoformat()
            )

        return jsonify({
            "success": True,
            "message": "Employee updated successfully.",
            "employee": updated,
            "data": updated
        })

    except Exception as error:

        print("UPDATE EMPLOYEE ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to update employee.",
            "error": str(error)
        }), 500


# ============================================================
# EMPLOYEES — DELETE / DEACTIVATE
# ============================================================

@app.route("/api/employees/<int:employee_id>", methods=["DELETE"])
def delete_employee(employee_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        employee = fetch_one(
            """
            SELECT id, full_name
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        # ----------------------------------------------------
        # IMPORTANT:
        # We DO NOT physically delete employees.
        #
        # Historical attendance and payments must remain
        # permanently available.
        # ----------------------------------------------------

        execute_query(
            """
            UPDATE employees
            SET is_active = 0
            WHERE id = %s
            """,
            (employee_id,)
        )

        # Also disable their login if one exists
        execute_query(
            """
            UPDATE users
            SET is_active = 0
            WHERE employee_id = %s
            """,
            (employee_id,)
        )

        return jsonify({
            "success": True,
            "message": (
                f"{employee['full_name']} was archived successfully."
            )
        })

    except Exception as error:

        print("DELETE EMPLOYEE ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to archive employee.",
            "error": str(error)
        }), 500


# ============================================================
# EMPLOYEE — RESTORE
# ============================================================

@app.route("/api/employees/<int:employee_id>/restore", methods=["POST"])
def restore_employee(employee_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        employee = fetch_one(
            """
            SELECT id, full_name
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        execute_query(
            """
            UPDATE employees
            SET is_active = 1
            WHERE id = %s
            """,
            (employee_id,)
        )

        execute_query(
            """
            UPDATE users
            SET is_active = 1
            WHERE employee_id = %s
            """,
            (employee_id,)
        )

        return jsonify({
            "success": True,
            "message": (
                f"{employee['full_name']} was restored successfully."
            )
        })

    except Exception as error:

        print("RESTORE EMPLOYEE ERROR:", error)

        return jsonify({
            "success": False,
            "message": "Failed to restore employee.",
            "error": str(error)
        }), 500


# ============================================================
# CREATE EMPLOYEE LOGIN
# ============================================================

    
# ============================================================
# EMPLOYEE PROFILE
# ============================================================

@app.route(
    "/api/employees/<int:employee_id>/profile",
    methods=["PUT"]
)
def update_employee_profile(employee_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    # Employee can edit their own profile.
    # Admin can edit any employee profile.

    if (
        user["role"] != "admin"
        and user.get("employee_id") != employee_id
    ):
        return json_error(
            "You are not allowed to edit this profile.",
            403
        )

    try:

        data = request.get_json(
            silent=True
        ) or {}

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        # ----------------------------------------------------
        # Employee name and phone can be updated.
        # Daily rate is admin-controlled.
        # ----------------------------------------------------

        full_name = data.get(
            "full_name",
            employee["full_name"]
        )

        phone = data.get(
            "phone",
            employee["phone"]
        )

        profile_picture = data.get(
            "profile_picture",
            employee["profile_picture"]
        )

        if user["role"] == "admin":

            daily_rate = data.get(
                "daily_rate",
                employee["daily_rate"]
            )

        else:

            daily_rate = employee["daily_rate"]

        full_name = str(
            full_name
        ).strip()

        phone = str(
            phone
        ).strip()

        try:

            daily_rate = float(
                daily_rate
            )

        except (ValueError, TypeError):

            return json_error(
                "Daily rate must be a valid number."
            )

        if daily_rate < 0:

            return json_error(
                "Daily rate cannot be negative."
            )

        conn = get_db()
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                UPDATE employees
                SET
                    full_name = %s,
                    phone = %s,
                    profile_picture = %s,
                    daily_rate = %s
                WHERE id = %s
                """,
                (
                    full_name,
                    phone,
                    profile_picture,
                    daily_rate,
                    employee_id
                )
            )

            # Keep linked user name synchronized
            cursor.execute(
                """
                UPDATE users
                SET full_name = %s
                WHERE employee_id = %s
                """,
                (
                    full_name,
                    employee_id
                )
            )

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        updated = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate,
                is_active,
                created_at,
                updated_at
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        updated["is_active"] = bool(
            updated["is_active"]
        )

        if updated.get("daily_rate") is not None:
            updated["daily_rate"] = float(
                updated["daily_rate"]
            )

        if updated.get("created_at"):
            updated["created_at"] = (
                updated["created_at"].isoformat()
            )

        if updated.get("updated_at"):
            updated["updated_at"] = (
                updated["updated_at"].isoformat()
            )

        return jsonify({
            "success": True,
            "message": "Profile updated successfully.",
            "employee": updated,
            "data": updated
        })

    except Exception as error:

        print(
            "UPDATE EMPLOYEE PROFILE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to update employee profile.",
            "error": str(error)
        }), 500

    # ============================================================
# ATTENDANCE
# ============================================================


def attendance_to_dict(row):

    return {

        "id":
            row["id"],

        "employee_id":
            row["employee_id"],

        "employee_name":
            row.get("employee_name"),

        "profile_picture":
            row.get("profile_picture"),

        "term_id":
            row["term_id"],

        "academic_year_id":
            row.get("academic_year_id"),

        "year":
            row.get("year"),

        "term_number":
            row.get("term_number"),

        "term_name":
            row.get("term_name"),

        "attendance_date": (
            row["attendance_date"].isoformat()
            if row.get("attendance_date")
            else None
        ),

        "status":
            row["status"],

        "amount_earned": (
            float(row["amount_earned"])
            if row.get("amount_earned") is not None
            else 0
        ),

        "notes":
            row.get("notes") or "",

        "created_at": (
            row["created_at"].isoformat()
            if row.get("created_at")
            else None
        ),

        "updated_at": (
            row["updated_at"].isoformat()
            if row.get("updated_at")
            else None
        )

    }

# ============================================================
# GET ATTENDANCE FOR A TERM
# ============================================================

@app.route(
    "/api/terms/<int:term_id>/attendance",
    methods=["GET"]
)
def get_term_attendance(term_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        # ----------------------------------------------------
        # Make sure term exists
        # ----------------------------------------------------

        term = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        # ----------------------------------------------------
        # Optional date filter
        # ----------------------------------------------------

        attendance_date = request.args.get(
            "date"
        )

        # ----------------------------------------------------
        # Optional employee filter
        # ----------------------------------------------------

        employee_id = request.args.get(
            "employee_id"
        )

        # ----------------------------------------------------
        # Build query
        # ----------------------------------------------------

        query = """
            SELECT
                a.id,
                a.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                a.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                a.attendance_date,
                a.status,
                a.amount_earned,
                a.notes,
                a.created_at,
                a.updated_at
            FROM attendance a
            JOIN employees e
                ON e.id = a.employee_id
            JOIN terms t
                ON t.id = a.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE a.term_id = %s
        """

        params = [term_id]

        if attendance_date:

            query += """
                AND a.attendance_date = %s
            """

            params.append(
                attendance_date
            )

        if employee_id:

            query += """
                AND a.employee_id = %s
            """

            params.append(
                employee_id
            )

        query += """
            ORDER BY
                a.attendance_date DESC,
                e.full_name ASC
        """

        rows = fetch_all(
            query,
            tuple(params)
        )

        attendance = [
            attendance_to_dict(row)
            for row in rows
        ]

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        total_records = len(attendance)

        present_count = sum(
            1
            for item in attendance
            if item["status"] == "present"
        )

        absent_count = sum(
            1
            for item in attendance
            if item["status"] == "absent"
        )

        total_earned = sum(
            float(
                item.get(
                    "amount_earned",
                    0
                ) or 0
            )
            for item in attendance
        )

        return jsonify({
            "success": True,

            "term": {
                "id": term["id"],
                "academic_year_id": term["academic_year_id"],
                "year": term["year"],
                "term_number": term["term_number"],
                "name": term["name"]
            },

            "attendance": attendance,

            "records": attendance,

            "summary": {
                "total": total_records,
                "present": present_count,
                "absent": absent_count,
                "total_earned": total_earned
            },

            "data": attendance
        })

    except Exception as error:

        print(
            "GET TERM ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to load attendance.",
            "error": str(error)
        }), 500




# ============================================================
# GET ATTENDANCE FOR A SPECIFIC DATE
# ============================================================

@app.route(
    "/api/terms/<int:term_id>/attendance/date",
    methods=["GET"]
)
def get_attendance_for_date(term_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        attendance_date = request.args.get(
            "date"
        )

        if not attendance_date:

            attendance_date = (
                datetime.now()
                .date()
                .isoformat()
            )

        # ----------------------------------------------------
        # Validate date
        # ----------------------------------------------------

        try:

            datetime.strptime(
                attendance_date,
                "%Y-%m-%d"
            )

        except ValueError:

            return json_error(
                "Invalid date. Use YYYY-MM-DD."
            )

        # ----------------------------------------------------
        # Make sure term exists
        # ----------------------------------------------------

        term = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        # ----------------------------------------------------
        # Return ALL active employees.
        #
        # If attendance exists, use its saved values.
        #
        # If attendance does not exist:
        # status = absent
        # amount_earned = 0
        # notes = ""
        #
        # IMPORTANT:
        # We do NOT use employee.daily_rate.
        # ----------------------------------------------------

        rows = fetch_all(
            """
            SELECT
                e.id AS employee_id,
                e.full_name AS employee_name,
                e.profile_picture,

                a.id AS attendance_id,
                a.status,
                a.amount_earned,
                a.notes

            FROM employees e

            LEFT JOIN attendance a
                ON a.employee_id = e.id
                AND a.term_id = %s
                AND a.attendance_date = %s

            WHERE e.is_active = 1

            ORDER BY e.full_name ASC
            """,
            (
                term_id,
                attendance_date
            )
        )

        records = []

        for row in rows:

            amount_earned = (
                row["amount_earned"]
                if row["amount_earned"] is not None
                else 0
            )

            records.append({

                "employee_id":
                    row["employee_id"],

                "employee_name":
                    row["employee_name"],

                "profile_picture":
                    row["profile_picture"],

                "attendance_id":
                    row["attendance_id"],

                "status":
                    (
                        row["status"]
                        if row["status"]
                        else "absent"
                    ),

                "amount_earned":
                    float(amount_earned),

                "notes":
                    row["notes"] or ""
            })

        # ----------------------------------------------------
        # Summary for this date
        # ----------------------------------------------------

        present_count = sum(
            1
            for item in records
            if item["status"] == "present"
        )

        absent_count = sum(
            1
            for item in records
            if item["status"] == "absent"
        )

        total_earned = sum(
            item["amount_earned"]
            for item in records
        )

        return jsonify({

            "success": True,

            "date":
                attendance_date,

            "term_id":
                term_id,

            "attendance":
                records,

            "records":
                records,

            "summary": {

                "total":
                    len(records),

                "present":
                    present_count,

                "absent":
                    absent_count,

                "total_earned":
                    total_earned
            },

            "data":
                records
        })

    except Exception as error:

        print(
            "GET ATTENDANCE DATE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to load attendance for date.",
            "error": str(error)
        }), 500


# ============================================================
# SAVE SINGLE ATTENDANCE
# ============================================================

@app.route(
    "/api/attendance",
    methods=["POST"]
)
def create_attendance():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        employee_id = data.get(
            "employee_id"
        )

        term_id = data.get(
            "term_id"
        )

        attendance_date = data.get(
            "attendance_date",
            data.get("date")
        )

        status = str(
            data.get(
                "status",
                "present"
            )
        ).lower().strip()

        notes = data.get(
            "notes",
            ""
        )

        # ====================================================
        # AMOUNT EARNED
        # ====================================================

        amount_earned = data.get(
            "amount_earned"
        )

        if not employee_id:

            return json_error(
                "Employee ID is required."
            )

        if not term_id:

            return json_error(
                "Term ID is required."
            )

        if not attendance_date:

            attendance_date = datetime.now().date().isoformat()

        try:

            employee_id = int(
                employee_id
            )

            term_id = int(
                term_id
            )

        except (ValueError, TypeError):

            return json_error(
                "Employee ID and term ID must be valid numbers."
            )

        try:

            datetime.strptime(
                attendance_date,
                "%Y-%m-%d"
            )

        except ValueError:

            return json_error(
                "Invalid attendance date. Use YYYY-MM-DD."
            )

        if status not in [
            "present",
            "absent"
        ]:

            return json_error(
                "Attendance status must be present or absent."
            )

        # ====================================================
        # AMOUNT VALIDATION
        # ====================================================

        if status == "absent":

            amount_earned = 0

        else:

            if amount_earned is None or str(
                amount_earned
            ).strip() == "":

                return json_error(
                    "Amount earned is required when attendance is present."
                )

            try:

                amount_earned = float(
                    amount_earned
                )

            except (ValueError, TypeError):

                return json_error(
                    "Amount earned must be a valid number."
                )

            if amount_earned < 0:

                return json_error(
                    "Amount earned cannot be negative."
                )

        # ====================================================
        # EMPLOYEE
        # ====================================================

        employee = fetch_one(
            """
            SELECT
                id,
                full_name
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        # ====================================================
        # TERM
        # ====================================================

        term = fetch_one(
            """
            SELECT
                id
            FROM terms
            WHERE id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        # ====================================================
        # CHECK EXISTING ATTENDANCE
        # ====================================================

        existing = fetch_one(
            """
            SELECT
                id
            FROM attendance
            WHERE employee_id = %s
              AND term_id = %s
              AND attendance_date = %s
            LIMIT 1
            """,
            (
                employee_id,
                term_id,
                attendance_date
            )
        )

        # ====================================================
        # UPDATE EXISTING
        # ====================================================

        if existing:

            execute_query(
                """
                UPDATE attendance
                SET
                    status = %s,
                    amount_earned = %s,
                    notes = %s
                WHERE id = %s
                """,
                (
                    status,
                    amount_earned,
                    notes,
                    existing["id"]
                )
            )

            attendance_id = existing["id"]

            message = (
                "Attendance updated successfully."
            )

        # ====================================================
        # CREATE NEW
        # ====================================================

        else:

            conn = get_db()
            cursor = conn.cursor()

            try:

                cursor.execute(
                    """
                    INSERT INTO attendance
                    (
                        employee_id,
                        term_id,
                        attendance_date,
                        status,
                        amount_earned,
                        notes
                    )
                    VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        employee_id,
                        term_id,
                        attendance_date,
                        status,
                        amount_earned,
                        notes
                    )
                )

                attendance_id = cursor.lastrowid

                conn.commit()

            except Exception:

                conn.rollback()
                raise

            finally:

                cursor.close()
                conn.close()

            message = (
                "Attendance saved successfully."
            )

        # ====================================================
        # GET SAVED RECORD
        # ====================================================

        record = fetch_one(
            """
            SELECT
                a.id,
                a.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                a.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                a.attendance_date,
                a.status,
                a.amount_earned,
                a.notes,
                a.created_at,
                a.updated_at
            FROM attendance a
            JOIN employees e
                ON e.id = a.employee_id
            JOIN terms t
                ON t.id = a.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE a.id = %s
            LIMIT 1
            """,
            (attendance_id,)
        )

        result = attendance_to_dict(
            record
        )

        return jsonify({
            "success": True,
            "message": message,
            "attendance": result,
            "data": result
        })

    except mysql.connector.IntegrityError as error:

        print(
            "CREATE ATTENDANCE INTEGRITY ERROR:",
            error
        )

        return json_error(
            "Attendance already exists for this employee, date and term.",
            409
        )

    except Exception as error:

        print(
            "CREATE ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to save attendance.",
            "error": str(error)
        }), 500


# ============================================================
# SAVE BULK ATTENDANCE
# ============================================================

@app.route(
    "/api/attendance/bulk",
    methods=["POST"]
)
def save_bulk_attendance():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        term_id = data.get(
            "term_id"
        )

        attendance_date = data.get(
            "attendance_date",
            data.get("date")
        )

        records = data.get(
            "attendance",
            data.get(
                "records",
                data.get(
                    "employees",
                    []
                )
            )
        )

        if not term_id:

            return json_error(
                "Term ID is required."
            )

        if not attendance_date:

            attendance_date = (
                datetime.now()
                .date()
                .isoformat()
            )

        try:

            term_id = int(
                term_id
            )

        except (ValueError, TypeError):

            return json_error(
                "Term ID must be a valid number."
            )

        try:

            datetime.strptime(
                attendance_date,
                "%Y-%m-%d"
            )

        except ValueError:

            return json_error(
                "Invalid attendance date. Use YYYY-MM-DD."
            )

        if not isinstance(
            records,
            list
        ):

            return json_error(
                "Attendance records must be an array."
            )

        term = fetch_one(
            """
            SELECT
                id,
                academic_year_id,
                term_number,
                name
            FROM terms
            WHERE id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        # ----------------------------------------------------
        # One transaction for the entire attendance save.
        # ----------------------------------------------------

        conn = get_db()

        cursor = conn.cursor()

        saved = []
        skipped = []
        errors = []

        try:

            for item in records:

                employee_id = item.get(
                    "employee_id"
                )

                status = str(
                    item.get(
                        "status",
                        "absent"
                    )
                ).lower().strip()

                notes = item.get(
                    "notes",
                    ""
                )

                # ------------------------------------------------
                # AMOUNT EARNED
                #
                # This is entered manually by the user.
                # We DO NOT use the employee daily rate.
                # ------------------------------------------------

                amount_earned = item.get(
                    "amount_earned"
                )
                print(
    "ATTENDANCE DEBUG:",
    "employee_id =", employee_id,
    "raw amount_earned =", repr(amount_earned),
    "full item =", item
)

                if amount_earned in [
                    None,
                    ""
                ]:

                    amount_earned = 0

                try:

                    amount_earned = float(
                        amount_earned
                    )

                except (
                    ValueError,
                    TypeError
                ):

                    errors.append({
                        "employee_id": employee_id,
                        "message": (
                            "Amount earned must be a valid number."
                        )
                    })

                    continue

                if amount_earned < 0:

                    errors.append({
                        "employee_id": employee_id,
                        "message": (
                            "Amount earned cannot be negative."
                        )
                    })

                    continue

                if not employee_id:

                    errors.append({
                        "record": item,
                        "message": (
                            "Employee ID is missing."
                        )
                    })

                    continue

                try:

                    employee_id = int(
                        employee_id
                    )

                except (
                    ValueError,
                    TypeError
                ):

                    errors.append({
                        "record": item,
                        "message": (
                            "Invalid employee ID."
                        )
                    })

                    continue

                if status not in [
                    "present",
                    "absent"
                ]:

                    errors.append({
                        "employee_id": employee_id,
                        "message": (
                            "Status must be present or absent."
                        )
                    })

                    continue

                # ------------------------------------------------
                # CHECK EMPLOYEE
                # ------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id,
                        full_name
                    FROM employees
                    WHERE id = %s
                    LIMIT 1
                    """,
                    (employee_id,)
                )

                employee = cursor.fetchone()

                if not employee:

                    errors.append({
                        "employee_id": employee_id,
                        "message": (
                            "Employee not found."
                        )
                    })

                    continue

                # ------------------------------------------------
                # CHECK EXISTING ATTENDANCE
                # ------------------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id
                    FROM attendance
                    WHERE employee_id = %s
                      AND term_id = %s
                      AND attendance_date = %s
                    LIMIT 1
                    """,
                    (
                        employee_id,
                        term_id,
                        attendance_date
                    )
                )

                existing = cursor.fetchone()

                # ------------------------------------------------
                # UPDATE EXISTING ATTENDANCE
                # ------------------------------------------------

                if existing:

                    cursor.execute(
                        """
                        UPDATE attendance
                        SET
                            status = %s,
                            amount_earned = %s,
                            notes = %s
                        WHERE id = %s
                        """,
                        (
                            status,
                            amount_earned,
                            notes,
                            existing["id"]
                        )
                    )

                    saved.append({
                        "employee_id": employee_id,
                        "employee_name": employee["full_name"],
                        "attendance_id": existing["id"],
                        "status": status,
                        "amount_earned": amount_earned,
                        "notes": notes,
                        "action": "updated"
                    })

                # ------------------------------------------------
                # CREATE NEW ATTENDANCE
                # ------------------------------------------------

                else:

                    cursor.execute(
                        """
                        INSERT INTO attendance
                        (
                            employee_id,
                            term_id,
                            attendance_date,
                            status,
                            amount_earned,
                            notes
                        )
                        VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s
                        )
                        """,
                        (
                            employee_id,
                            term_id,
                            attendance_date,
                            status,
                            amount_earned,
                            notes
                        )
                    )

                    attendance_id = cursor.lastrowid

                    saved.append({
                        "employee_id": employee_id,
                        "employee_name": employee["full_name"],
                        "attendance_id": attendance_id,
                        "status": status,
                        "amount_earned": amount_earned,
                        "notes": notes,
                        "action": "created"
                    })

            conn.commit()

        except Exception:

            conn.rollback()

            raise

        finally:

            cursor.close()

            conn.close()

        return jsonify({
            "success": True,

            "message": (
                f"Attendance saved for "
                f"{len(saved)} employee(s)."
            ),

            "date": attendance_date,

            "term_id": term_id,

            "saved": saved,

            "skipped": skipped,

            "errors": errors,

            "saved_count": len(saved),

            "skipped_count": len(skipped),

            "error_count": len(errors),

            "data": saved
        })

    except Exception as error:

        print(
            "BULK ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": (
                "Failed to save attendance."
            ),
            "error": str(error)
        }), 500


# ============================================================
# UPDATE ATTENDANCE
# ============================================================

@app.route(
    "/api/attendance/<int:attendance_id>",
    methods=["PUT"]
)
def update_attendance(attendance_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        existing = fetch_one(
            """
            SELECT
                id,
                employee_id,
                term_id,
                attendance_date,
                status,
                notes
            FROM attendance
            WHERE id = %s
            LIMIT 1
            """,
            (attendance_id,)
        )

        if not existing:

            return json_error(
                "Attendance record not found.",
                404
            )

        data = request.get_json(
            silent=True
        ) or {}

        status = str(
            data.get(
                "status",
                existing["status"]
            )
        ).lower().strip()

        notes = data.get(
            "notes",
            existing["notes"]
        )

        attendance_date = data.get(
            "attendance_date",
            existing["attendance_date"]
        )

        if status not in [
            "present",
            "absent"
        ]:

            return json_error(
                "Status must be present or absent."
            )

        if isinstance(
            attendance_date,
            datetime
        ):
            attendance_date = (
                attendance_date.date().isoformat()
            )

        elif hasattr(
            attendance_date,
            "isoformat"
        ):
            attendance_date = (
                attendance_date.isoformat()
            )

        try:

            datetime.strptime(
                attendance_date,
                "%Y-%m-%d"
            )

        except ValueError:

            return json_error(
                "Invalid attendance date. Use YYYY-MM-DD."
            )

        # Check for a conflicting record
        conflict = fetch_one(
            """
            SELECT
                id
            FROM attendance
            WHERE employee_id = %s
              AND term_id = %s
              AND attendance_date = %s
              AND id != %s
            LIMIT 1
            """,
            (
                existing["employee_id"],
                existing["term_id"],
                attendance_date,
                attendance_id
            )
        )

        if conflict:

            return json_error(
                "Another attendance record already exists for this date.",
                409
            )

        execute_query(
            """
            UPDATE attendance
            SET
                attendance_date = %s,
                status = %s,
                notes = %s
            WHERE id = %s
            """,
            (
                attendance_date,
                status,
                notes,
                attendance_id
            )
        )

        updated = fetch_one(
            """
            SELECT
                a.id,
                a.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                a.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                a.attendance_date,
                a.status,
                a.notes,
                a.created_at,
                a.updated_at
            FROM attendance a
            JOIN employees e
                ON e.id = a.employee_id
            JOIN terms t
                ON t.id = a.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE a.id = %s
            LIMIT 1
            """,
            (attendance_id,)
        )

        result = attendance_to_dict(
            updated
        )

        return jsonify({
            "success": True,
            "message": "Attendance updated successfully.",
            "attendance": result,
            "data": result
        })

    except Exception as error:

        print(
            "UPDATE ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to update attendance.",
            "error": str(error)
        }), 500


# ============================================================
# DELETE ATTENDANCE
# ============================================================

@app.route(
    "/api/attendance/<int:attendance_id>",
    methods=["DELETE"]
)
def delete_attendance(attendance_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        existing = fetch_one(
            """
            SELECT
                id,
                employee_id,
                term_id,
                attendance_date
            FROM attendance
            WHERE id = %s
            LIMIT 1
            """,
            (attendance_id,)
        )

        if not existing:

            return json_error(
                "Attendance record not found.",
                404
            )

        # Deleting an attendance record does not affect
        # any payment or employee history.

        execute_query(
            """
            DELETE FROM attendance
            WHERE id = %s
            """,
            (attendance_id,)
        )

        return jsonify({
            "success": True,
            "message": "Attendance record deleted successfully."
        })

    except Exception as error:

        print(
            "DELETE ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to delete attendance.",
            "error": str(error)
        }), 500


# ============================================================
# EMPLOYEE ATTENDANCE HISTORY
# ============================================================

@app.route(
    "/api/employees/<int:employee_id>/attendance",
    methods=["GET"]
)
def get_employee_attendance(employee_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    # Employee can only view their own attendance.
    if (
        user["role"] != "admin"
        and user.get("employee_id") != employee_id
    ):
        return json_error(
            "You are not allowed to view this attendance.",
            403
        )

    try:

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                profile_picture
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        term_id = request.args.get(
            "term_id"
        )

        query = """
            SELECT
                a.id,
                a.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                a.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                a.attendance_date,
                a.status,
                a.notes,
                a.created_at,
                a.updated_at
            FROM attendance a
            JOIN employees e
                ON e.id = a.employee_id
            JOIN terms t
                ON t.id = a.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE a.employee_id = %s
        """

        params = [
            employee_id
        ]

        if term_id:

            query += """
                AND a.term_id = %s
            """

            params.append(
                term_id
            )

        query += """
            ORDER BY
                a.attendance_date DESC
        """

        rows = fetch_all(
            query,
            tuple(params)
        )

        records = [
            attendance_to_dict(row)
            for row in rows
        ]

        present_count = sum(
            1
            for row in records
            if row["status"] == "present"
        )

        absent_count = sum(
            1
            for row in records
            if row["status"] == "absent"
        )

        return jsonify({
            "success": True,
            "employee": {
                "id": employee["id"],
                "full_name": employee["full_name"],
                "profile_picture": employee["profile_picture"]
            },
            "attendance": records,
            "records": records,
            "summary": {
                "total_days_recorded": len(records),
                "days_present": present_count,
                "days_absent": absent_count
            },
            "data": records
        })

    except Exception as error:

        print(
            "EMPLOYEE ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to load employee attendance.",
            "error": str(error)
        }), 500


# ============================================================
# ATTENDANCE SUMMARY FOR AN EMPLOYEE IN A TERM
# ============================================================

@app.route(
    "/api/terms/<int:term_id>/employees/<int:employee_id>/attendance-summary",
    methods=["GET"]
)
def employee_term_attendance_summary(
    term_id,
    employee_id
):

    user, error_response = require_auth()

    if error_response:
        return error_response

    if (
        user["role"] != "admin"
        and user.get("employee_id") != employee_id
    ):
        return json_error(
            "You are not allowed to view this information.",
            403
        )

    try:

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                profile_picture
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        term = fetch_one(
            """
            SELECT
                t.id,
                t.term_number,
                t.name,
                ay.id AS academic_year_id,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        summary = fetch_one(
            """
            SELECT
                COUNT(*) AS total_recorded,
                SUM(
                    CASE
                        WHEN status = 'present'
                        THEN 1
                        ELSE 0
                    END
                ) AS days_present,
                SUM(
                    CASE
                        WHEN status = 'absent'
                        THEN 1
                        ELSE 0
                    END
                ) AS days_absent
            FROM attendance
            WHERE employee_id = %s
              AND term_id = %s
            """,
            (
                employee_id,
                term_id
            )
        )

        return jsonify({
            "success": True,
            "employee": {
                "id": employee["id"],
                "full_name": employee["full_name"],
                "profile_picture": employee["profile_picture"]
            },
            "term": {
                "id": term["id"],
                "academic_year_id": term["academic_year_id"],
                "year": term["year"],
                "term_number": term["term_number"],
                "name": term["name"]
            },
            "summary": {
                "total_recorded": int(
                    summary["total_recorded"] or 0
                ),
                "days_present": int(
                    summary["days_present"] or 0
                ),
                "days_absent": int(
                    summary["days_absent"] or 0
                )
            }
        })

    except Exception as error:

        print(
            "ATTENDANCE SUMMARY ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to calculate attendance summary.",
            "error": str(error)
        }), 500


# ============================================================
# ATTENDANCE SEARCH
# ============================================================

@app.route(
    "/api/attendance/search",
    methods=["GET"]
)
def search_attendance():

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        search = request.args.get(
            "search",
            ""
        ).strip()

        term_id = request.args.get(
            "term_id"
        )

        status = request.args.get(
            "status"
        )

        date_from = request.args.get(
            "date_from"
        )

        date_to = request.args.get(
            "date_to"
        )

        query = """
            SELECT
                a.id,
                a.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                a.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                a.attendance_date,
                a.status,
                a.notes,
                a.created_at,
                a.updated_at
            FROM attendance a
            JOIN employees e
                ON e.id = a.employee_id
            JOIN terms t
                ON t.id = a.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE 1 = 1
        """

        params = []

        # Employees can only search their own records.
        if user["role"] != "admin":

            query += """
                AND a.employee_id = %s
            """

            params.append(
                user["employee_id"]
            )

        if search:

            query += """
                AND (
                    e.full_name LIKE %s
                    OR e.phone LIKE %s
                )
            """

            search_value = f"%{search}%"

            params.extend([
                search_value,
                search_value
            ])

        if term_id:

            query += """
                AND a.term_id = %s
            """

            params.append(
                term_id
            )

        if status:

            if status not in [
                "present",
                "absent"
            ]:

                return json_error(
                    "Invalid attendance status."
                )

            query += """
                AND a.status = %s
            """

            params.append(
                status
            )

        if date_from:

            query += """
                AND a.attendance_date >= %s
            """

            params.append(
                date_from
            )

        if date_to:

            query += """
                AND a.attendance_date <= %s
            """

            params.append(
                date_to
            )

        query += """
            ORDER BY
                a.attendance_date DESC,
                e.full_name ASC
        """

        rows = fetch_all(
            query,
            tuple(params)
        )

        records = [
            attendance_to_dict(row)
            for row in rows
        ]

        return jsonify({
            "success": True,
            "attendance": records,
            "records": records,
            "count": len(records),
            "data": records
        })

    except Exception as error:

        print(
            "SEARCH ATTENDANCE ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to search attendance.",
            "error": str(error)
        }), 500

    # ============================================================
# PAYMENTS
# ============================================================

def payment_to_dict(row):
    amount = row.get("amount")

    if amount is not None:
        amount = float(amount)

    return {
        "id": row["id"],
        "employee_id": row["employee_id"],
        "employee_name": row.get("employee_name"),
        "profile_picture": row.get("profile_picture"),
        "term_id": row["term_id"],
        "academic_year_id": row.get("academic_year_id"),
        "year": row.get("year"),
        "term_number": row.get("term_number"),
        "term_name": row.get("term_name"),
        "amount": amount,
        "paid_amount": amount,
        "method": row.get("method"),
        "payment_method": row.get("method"),
        "transaction_code": row.get("transaction_code"),
        "mpesa_code": row.get("transaction_code"),
        "reference": row.get("reference"),
        "phone": row.get("phone"),
        "receiver": row.get("receiver"),
        "transaction_date": (
            row["transaction_date"].isoformat()
            if row.get("transaction_date")
            else None
        ),
        "payment_date": (
            row["payment_date"].isoformat()
            if row.get("payment_date")
            else None
        ),
        "original_message": row.get("original_message"),
        "created_by": row.get("created_by"),
        "created_at": (
            row["created_at"].isoformat()
            if row.get("created_at")
            else None
        )
    }


# ============================================================
# PAYMENT MESSAGE PARSER
# ============================================================

def parse_payment_message(message):
    """
    Extract useful information from common Kenyan
    M-Pesa and bank SMS messages.

    This function ONLY parses the message.
    It does NOT save anything to the database.
    """

    if not message:
        return {
            "amount": None,
            "transaction_code": None,
            "phone": None,
            "receiver": None,
            "transaction_date": None,
            "reference": None,
            "raw_message": ""
        }

    text = str(message).strip()

    # ========================================================
    # TRANSACTION CODE / REFERENCE
    # ========================================================

    transaction_code = None
    reference = None

    # --------------------------------------------------------
    # 1. Explicit bank reference
    #
    # Examples:
    # Ref: BNK7X92PLQ
    # Reference: BNK7X92PLQ
    # Ref BNK7X92PLQ
    # --------------------------------------------------------

    explicit_reference_patterns = [
        r"\bref(?:erence)?\s*(?:number|no|#)?\s*[:\-]?\s*([A-Z0-9][A-Z0-9\-\/]{4,30})\b",

        r"\btransaction\s*(?:id|code|reference|ref)"
        r"\s*(?:number|no|#)?\s*[:\-]?\s*"
        r"([A-Z0-9][A-Z0-9\-\/]{4,30})\b",

        r"\btxn\s*(?:id|code|reference|ref)"
        r"\s*(?:number|no|#)?\s*[:\-]?\s*"
        r"([A-Z0-9][A-Z0-9\-\/]{4,30})\b"
    ]

    for pattern in explicit_reference_patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:

            candidate = match.group(1).strip().upper()

            # Make sure this is not an ordinary word.
            if (
                any(char.isdigit() for char in candidate)
                and len(candidate) >= 5
            ):
                reference = candidate
                transaction_code = candidate
                break

    # --------------------------------------------------------
    # 2. M-Pesa style transaction codes
    #
    # Examples:
    # QWE4RTY8UI
    # TJH7KQ4ABC
    # KCA7H2P9XZ
    # --------------------------------------------------------

    if not transaction_code:

        mpesa_patterns = [
            r"\b([A-Z]{2,4}\d[A-Z0-9]{5,12})\b"
        ]

        for pattern in mpesa_patterns:

            matches = re.findall(
                pattern,
                text,
                re.IGNORECASE
            )

            for candidate in matches:

                candidate = candidate.upper()

                # Must contain at least one digit.
                if not any(char.isdigit() for char in candidate):
                    continue

                # Ignore common words that happen to contain numbers.
                if candidate in {
                    "KSH",
                    "KES",
                    "MPESA",
                    "M-PESA"
                }:
                    continue

                transaction_code = candidate
                break

            if transaction_code:
                break

    # ========================================================
    # AMOUNT
    # ========================================================

    amount = None

    amount_patterns = [

        # Ksh 5,000.00
        r"(?:Ksh|KES|KSh|Sh)\s*"
        r"([0-9][0-9,]*(?:\.[0-9]{1,2})?)",

        # KES5,000
        r"(?:Ksh|KES|KSh|Sh)"
        r"([0-9][0-9,]*(?:\.[0-9]{1,2})?)",

        # amount of 5000
        r"(?:amount|paid|payment|sent|received|deposit|withdrawn)"
        r"\s*(?:of|:)?\s*"
        r"(?:Ksh|KES|KSh|Sh)?\s*"
        r"([0-9][0-9,]*(?:\.[0-9]{1,2})?)"
    ]

    for pattern in amount_patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:

            try:

                amount = float(
                    match.group(1).replace(",", "")
                )

                break

            except (ValueError, TypeError):

                pass

    # ========================================================
    # PHONE NUMBER
    # ========================================================

    phone = None

    phone_patterns = [

        # +254 712 345 678
        r"(\+254\s?7\d{2}\s?\d{3}\s?\d{3})",

        # 254712345678
        r"\b(2547\d{8})\b",

        # 0712345678
        r"\b(07\d{8})\b"
    ]

    for pattern in phone_patterns:

        match = re.search(
            pattern,
            text
        )

        if match:

            phone = (
                match.group(1)
                .replace(" ", "")
            )

            break

    # ========================================================
    # RECEIVER / RECIPIENT
    # ========================================================

    receiver = None

    receiver_patterns = [

        # Sent to JOHN KAMAU
        r"\b(?:sent\s+to|paid\s+to|to)\s+"
        r"([A-Za-z][A-Za-z .'-]{1,80}?)"
        r"(?=\s+(?:07\d{8}|2547\d{8}|\+254)|"
        r"\s+on\s+|\s+at\s+|\s+for\s+|"
        r"\s+Ref\b|\s+Reference\b|"
        r"\.|$)",

        # Received by JOHN KAMAU
        r"\b(?:received\s+by)\s+"
        r"([A-Za-z][A-Za-z .'-]{1,80}?)"
        r"(?=\s+(?:07\d{8}|2547\d{8}|\+254)|"
        r"\s+on\s+|\s+at\s+|\s+for\s+|"
        r"\s+Ref\b|\s+Reference\b|"
        r"\.|$)",

        # From JOHN KAMAU
        r"\b(?:from|received\s+from)\s+"
        r"([A-Za-z][A-Za-z .'-]{1,80}?)"
        r"(?=\s+(?:07\d{8}|2547\d{8}|\+254)|"
        r"\s+on\s+|\s+at\s+|\s+for\s+|"
        r"\s+Ref\b|\s+Reference\b|"
        r"\.|$)"
    ]

    for pattern in receiver_patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:

            receiver = match.group(1).strip()

            # Remove trailing punctuation.
            receiver = receiver.rstrip(".,;:")

            # Remove accidental whitespace.
            receiver = re.sub(
                r"\s+",
                " ",
                receiver
            ).strip()

            if receiver:
                break

   # ========================================================
# DATE
# ========================================================

    transaction_date = None

    date_patterns = [

        # 13/09/2026
        r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b",

        # 13-09-2026
        r"\b(\d{1,2})-(\d{1,2})-(\d{4})\b",

        # 2026-09-13
        r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b"
    ]

    for pattern in date_patterns:

        match = re.search(
            pattern,
            text
        )

        if not match:
            continue

        try:

            # YYYY-MM-DD
            if pattern == r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b":

                year = int(match.group(1))
                month = int(match.group(2))
                day = int(match.group(3))

            # DD/MM/YYYY or DD-MM-YYYY
            else:

                day = int(match.group(1))
                month = int(match.group(2))
                year = int(match.group(3))

            parsed_date = datetime(
                year,
                month,
                day
            )

            # Convert to MySQL-friendly format
            transaction_date = parsed_date.date().isoformat()

            break

        except ValueError:

            transaction_date = None
    # ========================================================
    # FALLBACK REFERENCE
    # ========================================================

    # If no explicit Ref/Transaction ID was found,
    # use a clearly labelled account/invoice reference.
    if not reference:

        fallback_reference_patterns = [

            r"\baccount\s*(?:number|no|#)?"
            r"\s*[:\-]\s*"
            r"([A-Z0-9][A-Z0-9\-\/]{4,30})\b",

            r"\binvoice\s*(?:number|no|#)?"
            r"\s*[:\-]\s*"
            r"([A-Z0-9][A-Z0-9\-\/]{4,30})\b"
        ]

        for pattern in fallback_reference_patterns:

            match = re.search(
                pattern,
                text,
                re.IGNORECASE
            )

            if match:

                candidate = match.group(1).strip().upper()

                if any(
                    char.isdigit()
                    for char in candidate
                ):
                    reference = candidate
                    break

    # ========================================================
    # FINAL NORMALIZATION
    # ========================================================

    if transaction_code and not reference:
        reference = transaction_code

    if reference and not transaction_code:

        # Only use reference as transaction code when
        # it looks like an actual transaction identifier.
        if (
            any(char.isdigit() for char in reference)
            and len(reference) >= 5
        ):
            transaction_code = reference

    return {
        "amount": amount,
        "transaction_code": transaction_code,
        "phone": phone,
        "receiver": receiver,
        "transaction_date": transaction_date,
        "reference": reference,
        "raw_message": text
    }
# ============================================================
# FIND EMPLOYEE FROM PAYMENT MESSAGE
# ============================================================

def find_employee_for_payment(parsed):
    """
    Attempts to match a payment to an employee using:

    1. Phone number
    2. Receiver name
    """

    phone = parsed.get(
        "phone"
    )

    receiver = parsed.get(
        "receiver"
    )

    # --------------------------------------------------------
    # Phone matching
    # --------------------------------------------------------

    if phone:

        normalized_phone = phone

        if normalized_phone.startswith(
            "+254"
        ):
            normalized_phone = (
                "0" +
                normalized_phone[4:]
            )

        elif normalized_phone.startswith(
            "254"
        ):
            normalized_phone = (
                "0" +
                normalized_phone[3:]
            )

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture
            FROM employees
            WHERE REPLACE(
                REPLACE(phone, ' ', ''),
                '-',
                ''
            ) = %s
            LIMIT 1
            """,
            (
                normalized_phone
                .replace(" ", "")
                .replace("-", "")
            ,)
        )

        if employee:
            return employee

    # --------------------------------------------------------
    # Name matching
    # --------------------------------------------------------

    if receiver:

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture
            FROM employees
            WHERE LOWER(full_name) = LOWER(%s)
            LIMIT 1
            """,
            (receiver,)
        )

        if employee:
            return employee

        # Partial name match
        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture
            FROM employees
            WHERE LOWER(full_name) LIKE LOWER(%s)
            ORDER BY
                full_name ASC
            LIMIT 1
            """,
            (f"%{receiver}%",)
        )

        if employee:
            return employee

    return None


# ============================================================
# GET ALL PAYMENTS FOR TERM
# ============================================================

@app.route(
    "/api/terms/<int:term_id>/payments",
    methods=["GET"]
)
def get_term_payments(term_id):

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        term = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        query = """
            SELECT
                p.id,
                p.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                p.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                p.amount,
                p.method,
                p.transaction_code,
                p.reference,
                p.phone,
                p.receiver,
                p.transaction_date,
                p.payment_date,
                p.original_message,
                p.created_by,
                p.created_at
            FROM payments p
            JOIN employees e
                ON e.id = p.employee_id
            JOIN terms t
                ON t.id = p.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE p.term_id = %s
        """

        params = [
            term_id
        ]

        # Employee only sees own payments
        if user["role"] != "admin":

            if not user.get("employee_id"):

                return jsonify({
                    "success": True,
                    "payments": [],
                    "data": []
                })

            query += """
                AND p.employee_id = %s
            """

            params.append(
                user["employee_id"]
            )

        query += """
            ORDER BY
                p.payment_date DESC,
                p.id DESC
        """

        rows = fetch_all(
            query,
            tuple(params)
        )

        payments = [
            payment_to_dict(row)
            for row in rows
        ]

        total_paid = sum(
            item["amount"] or 0
            for item in payments
        )

        return jsonify({
            "success": True,
            "payments": payments,
            "records": payments,
            "total_paid": total_paid,
            "count": len(payments),
            "data": payments
        })

    except Exception as error:

        print(
            "GET TERM PAYMENTS ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to load payments.",
            "error": str(error)
        }), 500


# ============================================================
# GET EMPLOYEE PAYMENTS
# ============================================================

@app.route(
    "/api/terms/<int:term_id>/employees/<int:employee_id>/payments",
    methods=["GET"]
)
def get_employee_term_payments(
    term_id,
    employee_id
):

    user, error_response = require_auth()

    if error_response:
        return error_response

    # Employee can only see own payment history
    if (
        user["role"] != "admin"
        and user.get("employee_id") != employee_id
    ):

        return json_error(
            "You are not allowed to view these payments.",
            403
        )

    try:

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        term = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        rows = fetch_all(
            """
            SELECT
                p.id,
                p.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                p.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                p.amount,
                p.method,
                p.transaction_code,
                p.reference,
                p.phone,
                p.receiver,
                p.transaction_date,
                p.payment_date,
                p.original_message,
                p.created_by,
                p.created_at
            FROM payments p
            JOIN employees e
                ON e.id = p.employee_id
            JOIN terms t
                ON t.id = p.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE p.term_id = %s
              AND p.employee_id = %s
            ORDER BY
                p.payment_date DESC,
                p.id DESC
            """,
            (
                term_id,
                employee_id
            )
        )

        payments = [
            payment_to_dict(row)
            for row in rows
        ]

        total_paid = sum(
            item["amount"] or 0
            for item in payments
        )

        return jsonify({
            "success": True,
            "employee": {
                "id": employee["id"],
                "full_name": employee["full_name"],
                "phone": employee["phone"],
                "email": employee["email"],
                "profile_picture": employee["profile_picture"],
                "daily_rate": (
                    float(employee["daily_rate"])
                    if employee["daily_rate"] is not None
                    else 0
                )
            },
            "term": {
                "id": term["id"],
                "academic_year_id": term["academic_year_id"],
                "year": term["year"],
                "term_number": term["term_number"],
                "name": term["name"]
            },
            "payments": payments,
            "records": payments,
            "total_paid": total_paid,
            "data": payments
        })

    except Exception as error:

        print(
            "GET EMPLOYEE PAYMENTS ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to load employee payments.",
            "error": str(error)
        }), 500


# ============================================================
# EMPLOYEE PAYMENT SUMMARY
# ============================================================

@app.route(
    "/api/terms/<int:term_id>/employees/<int:employee_id>/summary",
    methods=["GET"]
)
def employee_payment_summary(
    term_id,
    employee_id
):

    user, error_response = require_auth()

    if error_response:
        return error_response

    if (
        user["role"] != "admin"
        and user.get("employee_id") != employee_id
    ):
        return json_error(
            "You are not allowed to view this summary.",
            403
        )

    try:

        print("🔥 EMPLOYEE SUMMARY ROUTE RUNNING 🔥")

        # ----------------------------------------------------
        # Employee
        # ----------------------------------------------------

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone,
                email,
                profile_picture,
                daily_rate
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:
            return json_error(
                "Employee not found.",
                404
            )

        # ----------------------------------------------------
        # Term
        # ----------------------------------------------------

        term = fetch_one(
            """
            SELECT
                t.id,
                t.academic_year_id,
                t.term_number,
                t.name,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:
            return json_error(
                "Term not found.",
                404
            )

        # ----------------------------------------------------
        # Attendance summary
        #
        # Days worked are based ONLY on attendance records.
        # ----------------------------------------------------

        attendance_summary = fetch_one(
            """
            SELECT

                COUNT(*) AS total_recorded,

                COALESCE(
                    SUM(
                        CASE
                            WHEN status = 'present'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS days_present,

                COALESCE(
                    SUM(
                        CASE
                            WHEN status = 'absent'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS days_absent

            FROM attendance

            WHERE employee_id = %s
              AND term_id = %s
            """,
            (
                employee_id,
                term_id
            )
        )

        days_worked = int(
            attendance_summary["days_present"] or 0
        )

        days_absent = int(
            attendance_summary["days_absent"] or 0
        )

        # ----------------------------------------------------
        # Daily rate
        #
        # DO NOT CHANGE THIS.
        # ----------------------------------------------------

        daily_rate = float(
            employee["daily_rate"] or 0
        )

        # ----------------------------------------------------
        # MANUAL ATTENDANCE EARNINGS
        #
        # These are the amounts entered for attendance.
        #
        # IMPORTANT:
        # The old KSh 2,000 is already part of the employee's
        # existing earnings and must remain included.
        # ----------------------------------------------------

        earned_result = fetch_one(
            """
            SELECT
                COALESCE(
                    SUM(amount_earned),
                    0
                ) AS manual_earnings

            FROM attendance

            WHERE employee_id = %s
              AND term_id = %s
              AND status = 'present'
            """,
            (
                employee_id,
                term_id
            )
        )

        manual_earnings = float(
            earned_result["manual_earnings"] or 0
        )

        # ----------------------------------------------------
        # Existing KSh 2,000
        #
        # This preserves the amount that was already recorded
        # before the attendance calculation was changed.
        # ----------------------------------------------------

        manual_earnings = float(
    earned_result["manual_earnings"] or 0
)

        amount_earned = manual_earnings

        print(
            "🔥 MANUAL ATTENDANCE EARNINGS =",
            manual_earnings
        )

        print(
            "🔥 TOTAL AMOUNT EARNED =",
            amount_earned
        )

        # ----------------------------------------------------
        # Total paid
        # ----------------------------------------------------

        paid_result = fetch_one(
            """
            SELECT
                COALESCE(
                    SUM(amount),
                    0
                ) AS total_paid

            FROM payments

            WHERE employee_id = %s
              AND term_id = %s
            """,
            (
                employee_id,
                term_id
            )
        )

        total_paid = float(
            paid_result["total_paid"] or 0
        )

        # ----------------------------------------------------
        # Remaining
        # ----------------------------------------------------

        remaining = (
            amount_earned -
            total_paid
        )

        if abs(remaining) < 0.005:
            remaining = 0

        # ----------------------------------------------------
        # Payment status
        # ----------------------------------------------------

        if remaining > 0:
            payment_status = "Pending"

        elif remaining < 0:
            payment_status = "Overpaid"

        else:
            payment_status = "Paid"

        # ----------------------------------------------------
        # Final summary
        # ----------------------------------------------------

        summary = {

            "total_days_worked":
                days_worked,

            "days_worked":
                days_worked,

            "days_present":
                days_worked,

            "days_absent":
                days_absent,

            # KEEP EXISTING RATE
            "daily_rate":
                daily_rate,

            # TOTAL EARNED
            "amount_earned":
                amount_earned,

            "total_earned":
                amount_earned,

            # TOTAL PAYMENTS
            "total_paid":
                total_paid,

            # BALANCE
            "remaining_to_be_paid":
                remaining,

            "remaining":
                remaining,

            "payment_status":
                payment_status
        }

        return jsonify({

            "success": True,

            "employee": {
                "id":
                    employee["id"],

                "full_name":
                    employee["full_name"],

                "phone":
                    employee["phone"],

                "email":
                    employee["email"],

                "profile_picture":
                    employee["profile_picture"]
            },

            "term": {
                "id":
                    term["id"],

                "academic_year_id":
                    term["academic_year_id"],

                "year":
                    term["year"],

                "term_number":
                    term["term_number"],

                "name":
                    term["name"]
            },

            "summary":
                summary,

            "data":
                summary
        })

    except Exception as error:

        print(
            "EMPLOYEE PAYMENT SUMMARY ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message":
                "Failed to calculate payment summary.",
            "error":
                str(error)
        }), 500
# ============================================================
# CASH PAYMENT
# ============================================================

@app.route(
    "/api/payments/cash",
    methods=["POST"]
)
def record_cash_payment():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        employee_id = data.get(
            "employee_id"
        )

        term_id = data.get(
            "term_id"
        )

        amount = data.get(
            "amount"
        )

        payment_date = data.get(
            "payment_date"
        )

        reference = data.get(
            "reference"
        )

        if not employee_id:

            return json_error(
                "Employee ID is required."
            )

        if not term_id:

            return json_error(
                "Term ID is required."
            )

        if amount in [
            None,
            ""
        ]:

            return json_error(
                "Payment amount is required."
            )

        try:

            employee_id = int(
                employee_id
            )

            term_id = int(
                term_id
            )

            amount = float(
                amount
            )

        except (ValueError, TypeError):

            return json_error(
                "Invalid employee, term or payment amount."
            )

        if amount <= 0:

            return json_error(
                "Payment amount must be greater than zero."
            )

        employee = fetch_one(
            """
            SELECT
                id,
                full_name
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        term = fetch_one(
            """
            SELECT
                id
            FROM terms
            WHERE id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        conn = get_db()
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                INSERT INTO payments
                (
                    employee_id,
                    term_id,
                    amount,
                    method,
                    transaction_code,
                    reference,
                    phone,
                    receiver,
                    transaction_date,
                    original_message,
                    created_by,
                    payment_date
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    'Cash',
                    NULL,
                    %s,
                    NULL,
                    %s,
                    NULL,
                    NULL,
                    %s,
                    COALESCE(%s, NOW())
                )
                """,
                (
                    employee_id,
                    term_id,
                    amount,
                    reference,
                    employee["full_name"],
                    user["id"],
                    payment_date
                )
            )

            payment_id = cursor.lastrowid

            conn.commit()

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        payment = fetch_one(
            """
            SELECT
                p.id,
                p.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                p.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                p.amount,
                p.method,
                p.transaction_code,
                p.reference,
                p.phone,
                p.receiver,
                p.transaction_date,
                p.payment_date,
                p.original_message,
                p.created_by,
                p.created_at
            FROM payments p
            JOIN employees e
                ON e.id = p.employee_id
            JOIN terms t
                ON t.id = p.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE p.id = %s
            LIMIT 1
            """,
            (payment_id,)
        )

        result = payment_to_dict(
            payment
        )

        return jsonify({
            "success": True,
            "message": "Cash payment recorded successfully.",
            "payment": result,
            "data": result
        }), 201

    except Exception as error:

        print(
            "CASH PAYMENT ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to record cash payment.",
            "error": str(error)
        }), 500


# ============================================================
# M-PESA PAYMENT PREVIEW
# ============================================================

@app.route(
    "/api/payments/mpesa/preview",
    methods=["POST"]
)
def preview_mpesa_payment():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        message = data.get(
            "message",
            data.get(
                "original_message",
                ""
            )
        )

        if not message:

            return json_error(
                "Please paste the M-Pesa message."
            )

        parsed = parse_payment_message(
            message
        )

        matched_employee = (
            find_employee_for_payment(
                parsed
            )
        )

        result = {
            "method": "M-Pesa",
            "amount": parsed["amount"],
            "transaction_amount": parsed["amount"],
            "paid_amount": parsed["amount"],
            "transaction_code": parsed["transaction_code"],
            "mpesa_code": parsed["transaction_code"],
            "reference": parsed["reference"],
            "phone": parsed["phone"],
            "receiver": parsed["receiver"],
            "recipient": parsed["receiver"],
            "transaction_date": parsed["transaction_date"],
            "matched_employee": (
                {
                    "id": matched_employee["id"],
                    "full_name": matched_employee["full_name"],
                    "phone": matched_employee["phone"],
                    "profile_picture": matched_employee["profile_picture"]
                }
                if matched_employee
                else None
            ),
            "original_message": message
        }

        return jsonify({
            "success": True,
            "message": "M-Pesa message parsed successfully.",
            "preview": result,
            "transaction": result,
            "data": result
        })

    except Exception as error:

        print(
            "MPESA PREVIEW ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to parse M-Pesa message.",
            "error": str(error)
        }), 500


# ============================================================
# RECORD M-PESA PAYMENT
# ============================================================

@app.route(
    "/api/payments/mpesa",
    methods=["POST"]
)
def record_mpesa_payment():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        employee_id = data.get(
            "employee_id"
        )

        term_id = data.get(
            "term_id"
        )

        message = data.get(
            "message",
            data.get(
                "original_message",
                ""
            )
        )

        # Frontend may send already parsed transaction data
        transaction = data.get(
            "transaction",
            data.get(
                "preview"
            )
        )

        if not message and transaction:

            message = transaction.get(
                "original_message",
                ""
            )

        # ----------------------------------------------------
        # Parse message
        # ----------------------------------------------------

        parsed = parse_payment_message(
            message
        ) if message else {
            "amount": data.get("amount"),
            "transaction_code": data.get(
                "transaction_code",
                data.get("mpesa_code")
            ),
            "phone": data.get("phone"),
            "receiver": data.get("receiver"),
            "transaction_date": data.get(
                "transaction_date"
            ),
            "reference": data.get("reference"),
            "raw_message": message
        }

        if transaction:

            if not parsed.get("amount"):
                parsed["amount"] = transaction.get(
                    "amount",
                    transaction.get(
                        "transaction_amount"
                    )
                )

            if not parsed.get("transaction_code"):
                parsed["transaction_code"] = transaction.get(
                    "transaction_code",
                    transaction.get(
                        "mpesa_code"
                    )
                )

            if not parsed.get("phone"):
                parsed["phone"] = transaction.get(
                    "phone"
                )

            if not parsed.get("receiver"):
                parsed["receiver"] = transaction.get(
                    "receiver",
                    transaction.get(
                        "recipient"
                    )
                )

        # ----------------------------------------------------
        # Match employee automatically if employee_id wasn't
        # explicitly supplied.
        # ----------------------------------------------------

        if not employee_id:

            matched_employee = find_employee_for_payment(
                parsed
            )

            if matched_employee:

                employee_id = matched_employee["id"]

        if not employee_id:

            return json_error(
                "Could not identify the employee. Please select the employee manually."
            )

        if not term_id:

            return json_error(
                "Term ID is required."
            )

        amount = parsed.get(
            "amount"
        )

        if amount is None:

            return json_error(
                "Could not identify the payment amount."
            )

        try:

            employee_id = int(
                employee_id
            )

            term_id = int(
                term_id
            )

            amount = float(
                amount
            )

        except (ValueError, TypeError):

            return json_error(
                "Invalid payment information."
            )

        if amount <= 0:

            return json_error(
                "Payment amount must be greater than zero."
            )

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        term = fetch_one(
            """
            SELECT
                id
            FROM terms
            WHERE id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        transaction_code = parsed.get(
            "transaction_code"
        )

        # ----------------------------------------------------
        # Duplicate transaction protection
        # ----------------------------------------------------

        if transaction_code:

            duplicate = fetch_one(
                """
                SELECT
                    id,
                    employee_id,
                    amount
                FROM payments
                WHERE transaction_code = %s
                LIMIT 1
                """,
                (transaction_code,)
            )

            if duplicate:

                return json_error(
                    "This M-Pesa transaction has already been recorded.",
                    409
                )

        conn = get_db()
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                INSERT INTO payments
                (
                    employee_id,
                    term_id,
                    amount,
                    method,
                    transaction_code,
                    reference,
                    phone,
                    receiver,
                    transaction_date,
                    original_message,
                    created_by,
                    payment_date
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    'M-Pesa',
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    NOW()
                )
                """,
                (
                    employee_id,
                    term_id,
                    amount,
                    transaction_code,
                    parsed.get("reference"),
                    parsed.get("phone"),
                    parsed.get("receiver"),
                    parsed.get("transaction_date"),
                    message,
                    user["id"]
                )
            )

            payment_id = cursor.lastrowid

            conn.commit()

        except mysql.connector.IntegrityError as error:

            conn.rollback()

            print(
                "MPESA PAYMENT INTEGRITY ERROR:",
                error
            )

            return json_error(
                "This transaction may already have been recorded.",
                409
            )

        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        payment = fetch_one(
            """
            SELECT
                p.id,
                p.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                p.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                p.amount,
                p.method,
                p.transaction_code,
                p.reference,
                p.phone,
                p.receiver,
                p.transaction_date,
                p.payment_date,
                p.original_message,
                p.created_by,
                p.created_at
            FROM payments p
            JOIN employees e
                ON e.id = p.employee_id
            JOIN terms t
                ON t.id = p.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE p.id = %s
            LIMIT 1
            """,
            (payment_id,)
        )

        result = payment_to_dict(
            payment
        )

        return jsonify({
            "success": True,
            "message": "M-Pesa payment recorded successfully.",
            "payment": result,
            "data": result
        }), 201

    except Exception as error:

        print(
            "MPESA PAYMENT ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to record M-Pesa payment.",
            "error": str(error)
        }), 500


# ============================================================
# BANK PAYMENT PREVIEW
# ============================================================

@app.route(
    "/api/payments/bank/preview",
    methods=["POST"]
)
def preview_bank_payment():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        message = data.get(
            "message",
            data.get(
                "original_message",
                ""
            )
        )

        if not message:

            return json_error(
                "Please paste the bank transaction message."
            )

        parsed = parse_payment_message(
            message
        )

        matched_employee = find_employee_for_payment(
            parsed
        )

        result = {
            "method": "Bank",
            "amount": parsed["amount"],
            "transaction_amount": parsed["amount"],
            "paid_amount": parsed["amount"],
            "transaction_code": parsed["transaction_code"],
            "reference": parsed["reference"],
            "phone": parsed["phone"],
            "receiver": parsed["receiver"],
            "recipient": parsed["receiver"],
            "transaction_date": parsed["transaction_date"],
            "matched_employee": (
                {
                    "id": matched_employee["id"],
                    "full_name": matched_employee["full_name"],
                    "phone": matched_employee["phone"],
                    "profile_picture": matched_employee["profile_picture"]
                }
                if matched_employee
                else None
            ),
            "original_message": message
        }

        return jsonify({
            "success": True,
            "message": "Bank message parsed successfully.",
            "preview": result,
            "transaction": result,
            "data": result
        })

    except Exception as error:

        print(
            "BANK PREVIEW ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to parse bank message.",
            "error": str(error)
        }), 500


# ============================================================
# RECORD BANK PAYMENT
# ============================================================

@app.route(
    "/api/payments/bank",
    methods=["POST"]
)
def record_bank_payment():

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        data = request.get_json(
            silent=True
        ) or {}

        employee_id = data.get(
            "employee_id"
        )

        term_id = data.get(
            "term_id"
        )

        message = data.get(
            "message",
            data.get(
                "original_message",
                ""
            )
        )

        transaction = data.get(
            "transaction",
            data.get(
                "preview"
            )
        )

        if not message and transaction:

            message = transaction.get(
                "original_message",
                ""
            )

        parsed = parse_payment_message(
            message
        ) if message else {
            "amount": data.get("amount"),
            "transaction_code": data.get(
                "transaction_code",
                data.get("reference")
            ),
            "phone": data.get("phone"),
            "receiver": data.get("receiver"),
            "transaction_date": data.get(
                "transaction_date"
            ),
            "reference": data.get("reference"),
            "raw_message": message
        }

        if transaction:

            if not parsed.get("amount"):
                parsed["amount"] = transaction.get(
                    "amount",
                    transaction.get(
                        "transaction_amount"
                    )
                )

            if not parsed.get("transaction_code"):
                parsed["transaction_code"] = transaction.get(
                    "transaction_code",
                    transaction.get(
                        "reference"
                    )
                )

            if not parsed.get("phone"):
                parsed["phone"] = transaction.get(
                    "phone"
                )

            if not parsed.get("receiver"):
                parsed["receiver"] = transaction.get(
                    "receiver",
                    transaction.get(
                        "recipient"
                    )
                )

        if not employee_id:

            matched_employee = find_employee_for_payment(
                parsed
            )

            if matched_employee:

                employee_id = matched_employee["id"]

        if not employee_id:

            return json_error(
                "Could not identify the employee. Please select the employee manually."
            )

        if not term_id:

            return json_error(
                "Term ID is required."
            )

        amount = parsed.get(
            "amount"
        )

        if amount is None:

            return json_error(
                "Could not identify the payment amount."
            )

        try:

            employee_id = int(
                employee_id
            )

            term_id = int(
                term_id
            )

            amount = float(
                amount
            )

        except (ValueError, TypeError):

            return json_error(
                "Invalid payment information."
            )

        if amount <= 0:

            return json_error(
                "Payment amount must be greater than zero."
            )

        employee = fetch_one(
            """
            SELECT
                id,
                full_name,
                phone
            FROM employees
            WHERE id = %s
            LIMIT 1
            """,
            (employee_id,)
        )

        if not employee:

            return json_error(
                "Employee not found.",
                404
            )

        term = fetch_one(
            """
            SELECT
                id
            FROM terms
            WHERE id = %s
            LIMIT 1
            """,
            (term_id,)
        )

        if not term:

            return json_error(
                "Term not found.",
                404
            )

        transaction_code = parsed.get(
            "transaction_code"
        )

        if transaction_code:

            duplicate = fetch_one(
                """
                SELECT
                    id
                FROM payments
                WHERE transaction_code = %s
                LIMIT 1
                """,
                (transaction_code,)
            )

        if duplicate:

            print(
                "BANK PAYMENT DUPLICATE CHECK FOUND:",
            transaction_code,
            "EXISTING PAYMENT ID:",
            duplicate["id"]
            )

            return json_error(
            "This bank transaction has already been recorded.",
            409
        )

        conn = get_db()
        cursor = conn.cursor()

        try:

            cursor.execute(
                """
                INSERT INTO payments
                (
                    employee_id,
                    term_id,
                    amount,
                    method,
                    transaction_code,
                    reference,
                    phone,
                    receiver,
                    transaction_date,
                    original_message,
                    created_by,
                    payment_date
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    'Bank',
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    NOW()
                )
                """,
                (
                    employee_id,
                    term_id,
                    amount,
                    transaction_code,
                    parsed.get("reference"),
                    parsed.get("phone"),
                    parsed.get("receiver"),
                    parsed.get("transaction_date"),
                    message,
                    user["id"]
                )
            )

            payment_id = cursor.lastrowid

            conn.commit()

        except mysql.connector.IntegrityError as error:

            conn.rollback()

            print(
                "BANK PAYMENT INTEGRITY ERROR:",
                repr(error)
            )

            return jsonify({
                "success": False,
                "message": "Bank payment database conflict.",
                "error": str(error)
            }), 409
        except Exception:

            conn.rollback()
            raise

        finally:

            cursor.close()
            conn.close()

        payment = fetch_one(
            """
            SELECT
                p.id,
                p.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                p.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                p.amount,
                p.method,
                p.transaction_code,
                p.reference,
                p.phone,
                p.receiver,
                p.transaction_date,
                p.payment_date,
                p.original_message,
                p.created_by,
                p.created_at
            FROM payments p
            JOIN employees e
                ON e.id = p.employee_id
            JOIN terms t
                ON t.id = p.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE p.id = %s
            LIMIT 1
            """,
            (payment_id,)
        )

        result = payment_to_dict(
            payment
        )

        return jsonify({
            "success": True,
            "message": "Bank payment recorded successfully.",
            "payment": result,
            "data": result
        }), 201


    except Exception as error:

        print(
            "BANK PAYMENT ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to record bank payment.",
            "error": str(error)
        }), 500


# ============================================================
# DELETE PAYMENT
# ============================================================

@app.route(
    "/api/payments/<int:payment_id>",
    methods=["DELETE"]
)
def delete_payment(payment_id):

    user, error_response = require_admin()

    if error_response:
        return error_response

    try:

        payment = fetch_one(
            """
            SELECT
                id,
                employee_id,
                term_id,
                amount,
                method,
                transaction_code
            FROM payments
            WHERE id = %s
            LIMIT 1
            """,
            (payment_id,)
        )

        if not payment:

            return json_error(
                "Payment not found.",
                404
            )

        execute_query(
            """
            DELETE FROM payments
            WHERE id = %s
            """,
            (payment_id,)
        )

        return jsonify({
            "success": True,
            "message": "Payment deleted successfully."
        })

    except Exception as error:

        print(
            "DELETE PAYMENT ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to delete payment.",
            "error": str(error)
        }), 500


# ============================================================
# PAYMENT SEARCH
# ============================================================

@app.route(
    "/api/payments/search",
    methods=["GET"]
)
def search_payments():

    user, error_response = require_auth()

    if error_response:
        return error_response

    try:

        search = request.args.get(
            "search",
            ""
        ).strip()

        term_id = request.args.get(
            "term_id"
        )

        method = request.args.get(
            "method"
        )

        query = """
            SELECT
                p.id,
                p.employee_id,
                e.full_name AS employee_name,
                e.profile_picture,
                p.term_id,
                t.academic_year_id,
                ay.year,
                t.term_number,
                t.name AS term_name,
                p.amount,
                p.method,
                p.transaction_code,
                p.reference,
                p.phone,
                p.receiver,
                p.transaction_date,
                p.payment_date,
                p.original_message,
                p.created_by,
                p.created_at
            FROM payments p
            JOIN employees e
                ON e.id = p.employee_id
            JOIN terms t
                ON t.id = p.term_id
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE 1 = 1
        """

        params = []

        if user["role"] != "admin":

            query += """
                AND p.employee_id = %s
            """

            params.append(
                user["employee_id"]
            )

        if search:

            query += """
                AND (
                    e.full_name LIKE %s
                    OR e.phone LIKE %s
                    OR p.transaction_code LIKE %s
                    OR p.reference LIKE %s
                )
            """

            value = f"%{search}%"

            params.extend([
                value,
                value,
                value,
                value
            ])

        if term_id:

            query += """
                AND p.term_id = %s
            """

            params.append(
                term_id
            )

        if method:

            query += """
                AND p.method = %s
            """

            params.append(
                method
            )

        query += """
            ORDER BY
                p.payment_date DESC,
                p.id DESC
        """

        rows = fetch_all(
            query,
            tuple(params)
        )

        payments = [
            payment_to_dict(row)
            for row in rows
        ]

        return jsonify({
            "success": True,
            "payments": payments,
            "records": payments,
            "count": len(payments),
            "data": payments
        })

    except Exception as error:

        print(
            "SEARCH PAYMENTS ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "Failed to search payments.",
            "error": str(error)
        }), 500

        # ============================================================
# PART 5 — GAS PAYMENTS + DASHBOARD STATISTICS
# ============================================================

# ------------------------------------------------------------
# GAS PAYMENT HELPERS
# ------------------------------------------------------------

def gas_to_dict(row):

    if not row:
        return None

    return {
        "id": row.get("id"),

        "term_id": row.get("term_id"),

        "amount": float(
            row.get("amount") or 0
        ),

        "payment_date": (
            row["payment_date"].isoformat()
            if row.get("payment_date")
            else None
        ),

        "created_at": (
            row["created_at"].isoformat()
            if row.get("created_at")
            else None
        ),

        "created_by": row.get("created_by"),

        "created_by_name":
            row.get("created_by_name"),
    }
# ------------------------------------------------------------
# GET GAS PAYMENTS FOR A TERM
# ------------------------------------------------------------

@app.get("/api/terms/<int:term_id>/gas")
def get_term_gas_payments(term_id):
    user = get_current_user()

    if not user:
        return json_error("Authentication required", 401)

    term = fetch_one(
        """
        SELECT
            t.id,
            t.name,
            t.term_number,
            ay.id AS year_id,
            ay.year
        FROM terms t
        JOIN academic_years ay
            ON ay.id = t.academic_year_id
        WHERE t.id = %s
        """,
        (term_id,)
    )

    if not term:
        return json_error("Term not found", 404)

    rows = fetch_all(
        """
        SELECT
            gp.id,
            gp.term_id,
            gp.amount,
            gp.payment_date,
            gp.created_at,
            gp.created_by,
            u.full_name AS created_by_name
        FROM gas_payments gp
        LEFT JOIN users u
            ON u.id = gp.created_by
        WHERE gp.term_id = %s
        ORDER BY gp.payment_date DESC, gp.id DESC
        """,
        (term_id,)
    )

    payments = [gas_to_dict(row) for row in rows]

    total = sum(
        float(payment["amount"])
        for payment in payments
    )

    return jsonify({
        "success": True,
        "term": {
            "id": term["id"],
            "name": term["name"],
            "term_number": term["term_number"],
            "year_id": term["year_id"],
            "year": term["year"],
        },
        "payments": payments,
        "total": total,
        "count": len(payments),
    }), 200


# ------------------------------------------------------------
# ADD GAS PAYMENT
# ------------------------------------------------------------

@app.post("/api/gas")
def add_gas_payment():

    user, error_response = require_admin()

    if error_response:
        return error_response

    data = request.get_json(
        silent=True
    ) or {}

    term_id = data.get("term_id")
    amount = data.get("amount")

    if not term_id:
        return json_error(
            "term_id is required"
        )

    if amount is None or str(amount).strip() == "":
        return json_error(
            "Amount is required"
        )

    try:
        amount = float(amount)

    except (TypeError, ValueError):
        return json_error(
            "Amount must be a valid number"
        )

    if amount <= 0:
        return json_error(
            "Amount must be greater than zero"
        )

    # --------------------------------------------------------
    # Check term
    # --------------------------------------------------------

    term = fetch_one(
        """
        SELECT
            t.id,
            t.name,
            t.term_number,
            ay.id AS year_id,
            ay.year
        FROM terms t
        JOIN academic_years ay
            ON ay.id = t.academic_year_id
        WHERE t.id = %s
        """,
        (term_id,)
    )

    if not term:
        return json_error(
            "Term not found",
            404
        )

    # --------------------------------------------------------
    # Insert gas payment
    # --------------------------------------------------------

    payment_id = execute_query(
        """
        INSERT INTO gas_payments
            (
                term_id,
                amount,
                created_by
            )
        VALUES
            (
                %s,
                %s,
                %s
            )
        """,
        (
            term_id,
            amount,
            user["id"],
        )
    )

    # --------------------------------------------------------
    # Get newly created payment
    # --------------------------------------------------------

    payment = fetch_one(
        """
        SELECT
            gp.id,
            gp.term_id,
            gp.amount,
            gp.payment_date,
            gp.created_at,
            gp.created_by,
            u.full_name AS created_by_name
        FROM gas_payments gp
        LEFT JOIN users u
            ON u.id = gp.created_by
        WHERE gp.id = %s
        """,
        (payment_id,)
    )

    return jsonify({
        "success": True,
        "message":
            "Gas payment recorded successfully",
        "payment":
            gas_to_dict(payment),
    }), 201

# ------------------------------------------------------------
# DELETE GAS PAYMENT
# ------------------------------------------------------------

@app.delete("/api/gas/<int:gas_id>")
def delete_gas_payment(gas_id):
    user = require_admin()

    if not user:
        return json_error("Admin access required", 403)

    payment = fetch_one(
        """
        SELECT id, term_id, amount
        FROM gas_payments
        WHERE id = %s
        """,
        (gas_id,)
    )

    if not payment:
        return json_error("Gas payment not found", 404)

    execute_query(
        """
        DELETE FROM gas_payments
        WHERE id = %s
        """,
        (gas_id,)
    )

    return jsonify({
        "success": True,
        "message": "Gas payment deleted successfully"
    }), 200


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/api/dashboard")
def dashboard_statistics():
    user = get_current_user()

    if not user:
        return json_error("Authentication required", 401)

    year_id = request.args.get("year_id", type=int)
    term_id = request.args.get("term_id", type=int)

    # --------------------------------------------------------
    # DEFAULT TO CURRENT YEAR
    # --------------------------------------------------------

    if not year_id:
        current_year = fetch_one(
            """
            SELECT id, year
            FROM academic_years
            WHERE is_current = 1
            ORDER BY year DESC
            LIMIT 1
            """
        )

        if not current_year:
            current_year = fetch_one(
                """
                SELECT id, year
                FROM academic_years
                ORDER BY year DESC
                LIMIT 1
                """
            )

        if current_year:
            year_id = current_year["id"]

    # --------------------------------------------------------
    # YEAR INFORMATION
    # --------------------------------------------------------

    year = None

    if year_id:
        year = fetch_one(
            """
            SELECT id, year, is_current
            FROM academic_years
            WHERE id = %s
            """,
            (year_id,)
        )

    # --------------------------------------------------------
    # TERM INFORMATION
    # --------------------------------------------------------

    term = None

    if term_id:
        term = fetch_one(
            """
            SELECT
                t.id,
                t.name,
                t.term_number,
                t.academic_year_id,
                t.is_current,
                t.start_date,
                t.end_date,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.id = %s
            """,
            (term_id,)
        )

    # If no term supplied but year exists, use current term
    if not term and year_id:
        term = fetch_one(
            """
            SELECT
                t.id,
                t.name,
                t.term_number,
                t.academic_year_id,
                t.is_current,
                t.start_date,
                t.end_date,
                ay.year
            FROM terms t
            JOIN academic_years ay
                ON ay.id = t.academic_year_id
            WHERE t.academic_year_id = %s
            ORDER BY
                t.is_current DESC,
                t.term_number DESC
            LIMIT 1
            """,
            (year_id,)
        )

    # --------------------------------------------------------
    # EMPLOYEE COUNT
    # --------------------------------------------------------

    employee_count_row = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM employees
        WHERE is_active = 1
        """
    )

    employee_count = int(
        employee_count_row["total"]
        if employee_count_row
        else 0
    )

    # --------------------------------------------------------
    # ATTENDANCE STATISTICS
    # --------------------------------------------------------

    attendance_params = []
    attendance_filter = ""

    if term:
        attendance_filter = "WHERE a.term_id = %s"
        attendance_params.append(term["id"])

    elif year_id:
        attendance_filter = """
            WHERE a.term_id IN (
                SELECT id
                FROM terms
                WHERE academic_year_id = %s
            )
        """
        attendance_params.append(year_id)

    attendance_stats = fetch_one(
        f"""
        SELECT
            COUNT(*) AS total_records,
            COALESCE(
                SUM(
                    CASE
                        WHEN a.status = 'present'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS present_days,
            COALESCE(
                SUM(
                    CASE
                        WHEN a.status = 'absent'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS absent_days
        FROM attendance a
        {attendance_filter}
        """,
        tuple(attendance_params)
    )

    total_attendance_records = int(
        attendance_stats["total_records"]
        if attendance_stats
        else 0
    )

    present_days = int(
        attendance_stats["present_days"]
        if attendance_stats
        else 0
    )

    absent_days = int(
        attendance_stats["absent_days"]
        if attendance_stats
        else 0
    )

    # --------------------------------------------------------
    # PAYMENT STATISTICS
    # --------------------------------------------------------

    payment_params = []
    payment_filter = ""

    if term:
        payment_filter = "WHERE p.term_id = %s"
        payment_params.append(term["id"])

    elif year_id:
        payment_filter = """
            WHERE p.term_id IN (
                SELECT id
                FROM terms
                WHERE academic_year_id = %s
            )
        """
        payment_params.append(year_id)

    payment_stats = fetch_one(
        f"""
        SELECT
            COUNT(*) AS payment_count,
            COALESCE(SUM(p.amount), 0) AS total_paid
        FROM payments p
        {payment_filter}
        """,
        tuple(payment_params)
    )

    payment_count = int(
        payment_stats["payment_count"]
        if payment_stats
        else 0
    )

    total_paid = float(
        payment_stats["total_paid"]
        if payment_stats
        else 0
    )

    # --------------------------------------------------------
    # EARNINGS
    # --------------------------------------------------------

    earned_params = []
    earned_filter = ""

    if term:
        earned_filter = "WHERE a.term_id = %s"
        earned_params.append(term["id"])

    elif year_id:
        earned_filter = """
            WHERE a.term_id IN (
                SELECT id
                FROM terms
                WHERE academic_year_id = %s
            )
        """
        earned_params.append(year_id)

    earnings_row = fetch_one(
        f"""
        SELECT
            COALESCE(
                SUM(
                    CASE
                        WHEN a.status = 'present'
                        THEN a.days_worked * e.daily_rate
                        ELSE 0
                    END
                ),
                0
            ) AS total_earned
        FROM attendance a
        JOIN employees e
            ON e.id = a.employee_id
        {earned_filter}
        """,
        tuple(earned_params)
    )

    total_earned = float(
        earnings_row["total_earned"]
        if earnings_row
        else 0
    )

    remaining = total_earned - total_paid

    # --------------------------------------------------------
    # GAS STATISTICS
    # --------------------------------------------------------

    gas_params = []
    gas_filter = ""

    if term:
        gas_filter = "WHERE gp.term_id = %s"
        gas_params.append(term["id"])

    elif year_id:
        gas_filter = """
            WHERE gp.term_id IN (
                SELECT id
                FROM terms
                WHERE academic_year_id = %s
            )
        """
        gas_params.append(year_id)

    gas_row = fetch_one(
        f"""
        SELECT
            COUNT(*) AS gas_count,
            COALESCE(SUM(gp.amount), 0) AS total_gas
        FROM gas_payments gp
        {gas_filter}
        """,
        tuple(gas_params)
    )

    gas_count = int(
        gas_row["gas_count"]
        if gas_row
        else 0
    )

    total_gas = float(
        gas_row["total_gas"]
        if gas_row
        else 0
    )

    # --------------------------------------------------------
    # RETURN DASHBOARD
    # --------------------------------------------------------

    return jsonify({
        "success": True,

        "year": (
            {
                "id": year["id"],
                "year": year["year"],
                "is_current": bool(year["is_current"]),
            }
            if year
            else None
        ),

        "term": (
            {
                "id": term["id"],
                "name": term["name"],
                "term_number": term["term_number"],
                "year_id": term["academic_year_id"],
                "year": term["year"],
                "is_current": bool(term["is_current"]),
                "start_date": (
                    term["start_date"].isoformat()
                    if term.get("start_date")
                    else None
                ),
                "end_date": (
                    term["end_date"].isoformat()
                    if term.get("end_date")
                    else None
                ),
            }
            if term
            else None
        ),

        "statistics": {
            "employees": employee_count,
            "attendance_records": total_attendance_records,
            "present_days": present_days,
            "absent_days": absent_days,
            "total_earned": total_earned,
            "total_paid": total_paid,
            "remaining": remaining,
            "payment_count": payment_count,
            "gas_count": gas_count,
            "total_gas": total_gas,
        }
    }), 200

# ============================================================
# ACADEMIC YEARS
# ============================================================

    
# ============================================================
# YEAR SUMMARY
# ============================================================

@app.get("/api/years/<int:year_id>/summary")
def year_summary(year_id):
    user = get_current_user()

    if not user:
        return json_error("Authentication required", 401)

    year = fetch_one(
        """
        SELECT id, year, is_current
        FROM academic_years
        WHERE id = %s
        """,
        (year_id,)
    )

    if not year:
        return json_error("Academic year not found", 404)

    terms = fetch_all(
        """
        SELECT
            t.id,
            t.name,
            t.term_number,
            t.is_current,
            t.start_date,
            t.end_date,

            COALESCE(
                (
                    SELECT SUM(
                        CASE
                            WHEN a.status = 'present'
                            THEN a.days_worked * e.daily_rate
                            ELSE 0
                        END
                    )
                    FROM attendance a
                    JOIN employees e
                        ON e.id = a.employee_id
                    WHERE a.term_id = t.id
                ),
                0
            ) AS total_earned,

            COALESCE(
                (
                    SELECT SUM(p.amount)
                    FROM payments p
                    WHERE p.term_id = t.id
                ),
                0
            ) AS total_paid,

            COALESCE(
                (
                    SELECT SUM(gp.amount)
                    FROM gas_payments gp
                    WHERE gp.term_id = t.id
                ),
                0
            ) AS total_gas

        FROM terms t
        WHERE t.academic_year_id = %s
        ORDER BY t.term_number ASC
        """,
        (year_id,)
    )

    result = []

    for term in terms:
        earned = float(term["total_earned"] or 0)
        paid = float(term["total_paid"] or 0)

        result.append({
            "id": term["id"],
            "name": term["name"],
            "term_number": term["term_number"],
            "is_current": bool(term["is_current"]),
            "start_date": (
                term["start_date"].isoformat()
                if term.get("start_date")
                else None
            ),
            "end_date": (
                term["end_date"].isoformat()
                if term.get("end_date")
                else None
            ),
            "total_earned": earned,
            "total_paid": paid,
            "remaining": earned - paid,
            "total_gas": float(term["total_gas"] or 0),
        })

    return jsonify({
        "success": True,
        "year": {
            "id": year["id"],
            "year": year["year"],
            "is_current": bool(year["is_current"]),
        },
        "terms": result,
    }), 200


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health_check():
    try:
        row = fetch_one("SELECT 1 AS ok")

        if row and row.get("ok") == 1:
            return jsonify({
                "success": True,
                "status": "healthy",
                "database": "connected"
            }), 200

        return jsonify({
            "success": False,
            "status": "unhealthy",
            "database": "not responding"
        }), 503

    except Exception as e:
        return jsonify({
            "success": False,
            "status": "unhealthy",
            "database": "error",
            "error": str(e)
        }), 503

# ============================================================
# FINAL SECTION — ERROR HANDLING + SERVER START
# ============================================================


# ------------------------------------------------------------
# BASIC ERROR HANDLERS
# ------------------------------------------------------------

@app.errorhandler(404)
def handle_404(error):

    return jsonify({
        "success": False,
        "message": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def handle_405(error):

    return jsonify({
        "success": False,
        "message": "Method not allowed"
    }), 405


@app.errorhandler(500)
def handle_500(error):

    print("SERVER ERROR:", error)

    return jsonify({
        "success": False,
        "message": "Internal server error"
    }), 500

print("\n========== CHECKING ROUTES ==========")

for rule in app.url_map.iter_rules():
    print(rule)

print("=====================================\n")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False
    )