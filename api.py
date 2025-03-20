from flask import Flask, request, jsonify
from functools import wraps
import paho.mqtt.client as mqtt
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2
from datetime import datetime
import json
import uuid  # Import UUID generator
import pytz 

LOG_FILE = "garage_log.json" 
LOCAL_TZ = pytz.timezone("America/Chicago")  


app = Flask(__name__)

#Postgress Connection
DATABASE_URL = "postgresql://garage_admin:Sun84Mus@localhost/garage_db"


# Secure API Key (store this in an environment variable)
API_KEY = os.getenv("GARAGE_API_KEY", "SuperSecretKey123")

# MQTT Broker Details
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_USER = "espuser"
MQTT_PASSWORD = "Sun84Mus"

# MQTT Topics (One for Each Garage Door)
MQTT_TOPIC_1 = "GarageDoor/Button"   # First garage (unchanged)
MQTT_TOPIC_2 = "GarageDoor2/Button"  # Second garage

# Rate Limiting (Max 10 Requests Per Minute Per IP)
limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"])

# Global MQTT Client
mqtt_client = None

def log_garage_open(user_uuid, first_name, last_name):
    """Append a new garage open event to the log file, keeping only the last 20 entries."""
    now = datetime.now(pytz.utc).astimezone(LOCAL_TZ)  # ✅ Convert UTC to Central Time

    log_entry = {
        "timestamp": now.strftime("%Y-%m-%d %I:%M %p"),  # 🕒 Non-military time in local timezone
        "user_uuid": user_uuid,
        "user_name": f"{first_name} {last_name}"
    }

    # Load existing log file if it exists
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            try:
                logs = json.load(file)
            except json.JSONDecodeError:
                logs = []
    else:
        logs = []

    # Keep only the last 20 opens
    logs.append(log_entry)
    logs = logs[-20:]

    # Save back to the log file
    with open(LOG_FILE, "w") as file:
        json.dump(logs, file, indent=4)


def require_api_key(f):
    """Decorator to enforce API key validation on protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY")

        if api_key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        return f(*args, **kwargs)
    
    return decorated_function

def is_access_allowed(user_uuid):
    """Check if the user has permission and if the garage door can be opened."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Check if user is enabled and get the assigned garage ID
        cur.execute("SELECT is_enabled, garage_id FROM users WHERE user_uuid = %s", (user_uuid,))
        user_data = cur.fetchone()

        if not user_data:
            cur.close()
            conn.close()
            return False, "User not found"

        is_enabled, garage_id = user_data

        if not is_enabled:  # `is_enabled` is False
            cur.close()
            conn.close()
            return False, "User is disabled"

        # 🔍 Get garage settings
        cur.execute("""
            SELECT admin_lock, schedule_enabled
            FROM garage_settings
            WHERE garage_id = %s
        """, (garage_id,))
        settings = cur.fetchone()

        if not settings:
            cur.close()
            conn.close()
            return False, "Garage settings not found"

        admin_lock, schedule_enabled = settings

        # 🚨 **Check Admin Lock First**
        if admin_lock:
            cur.close()
            conn.close()
            return False, "Access denied: Admin lock is enabled"

        # 🚨 **Only Enforce Schedule if it's ENABLED**
        if schedule_enabled:
            now = datetime.now(pytz.utc).astimezone(LOCAL_TZ)  # ✅ Ensure correct timezone
            current_time = now.time()  # ✅ Extract just the time with timezone applied

            cur.execute("""
                SELECT lock_start, lock_end
                FROM garage_schedule
                WHERE garage_id = %s
            """, (garage_id,))
            schedule = cur.fetchone()

            if schedule:
                lock_start, lock_end = schedule

                lock_start_str = lock_start.strftime("%I:%M %p")  # Example: "05:00 PM"
                lock_end_str = lock_end.strftime("%I:%M %p")  # Example: "02:00 AM"

                # 🛑 **Case 1: Lock is within the same day (e.g., 2 PM - 10 PM)**
                if lock_start < lock_end:
                    if lock_start <= current_time <= lock_end:
                        cur.close()
                        conn.close()
                        return False, f"❌ Access denied: Outside allowed time ({lock_start_str} - {lock_end_str})"

                # 🛑 **Case 2: Lock spans midnight (e.g., 5 PM - 2 AM)**
                else:
                    if current_time >= lock_start or current_time <= lock_end:
                        cur.close()
                        conn.close()
                        return False, f"❌ Access denied: Outside allowed time ({lock_start_str} - {lock_end_str})"

        cur.close()
        conn.close()
        return True, "Access granted"

    except Exception as e:
        return False, f"Database error: {str(e)}"

@app.route('/toggle_user', methods=['PATCH'])
@require_api_key 
def toggle_user():
    """Enable or disable a user (only accessible by admins)"""
    data = request.get_json()
    
    admin_uuid = request.headers.get("X-User-UUID") or data.get("user_uuid")
    target_first_name = data.get("first_name")  # Target user's first name
    target_last_name = data.get("last_name")  # Target user's last name
    is_enabled = data.get("is_enabled")  # New status

    if not admin_uuid or not target_first_name or not target_last_name or is_enabled is None:
        return jsonify({"error": "Admin UUID, first name, last name, and new status are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Verify that the requesting user is an admin
        cur.execute("SELECT is_admin, garage_id FROM users WHERE user_uuid = %s", (admin_uuid,))
        admin_data = cur.fetchone()

        if not admin_data:
            return jsonify({"error": "Admin not found"}), 404

        is_admin, admin_garage_id = admin_data

        if not is_admin:
            return jsonify({"error": "Unauthorized - Only admins can modify users"}), 403

        # Find the user in the same garage
        cur.execute("""
            SELECT user_uuid FROM users 
            WHERE first_name = %s AND last_name = %s AND garage_id = %s
        """, (target_first_name, target_last_name, admin_garage_id))
        
        target_user = cur.fetchone()

        if not target_user:
            return jsonify({"error": "User not found in this garage"}), 404

        target_user_uuid = target_user[0]

        # Update the user's enabled status
        cur.execute("""
            UPDATE users 
            SET is_enabled = %s 
            WHERE user_uuid = %s 
            RETURNING user_uuid, is_enabled
        """, (is_enabled, target_user_uuid))

        updated_user = cur.fetchone()

        if not updated_user:
            return jsonify({"error": "User update failed"}), 500

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "user_uuid": updated_user[0],
            "is_enabled": updated_user[1]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get_garage_settings', methods=['GET'])
def get_garage_settings():
    """Fetch garage settings based on user UUID."""
    user_uuid = request.headers.get("X-User-UUID") or request.args.get("user_uuid")

    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Lookup garage_id based on user UUID
        cur.execute("SELECT garage_id FROM users WHERE user_uuid = %s", (user_uuid,))
        user_garage = cur.fetchone()

        if not user_garage:
            return jsonify({"error": "User not found or not assigned to a garage"}), 404

        garage_id = user_garage[0]

        # 🔍 Get garage settings
        cur.execute("""
            SELECT admin_lock, schedule_enabled
            FROM garage_settings
            WHERE garage_id = %s
        """, (garage_id,))
        settings = cur.fetchone()

        if not settings:
            return jsonify({"error": "Garage settings not found"}), 404

        admin_lock, schedule_enabled = settings

        cur.close()
        conn.close()

        return jsonify({
            "garage_id": garage_id,
            "admin_lock": admin_lock,
            "schedule_enabled": schedule_enabled
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
        
def connect_mqtt():
    """Attempt to connect to MQTT broker with retry logic"""
    client = mqtt.Client()
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        print("✅ MQTT Connected Successfully")
        return client
    except Exception as e:
        print(f"❌ MQTT Connection Failed: {e}")
        return None

# Initial MQTT Connection
mqtt_client = connect_mqtt()

@app.route('/dbtest', methods=['GET'])
def test_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return jsonify({"message": "Database connected successfully"})
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def get_db_connection():
    """Create a new database connection"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

@app.route('/get_users', methods=['GET'])
@require_api_key  # Ensures API security
def get_users():
    """Fetch all users for the garage assigned to the requesting user (Admin only)."""
    try:
        # 🔍 Get user UUID from headers
        user_uuid = request.headers.get("X-User-UUID")

        if not user_uuid:
            return jsonify({"error": "User UUID is required"}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Look up user info (garage_id & admin status)
        cur.execute("SELECT garage_id, is_admin FROM users WHERE user_uuid = %s", (user_uuid,))
        user_info = cur.fetchone()

        if not user_info:
            return jsonify({"error": "User not found"}), 404

        garage_id, is_admin = user_info

        # 🚨 Ensure only admins can fetch users

        # 🔍 Fetch users in the same garage
        cur.execute("""
            SELECT first_name, last_name, is_enabled, is_admin
            FROM users WHERE garage_id = %s
        """, (garage_id,))
        users = cur.fetchall()
        cur.close()
        conn.close()

        # ✅ Format user list
        user_list = [{
            "first_name": user[0],
            "last_name": user[1],
            "is_enabled": user[2],
            "is_admin": user[3]
        } for user in users]

        return jsonify(user_list)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/garage_history', methods=['GET'])
def get_garage_history():
    """Return the last 20 garage opens"""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            try:
                logs = json.load(file)
            except json.JSONDecodeError:
                logs = []
    else:
        logs = []

    return jsonify(logs[::-1])


@app.route('/update_schedule', methods=['POST'])
@require_api_key 
def update_garage_schedule():
    """Insert or update a schedule for a garage"""

    data = request.get_json()

    # 🔍 Get user UUID from headers or request JSON
    user_uuid = request.headers.get("X-User-UUID") or data.get("user_uuid")

    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        uuid.UUID(user_uuid)  # Validate UUID format
    except ValueError:
        return jsonify({"error": "Invalid User UUID format"}), 400

    lock_start = data.get("lock_start")
    lock_end = data.get("lock_end")

    if not lock_start or not lock_end:
        return jsonify({"error": "lock_start and lock_end are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Look up garage ID from user UUID
        cur.execute("SELECT garage_id FROM users WHERE user_uuid = %s", (user_uuid,))
        user_garage = cur.fetchone()

        if not user_garage:
            return jsonify({"error": "User not found or not assigned to a garage"}), 404

        garage_id = user_garage[0]

        # 🔍 Check if a schedule already exists for this garage
        cur.execute("SELECT 1 FROM garage_schedule WHERE garage_id = %s", (garage_id,))
        exists = cur.fetchone()

        if exists:
            # ✅ Update existing schedule
            query = """
                UPDATE garage_schedule
                SET lock_start = %s, lock_end = %s
                WHERE garage_id = %s
                RETURNING garage_id, lock_start, lock_end
            """
            cur.execute(query, (lock_start, lock_end, garage_id))
        else:
            # 🚀 Insert new schedule
            query = """
                INSERT INTO garage_schedule (garage_id, lock_start, lock_end)
                VALUES (%s, %s, %s)
                RETURNING garage_id, lock_start, lock_end
            """
            cur.execute(query, (garage_id, lock_start, lock_end))

        updated_row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "garage_id": updated_row[0],  # ✅ Fixed Index
            "lock_start": updated_row[1].strftime("%H:%M:%S"),  # ✅ Fixed Index
            "lock_end": updated_row[2].strftime("%H:%M:%S")  # ✅ Fixed Index
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    """Retrieve user information from the database using UUID"""
    user_uuid = request.headers.get("X-User-UUID") or request.args.get("user_uuid")

    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT first_name, last_name, is_enabled, is_admin, garage_id 
            FROM users 
            WHERE user_uuid = %s
        """, (user_uuid,))
        
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "first_name": user[0],
            "last_name": user[1],
            "is_enabled": user[2],
            "is_admin": user[3],
            "garage_id": user[4]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_garage_schedule', methods=['GET'])
def get_garage_schedule():
    """Retrieve the schedule for the garage assigned to the user"""
    user_uuid = request.headers.get("X-User-UUID")

    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get the garage ID linked to the user
        cur.execute("SELECT garage_id FROM users WHERE user_uuid = %s", (user_uuid,))
        user_garage = cur.fetchone()

        if not user_garage:
            return jsonify({"error": "User not found or not assigned to a garage"}), 404

        garage_id = user_garage[0]

        # Retrieve the schedule for the garage
        cur.execute("SELECT lock_start, lock_end FROM garage_schedule WHERE garage_id = %s", (garage_id,))
        schedule = cur.fetchone()

        cur.close()
        conn.close()

        if not schedule:
            return jsonify({"error": "No schedule found for this garage"}), 404

        return jsonify({
            "lock_start": schedule[0].strftime("%H:%M:%S"),
            "lock_end": schedule[1].strftime("%H:%M:%S")
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update_settings', methods=['PATCH'])
@require_api_key 
def update_garage_settings():
    """Update or insert garage settings, ensuring only admins can toggle `admin_lock`"""

    data = request.get_json()

    # 🔍 Get user UUID from headers or request JSON
    user_uuid = request.headers.get("X-User-UUID") or data.get("user_uuid")

    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        uuid.UUID(user_uuid)  # Validate UUID format
    except ValueError:
        return jsonify({"error": "Invalid User UUID format"}), 400

    # Retrieve settings from request
    admin_lock = data.get("admin_lock")
    schedule_enabled = data.get("schedule_enabled")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Lookup the garage ID and admin status from user UUID
        cur.execute("SELECT garage_id, is_admin FROM users WHERE user_uuid = %s", (user_uuid,))
        user_data = cur.fetchone()

        if not user_data:
            return jsonify({"error": "User not found or not assigned to a garage"}), 404

        garage_id, is_admin = user_data

        # 🔍 Check if settings exist for the garage
        cur.execute("SELECT * FROM garage_settings WHERE garage_id = %s", (garage_id,))
        existing_settings = cur.fetchone()

        if existing_settings:
            # ✅ Update existing settings
            fields = []
            values = []

            if admin_lock is not None:
                if not is_admin:
                    return jsonify({"error": "Unauthorized - Only admins can toggle admin_lock"}), 403
                fields.append("admin_lock = %s")
                values.append(admin_lock)

            if schedule_enabled is not None:
                fields.append("schedule_enabled = %s")
                values.append(schedule_enabled)

            values.append(garage_id)  # WHERE clause

            if fields:
                query = f"UPDATE garage_settings SET {', '.join(fields)} WHERE garage_id = %s RETURNING *"
                cur.execute(query, tuple(values))
                updated_row = cur.fetchone()
            else:
                updated_row = existing_settings  # No updates, return current settings

        else:
            # 🚀 Insert new settings since they don't exist
            query = """
                INSERT INTO garage_settings (garage_id, admin_lock, schedule_enabled)
                VALUES (%s, %s, %s)
                RETURNING *
            """
            cur.execute(query, (garage_id, admin_lock if admin_lock is not None else False,
                                schedule_enabled if schedule_enabled is not None else False))
            updated_row = cur.fetchone()

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "garage_id": updated_row[1],  # Corrected index
            "admin_lock": updated_row[2],  # Corrected index
            "schedule_enabled": updated_row[3]  # Corrected index
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/add_user', methods=['POST'])
@require_api_key
def add_user():
    """API endpoint to add a new user using a garage UUID and return the garage name"""
    try:
        data = request.get_json()
        is_enabled = False  # Default: User must be enabled manually
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        garage_uuid = data.get("garage_uuid")  # 🔥 Use UUID instead of ID
        is_admin = False  # Default: Not an admin

        if not first_name or not last_name or not garage_uuid:
            return jsonify({"error": "First name, last name, and garage UUID are required"}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Lookup Garage ID and Garage Name from Garage UUID
        cur.execute("SELECT id, name FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Invalid garage UUID"}), 400

        garage_id, garage_name = garage  # Extract ID and Name

        # ✅ Check if the user already exists in this garage
        cur.execute("""
            SELECT * FROM users WHERE first_name = %s AND last_name = %s AND garage_id = %s
        """, (first_name, last_name, garage_id))
        existing_user = cur.fetchone()

        if existing_user:
            return jsonify({"error": "User already exists in this garage"}), 409

        # ✅ Generate a unique user UUID
        user_uuid = str(uuid.uuid4())

        # ✅ Insert new user into the database
        cur.execute("""
            INSERT INTO users (is_enabled, first_name, last_name, garage_id, is_admin, user_uuid)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING user_uuid
        """, (is_enabled, first_name, last_name, garage_id, is_admin, user_uuid))

        new_user_uuid = cur.fetchone()[0]  # Fetch the UUID

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "message": "User added successfully. Waiting for admin approval.",
            "user_uuid": new_user_uuid,
            "garage_name": garage_name,  # ✅ Return the Garage Name for UI Display
            "garage_image": "motorcycle" if garage_id == 1 else "car"  # ✅ Change per garage

        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/open', methods=['GET'])
@limiter.limit("5 per minute")
@require_api_key 
def open_garage():
    """API Route to trigger a garage door with security checks, auto-detecting the garage_id"""

    # 🔍 Get user UUID from request headers or query parameters
    user_uuid = request.headers.get("X-User-UUID") or request.args.get("user_uuid")

    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        uuid.UUID(user_uuid)  # Validate UUID format
    except ValueError:
        return jsonify({"error": "Invalid User UUID format"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT first_name, last_name FROM users WHERE user_uuid = %s", (user_uuid,))
        user_info = cur.fetchone()

        if not user_info:
            return jsonify({"error": "User not found"}), 404

        first_name, last_name = user_info


        # 🔍 Fetch the garage ID for the given user UUID
        cur.execute("SELECT garage_id FROM users WHERE user_uuid = %s", (user_uuid,))
        user_garage = cur.fetchone()

        if not user_garage:
            return jsonify({"error": "User not found or not assigned to a garage"}), 404

        garage_id = user_garage[0]

        # 🚨 **Check Access Rules**
        allowed, message = is_access_allowed(user_uuid)
        if not allowed:
            return jsonify({"error": message}), 403

        # 🔍 Determine the correct MQTT topic based on the garage ID
        topic = MQTT_TOPIC_1 if garage_id == 1 else MQTT_TOPIC_2 if garage_id == 2 else None

        if not topic:
            return jsonify({"error": "Invalid Garage ID"}), 400

        response = publish_mqtt(topic)

        log_garage_open(user_uuid, first_name, last_name)

        cur.close()
        conn.close()

        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def publish_mqtt(topic):
    """Publish MQTT message to the correct topic"""
    global mqtt_client

    # Get API Key from request
    api_key = request.headers.get("X-API-KEY")

    if api_key != API_KEY:
        print("❌ Unauthorized API Access Attempt")
        return jsonify({"error": "Unauthorized"}), 403

    try:
        if mqtt_client is None or not mqtt_client.is_connected():
            print("🔄 MQTT Reconnecting...")
            mqtt_client = connect_mqtt()
            if mqtt_client is None:
                raise Exception("MQTT Client Not Connected")

        # Publish message
        result = mqtt_client.publish(topic, "open")
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise Exception(f"Failed to publish MQTT message: {result.rc}")

        print(f"📡 MQTT Publish Successful to {topic}")
        return jsonify({"message": f"Garage door triggered: {topic}"})

    except Exception as e:
        print(f"❌ API Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
