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
limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"])

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

def is_access_allowed(user_uuid, garage_uuid):
    """Check if the user has permission and if the garage door can be opened."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Check if user is enabled and assigned to the garage (in user_garages)
        cur.execute("""
            SELECT ug.is_enabled, g.id
            FROM user_garages ug
            JOIN garages g ON ug.garage_id = g.id
            WHERE ug.user_uuid = %s AND g.garage_uuid = %s
        """, (user_uuid, garage_uuid))
        user_data = cur.fetchone()

        if not user_data:
            cur.close()
            conn.close()
            return False, "User not found or not assigned to this garage"

        is_enabled, garage_id = user_data

        if not is_enabled:
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

        if admin_lock:
            cur.close()
            conn.close()
            return False, "Access denied: Admin lock is enabled"

        if schedule_enabled:
            now = datetime.now(pytz.utc).astimezone(LOCAL_TZ)
            current_time = now.time()

            cur.execute("""
                SELECT lock_start, lock_end
                FROM garage_schedule
                WHERE garage_id = %s
            """, (garage_id,))
            schedule = cur.fetchone()

            if schedule:
                lock_start, lock_end = schedule
                lock_start_str = lock_start.strftime("%I:%M %p")
                lock_end_str = lock_end.strftime("%I:%M %p")

                if lock_start < lock_end:
                    if lock_start <= current_time <= lock_end:
                        cur.close()
                        conn.close()
                        return False, f"❌ Access denied: Outside allowed time ({lock_start_str} - {lock_end_str})"
                else:
                    if current_time >= lock_start or current_time <= lock_end:
                        cur.close()
                        conn.close()
                        return False, f"❌ Access denied: Outside allowed time ({lock_start_str} - {lock_end_str})"

        cur.close()
        conn.close()
        return True, "✅ Access granted"

    except Exception as e:
        return False, f"Database error: {str(e)}"
@app.route('/toggle_user', methods=['PATCH'])
@require_api_key 
def toggle_user():
    """Enable or disable a user for a specific garage (only admins can do this)"""
    data = request.get_json()
    
    admin_uuid = request.headers.get("X-User-UUID") or data.get("admin_uuid")
    target_first_name = data.get("first_name")
    target_last_name = data.get("last_name")
    garage_uuid = request.headers.get("X-Garage-UUID") or data.get("garage_uuid")
    is_enabled = data.get("is_enabled")

    # ❌ target_user_uuid was being referenced before it was assigned
    if not admin_uuid or not target_first_name or not target_last_name or not garage_uuid or is_enabled is None:
        return jsonify({"error": "Admin UUID, first name, last name, garage UUID, and new status are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Verify that the requesting user is an admin in this garage
        cur.execute("""
            SELECT 1 FROM user_garages ug
            JOIN garages g ON ug.garage_id = g.id
            WHERE ug.user_uuid = %s AND g.garage_uuid = %s AND ug.is_admin = TRUE
        """, (admin_uuid, garage_uuid))

        if not cur.fetchone():
            return jsonify({"error": "Unauthorized - Only admins of this garage can modify users"}), 403

        # ✅ Ensure the target user exists in the correct garage
        cur.execute("""
            SELECT ug.id, ug.user_uuid
            FROM user_garages ug
            JOIN garages g ON ug.garage_id = g.id
            JOIN users u ON u.user_uuid = ug.user_uuid
            WHERE u.first_name = %s AND u.last_name = %s AND g.garage_uuid = %s
        """, (target_first_name, target_last_name, garage_uuid))

        target_user_entry = cur.fetchone()
        if not target_user_entry:
            return jsonify({"error": "User not found in this garage"}), 404

        entry_id, target_user_uuid = target_user_entry

        # ✅ Update the user's enabled status in the context of this garage
        cur.execute("""
            UPDATE user_garages 
            SET is_enabled = %s 
            WHERE user_uuid = %s 
              AND garage_id = (SELECT id FROM garages WHERE garage_uuid = %s)
            RETURNING user_uuid, is_enabled
        """, (is_enabled, target_user_uuid, garage_uuid))

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
    """Fetch garage settings based on user UUID and selected garage UUID."""
    user_uuid = request.headers.get("X-User-UUID") or request.args.get("user_uuid")
    garage_uuid = request.headers.get("X-Garage-UUID") or request.args.get("garage_uuid")

    if not user_uuid or not garage_uuid:
        return jsonify({"error": "User UUID and Garage UUID are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Validate that the user is assigned to the given garage
        cur.execute("""
            SELECT garage_id FROM user_garages 
            WHERE user_uuid = %s AND garage_id = (
                SELECT id FROM garages WHERE garage_uuid = %s
            )
        """, (user_uuid, garage_uuid))

        garage_data = cur.fetchone()

        if not garage_data:
            return jsonify({"error": "User not assigned to this garage"}), 403

        garage_id = garage_data[0]

        # 🔍 Get garage settings for the selected garage
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
@require_api_key
def get_users():
    """Fetch users only for the admin's selected garage"""
    try:
        user_uuid = request.headers.get("X-User-UUID")
        garage_uuid = request.headers.get("X-Garage-UUID")  # ✅ Now uses selected garage

        if not user_uuid or not garage_uuid:
            return jsonify({"error": "Missing user or garage UUID"}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Validate that the user is an admin of this garage
        cur.execute("""
            SELECT is_admin FROM user_garages ug
            JOIN garages g ON ug.garage_id = g.id
            WHERE ug.user_uuid = %s AND g.garage_uuid = %s
        """, (user_uuid, garage_uuid))

        is_admin = cur.fetchone()
        if not is_admin:
            return jsonify({"error": "Unauthorized"}), 403

        # ✅ Fetch only users for the selected garage
        cur.execute("""
            SELECT  u.first_name, u.last_name, ug.is_enabled, ug.is_admin
            FROM user_garages ug
            JOIN users u ON ug.user_uuid = u.user_uuid
            JOIN garages g ON ug.garage_id = g.id
            WHERE g.garage_uuid = %s order by first_name
        """, (garage_uuid,))

        users = cur.fetchall()
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
    """Insert or update a schedule for a specific garage based on UUID"""

    data = request.get_json()

    # 🔍 Get user UUID & garage UUID from headers or request JSON
    user_uuid = request.headers.get("X-User-UUID") or data.get("user_uuid")
    garage_uuid = request.headers.get("X-Garage-UUID") or data.get("garage_uuid")

    if not user_uuid or not garage_uuid:
        return jsonify({"error": "User UUID and Garage UUID are required"}), 400

    try:
        uuid.UUID(user_uuid)  # Validate User UUID format
        uuid.UUID(garage_uuid)  # Validate Garage UUID format
    except ValueError:
        return jsonify({"error": "Invalid UUID format"}), 400

    lock_start = data.get("lock_start")
    lock_end = data.get("lock_end")

    if not lock_start or not lock_end:
        return jsonify({"error": "lock_start and lock_end are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Look up the garage ID from the provided garage UUID
        cur.execute("SELECT id FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Garage not found"}), 404

        garage_id = garage[0]

        # 🔍 Check if the user is assigned to this garage
        cur.execute("SELECT 1 FROM user_garages WHERE user_uuid = %s AND garage_id = %s", (user_uuid, garage_id))
        is_assigned = cur.fetchone()

        if not is_assigned:
            return jsonify({"error": "User is not assigned to this garage"}), 403

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
            "garage_id": updated_row[0],  # ✅ Return correct garage ID
            "lock_start": updated_row[1].strftime("%I:%M %p"),  # 🕒 Convert to non-military time
            "lock_end": updated_row[2].strftime("%I:%M %p")  # 🕒 Convert to non-military time
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    """Retrieve user information for a specific garage UUID"""
    user_uuid = request.headers.get("X-User-UUID") or request.args.get("user_uuid")
    garage_uuid = request.headers.get("X-Garage-UUID") or request.args.get("garage_uuid")

    if not user_uuid or not garage_uuid:
        return jsonify({"error": "User UUID and Garage UUID are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Get the garage ID from the provided garage UUID
        cur.execute("SELECT id, name, image FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Invalid garage UUID"}), 404

        garage_id, garage_name, image_name = garage

        # 🔍 Retrieve user details by joining `users` and `user_garages`
        cur.execute("""
            SELECT u.first_name, u.last_name, ug.is_enabled, ug.is_admin 
            FROM users u
            JOIN user_garages ug ON u.user_uuid = ug.user_uuid
            WHERE u.user_uuid = %s AND ug.garage_id = %s
        """, (user_uuid, garage_id))

        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"error": "User not found in this garage"}), 404

        return jsonify({
            "first_name": user[0],
            "last_name": user[1],
            "is_enabled": user[2],
            "is_admin": user[3],
            "image_name": image_name
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_garage_schedule', methods=['GET'])
def get_garage_schedule():
    """Retrieve the schedule for a specific garage based on Garage UUID"""
    user_uuid = request.headers.get("X-User-UUID")
    garage_uuid = request.headers.get("X-Garage-UUID")  # 🔥 Now uses Garage UUID

    if not user_uuid or not garage_uuid:
        return jsonify({"error": "User UUID and Garage UUID are required"}), 400

    try:
        uuid.UUID(user_uuid)  # Validate User UUID format
        uuid.UUID(garage_uuid)  # Validate Garage UUID format
    except ValueError:
        return jsonify({"error": "Invalid UUID format"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Lookup the garage ID based on Garage UUID
        cur.execute("SELECT id FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Garage not found"}), 404

        garage_id = garage[0]

        # 🔍 Ensure the user is assigned to this garage
        cur.execute("""
            SELECT 1 FROM user_garages 
            WHERE user_uuid = %s AND garage_id = %s
        """, (user_uuid, garage_id))
        is_assigned = cur.fetchone()

        if not is_assigned:
            return jsonify({"error": "User is not assigned to this garage"}), 403

        # 🔍 Retrieve the schedule for the garage
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

@app.route('/add_garage', methods=['POST'])
@require_api_key
def add_garage():
    """Adds an existing garage to a user's account based on UUIDs."""
    try:
        data = request.get_json()
        user_uuid = request.headers.get("X-User-UUID") or data.get("user_uuid")
        garage_uuid = data.get("garage_uuid")

        if not user_uuid or not garage_uuid:
            return jsonify({"error": "User UUID and Garage UUID are required"}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 **Check if the garage exists**
        cur.execute("SELECT id, name FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Invalid garage UUID"}), 404

        garage_id, garage_name = garage

        # 🔍 **Check if the user already has access to this garage**
        cur.execute("""
            SELECT 1 FROM user_garages WHERE user_uuid = %s AND garage_id = %s
        """, (user_uuid, garage_id))
        existing_access = cur.fetchone()

        if existing_access:
            return jsonify({"error": "User already has access to this garage"}), 409

        # ✅ **Add the user to the garage**
        cur.execute("""
            INSERT INTO user_garages (user_uuid, garage_id)
            VALUES (%s, %s)
        """, (user_uuid, garage_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "message": "Garage successfully added to user",
            "garage_uuid": garage_uuid,
            "garage_name": garage_name
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_garage_info', methods=['GET'])
def get_garage_info():
    """Retrieve all garages assigned to a user along with their names and UUIDs."""
    
    user_uuid = request.headers.get("X-User-UUID")
    
    if not user_uuid:
        return jsonify({"error": "User UUID is required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch user details (first_name, last_name)
        cur.execute("""
            SELECT first_name, last_name 
            FROM users 
            WHERE user_uuid = %s
        """, (user_uuid,))
        
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        first_name, last_name = user

        # ✅ Fetch all garages linked to the user
        cur.execute("""
            SELECT g.garage_uuid, g.name 
            FROM garages g
            JOIN user_garages ug ON g.id = ug.garage_id  -- ✅ Using user_garages table
            WHERE ug.user_uuid = %s
        """, (user_uuid,))
        
        garages = cur.fetchall()

        cur.close()
        conn.close()

        # ✅ Format response
        garage_list = [{"uuid": row[0], "name": row[1]} for row in garages]

        return jsonify({
            "first_name": first_name,
            "last_name": last_name,
            "garages": garage_list
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update_settings', methods=['PATCH'])
@require_api_key 
def update_garage_settings():
    """Update or insert garage settings, ensuring only admins can modify settings for the selected garage"""

    data = request.get_json()

    # 🔍 Get user and garage UUIDs from headers
    user_uuid = request.headers.get("X-User-UUID")
    garage_uuid = request.headers.get("X-Garage-UUID")

    if not user_uuid or not garage_uuid:
        return jsonify({"error": "User UUID and Garage UUID are required"}), 400

    try:
        uuid.UUID(user_uuid)  # Validate User UUID format
        uuid.UUID(garage_uuid)  # Validate Garage UUID format
    except ValueError:
        return jsonify({"error": "Invalid UUID format"}), 400

    # Retrieve settings from request
    admin_lock = data.get("admin_lock")
    schedule_enabled = data.get("schedule_enabled")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Lookup the garage ID from the provided Garage UUID
        cur.execute("SELECT id FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Garage not found"}), 404

        garage_id = garage[0]

        # 🔍 Verify that the user is an admin of this garage
        cur.execute("SELECT is_admin FROM user_garages WHERE user_uuid = %s AND garage_id = %s", (user_uuid, garage_id))
        user_data = cur.fetchone()

        if not user_data:
            return jsonify({"error": "User is not assigned to this garage"}), 403

        is_admin = user_data[0]

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
            "garage_id": garage_id,
            "admin_lock": updated_row[2],  # Fixed index
            "schedule_enabled": updated_row[3]  # Fixed index
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/add_user', methods=['POST'])
@require_api_key
def add_user():
    """API endpoint to add a user to a garage using their UUID."""
    try:
        data = request.get_json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        garage_uuid = data.get("garage_uuid")

        if not first_name or not last_name or not garage_uuid:
            return jsonify({"error": "First name, last name, and garage UUID are required"}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Lookup Garage ID
        cur.execute("SELECT id, name FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        garage = cur.fetchone()

        if not garage:
            return jsonify({"error": "Invalid garage UUID"}), 400

        garage_id, garage_name = garage

        # ✅ Check if user already exists
        cur.execute("SELECT user_uuid FROM users WHERE first_name = %s AND last_name = %s", 
                    (first_name, last_name))
        user = cur.fetchone()

        if user:
            user_uuid = user[0]  # Existing user
        else:
            user_uuid = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO users (user_uuid, first_name, last_name) 
                VALUES (%s, %s, %s)
                RETURNING user_uuid
            """, (user_uuid, first_name, last_name))
            user_uuid = cur.fetchone()[0]

        # ✅ Add user to the garage
        cur.execute("""
            INSERT INTO user_garages (user_uuid, garage_id) 
            VALUES (%s, %s) 
            ON CONFLICT (user_uuid, garage_id) DO NOTHING
        """, (user_uuid, garage_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "message": "User added to garage successfully. Waiting for admin approval.",
            "user_uuid": user_uuid,
            "garage_name": garage_name,
            "garage_image": "motorcycle" if garage_id == 1 else "car" 
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/open', methods=['GET'])
@limiter.limit("10 per minute")
@require_api_key 
def open_garage():
    """API Route to trigger a garage door with security checks, auto-detecting the garage_id"""

    # 🔍 Get user UUID from request headers or query parameters
    user_uuid = request.headers.get("X-User-UUID") or request.args.get("user_uuid")
    garage_uuid = request.headers.get("X-Garage-UUID") or request.args.get("garage_uuid")

    if not user_uuid:
        return jsonify({"error": "User UUID and Garage UUID required"}), 400

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
 


      

        # 🚨 **Check Access Rules**
        allowed, message = is_access_allowed(user_uuid, garage_uuid)
        if not allowed:
            return jsonify({"error": message}), 403

        # 🔍 Determine the correct MQTT topic based on the garage ID
        cur.execute("SELECT mqtt_topic FROM garages WHERE garage_uuid = %s", (garage_uuid,))
        result = cur.fetchone()
        topic = result[0] if result else None

        if not topic:
            return jsonify({"error": "MQTT topic not configured for this garage"}), 500


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
