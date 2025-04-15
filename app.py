import os
import re
import sys
import tempfile
import time
import uuid
import uuid as uid
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from typing import List

import psycopg2
import requests
from PIL import Image, ImageDraw, ImageFont
from flask import Flask, request, render_template, jsonify, session, redirect, url_for, Response
from flask import flash
from flask import render_template_string, make_response, abort
from flask import send_file
from flask import send_from_directory
from psycopg2 import sql
from psycopg2._psycopg import DatabaseError
from psycopg2.extras import RealDictCursor
from scapy.all import rdpcap
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash

# ------------------------ FLASK APP ------------------------- #

# Flask app instance
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# ------------------ ENVIRONMENT VARIABLES -------------------- #

# Flags and awards
FLAG_1 = os.getenv("FLAG_1")
FLAG_2 = os.getenv("FLAG_2")
FLAG_3 = os.getenv("FLAG_3")
FLAG_4 = os.getenv("FLAG_4")
FLAG_5 = os.getenv("FLAG_5")
FLAG_1_SCORE = 50
FLAG_2_SCORE = 75
FLAG_3_SCORE = 125
FLAG_4_SCORE = 150
FLAG_5_SCORE = 100

# Flag key variable
KEY = os.getenv("KEY")

# Valid API key
VALID_API_KEYS = [os.getenv("VALID_API_KEY")]

# Global Tracker Variables
RATE_LIMIT = 0
LAST_RESET_TIME = time.time()
START_TIME = time.time()

# DB Global Var
DB_URL_AIVEN = os.getenv("DB_URL_AIVEN")
DB_NAME = os.getenv("DB_NAME")

# Bank Global Var
USERNAME = os.getenv('USERNAME_BANK')
PASSWORD = os.getenv('PASSWORD_BANK')


# ------------------------- DATABASE ------------------------- #

# Database connection
def get_db_connection() -> psycopg2._psycopg.connection:
    conn = psycopg2.connect(dsn=DB_URL_AIVEN, dbname=DB_NAME)
    return conn


# Reset admin required rate limit
def reset_rate_limit():
    global RATE_LIMIT, LAST_RESET_TIME
    if time.time() - LAST_RESET_TIME >= 3600:
        RATE_LIMIT = 0
        LAST_RESET_TIME = time.time()


# Decorator to check if the user is an admin
def admin_required(param: callable):
    @wraps(param)
    def wrap(*args, **kwargs):
        global RATE_LIMIT
        reset_rate_limit()

        is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"

        if is_browser_request:
            if 'team_name' not in session:
                return redirect(url_for('signin'))
            if session['team_name'] != 'ADMIN':
                abort(403, description=f"Insufficient Permissions, User {session['team_name']} is not admin")
        else:
            try:
                api_key = request.json.get('api-key') if request.is_json else request.headers.get('api-key')
                if api_key not in VALID_API_KEYS:
                    RATE_LIMIT += 1
                    if RATE_LIMIT > 15:
                        abort(429, description="Rate limit exceeded. Try again later.")
                    abort(403, description="Invalid API Key for ADMIN")
            except Exception:
                abort(400, description="No API key passed")

        return param(*args, **kwargs)

    return wrap


# Decorator to rate limit the user - Advised not to use with @admin_required
def rate_limit(limit: int, time_window: int = 3600):
    # Create an independent store for each decorator instance
    request_store = {}

    def decorator(func):
        @wraps(func)  # Preserve the original function metadata
        def wrapper(*args, **kwargs):
            user_ip = request.remote_addr
            current_time = time.time()

            # Ensure user IP is in the request store
            if user_ip not in request_store:
                request_store[user_ip] = []

            timestamps = request_store[user_ip]
            valid_timestamps = [ts for ts in timestamps if current_time - ts <= time_window]
            request_store[user_ip] = valid_timestamps

            if len(valid_timestamps) >= limit:
                abort(429, description="Rate limit exceeded. Try again later.")

            request_store[user_ip].append(current_time)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def create_tables():
    commands = [
        """
        CREATE TABLE IF NOT EXISTS teams (
            id SERIAL PRIMARY KEY,
            team_name VARCHAR(255) UNIQUE NOT NULL,
            score INTEGER DEFAULT 0,
            flags_submitted TEXT DEFAULT '',
            password TEXT NOT NULL,
            ip_address VARCHAR(255)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS item (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            price FLOAT NOT NULL,
            image TEXT NOT NULL,
            description TEXT,
            stock INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS receipt (
            id SERIAL PRIMARY KEY,
            user_email VARCHAR(255) NOT NULL,
            item_id INTEGER NOT NULL REFERENCES item(id),
            status VARCHAR(50) DEFAULT 'pending'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS missions (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            scraps INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS challenge_progress (
            id SERIAL PRIMARY KEY,
            team_name VARCHAR(255) NOT NULL REFERENCES teams(team_name),
            challenge_id INTEGER NOT NULL,
            flag_submitted BOOLEAN DEFAULT FALSE,
            score INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS credit_card (
            uuid UUID PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            scraps INTEGER DEFAULT 0
        )
        """
    ]

    try:
        # Connect to the PostgreSQL database
        conn = get_db_connection()
        cur = conn.cursor()

        # Execute each command to create the tables
        for command in commands:
            cur.execute(command)

        # Commit the changes
        conn.commit()

        print("Tables created successfully.")

    except Exception as e:
        print(f"Error creating tables: {e}")

    finally:
        if conn:
            cur.close()
            conn.close()


# --------------------------- APIs ---------------------------- #
# ------------------------ Standalone --------------------------#

@app.route('/api/executeQuery', methods=['POST'])
@admin_required
def execute_query():
    query = request.json.get('query')
    if not query:
        return jsonify({"error": "No query provided"}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        if query.strip().lower().startswith("select"):
            results = cursor.fetchall()
        else:
            conn.commit()
            results = {"message": "Query executed successfully"}
        cursor.close()
        conn.close()
        return jsonify(results), 200
    except Exception:
        return jsonify({"error": "Query Execution Failed - API execute_query"}), 500


@app.route('/abort/<http_code>')
@admin_required
def abort_num(http_code: int):
    http_status_codes = [
        100, 101, 102, 103, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
        300, 301, 302, 303, 304, 305, 306, 307, 308,
        400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
        415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 427, 428, 429, 431, 451,
        500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511
    ]
    if int(http_code) not in http_status_codes:
        abort(400, description=f"Invalid http code passed to abort, {http_code}")
    abort(int(http_code), description=f"Requested to abort with code {http_code}")


@app.route('/api/status', methods=['GET'])
def api_status():
    uptime = round(time.time() - START_TIME, 2)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        db_status = True
    except Exception:
        db_status = False

    return jsonify({
        "status": "API is running",
        "uptime_seconds": uptime,
        "database_connected": db_status
    })


@app.route('/api/download/<challenge_id>', methods=['GET'])
@rate_limit(limit=100)
def download_challenge_files(challenge_id: str):
    # Ensure the challenge_id is valid (you can expand this with your own validation logic)
    if challenge_id not in ["bin", "images", "pcap"]:
        return abort(404, description="Invalid challenge zip, available ['bin', 'images', 'pcap']")

    # Assuming challenge files are stored in a directory called 'challenge'
    challenge_file_path = f"../src/assets/{challenge_id}.zip"

    if os.path.exists(challenge_file_path):
        try:
            return send_from_directory('src/assets', f"{challenge_id}.zip", as_attachment=True), 200
        except Exception:
            return abort(500, description="Download Challenge Files Failed")
    else:
        return abort(404, description="Challenge files not found")


@app.route('/backup/db', methods=['GET'])
@admin_required
def backup_db():
    try:
        # Get the PostgreSQL database connection
        conn = get_db_connection()
        backup_file = BytesIO()

        with conn.cursor() as cursor:
            # Use PostgreSQL's built-in COPY command to dump the entire database
            cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
            tables = cursor.fetchall()

            for table in tables:
                table_name = table[0]
                cursor.copy_expert(f"COPY {table_name} TO STDOUT WITH BINARY", backup_file)

        backup_file.seek(0)

        # Create a response to stream the file to the user
        return Response(
            backup_file,
            mimetype='application/octet-stream',
            headers={"Content-Disposition": "attachment; filename=database_backup.dump"}
        )
    except Exception as e:
        return abort(500, description=f"Error backing up database as {e}")


# -------------------------- SHOP ------------------------------#

@app.route('/api/shop/buy', methods=['POST'])
@rate_limit(limit=50)
def buy():
    item_id = request.form.get('item_id')
    user_email = request.form.get('email')

    if not item_id or not user_email:
        flash("Invalid input! Make sure all fields are filled.", "error")
        return redirect(url_for('shop'))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM item WHERE id = %s;', (item_id,))
    item = cur.fetchone()

    if item and item["stock"] > 0:
        cur.execute('INSERT INTO receipt (user_email, item_id) VALUES (%s, %s);', (user_email, item_id))
        conn.commit()

        # Fetch the image URL (stored in the `image` column of the database)
        item_image_url = item['image']  # Assuming this is the URL of the image

        # Generate receipt image and return as a downloadable file
        receipt_image_io = generate_receipt_image(user_email, item['name'], item['price'], item_image_url)

        # Return the image directly as a downloadable file without saving it
        return send_file(receipt_image_io, mimetype='image/png', as_attachment=True,
                         download_name=f"receipt_{str(uuid.uuid4())[:8]}.png")

    else:
        flash('Item out of stock!', 'error')

    cur.close()
    conn.close()
    return redirect(url_for('shop'))


@app.route('/api/shop/update_stock', methods=['POST'])
@admin_required
def update_stock():
    conn = get_db_connection()
    cur = conn.cursor()

    # Iterate through all posted stock values
    for key, value in request.form.items():
        if key.startswith("stock_"):  # The key will be in the form of 'stock_<item_id>'
            item_id = key.split("_")[1]
            new_stock = int(value)
            cur.execute('UPDATE item SET stock = %s WHERE id = %s;', (new_stock, item_id))

    conn.commit()
    cur.close()
    conn.close()
    flash("Stock updated successfully!", "success")
    return redirect(url_for('modify_stock'))


@app.route('/api/shop/cancel_receipt', methods=['POST'])
@admin_required
def cancel_receipt():
    receipt_id = request.form.get('receipt_id')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM receipt WHERE id = %s;', (receipt_id,))
    conn.commit()
    flash("Receipt cancelled!", "success")

    cur.close()
    conn.close()
    return redirect(url_for('volunteer'))


@app.route('/api/shop/remove_mission/<int:mission_id>', methods=['GET'])
@admin_required
def remove_mission(mission_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM missions WHERE id = %s;', (mission_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash("Mission removed successfully!", "success")
    return redirect(url_for('missions'))


@app.route('/api/shop/add_mission', methods=['GET', 'POST'])
@admin_required
def add_mission():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        scraps = request.form.get('scraps')

        if not name or not description or not scraps:
            flash("All fields are required!", "error")
            return redirect(url_for('add_mission'))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO missions (name, description, scraps) VALUES (%s, %s, %s);',
                    (name, description, int(scraps)))
        conn.commit()
        cur.close()
        conn.close()

        flash("Mission added successfully!", "success")
        return redirect(url_for('missions'))

    return render_template_string(ADD_MISSION_TEMPLATE), 200


# --------------------------- GET ------------------------------#
@app.route('/api/get/size', methods=['GET'])
def get_db_size():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT pg_size_pretty(pg_database_size(current_database())) AS size")
        size = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return jsonify({"size": size}), 200
    except Exception:
        return jsonify({"error": "Failed to get database size"}), 500


@app.route('/api/get/activeConnections', methods=['GET'])
@rate_limit(limit=100)
def get_active_connections():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND pid <> pg_backend_pid()")
        active_connections = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return jsonify({"activeConnections": active_connections}), 200
    except Exception:
        return jsonify({"error": "Failed to get active connections"}), 500


@app.route('/api/get/allTeams', methods=['GET'])
@rate_limit(limit=100)
def view_teams():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, team_name, score FROM teams')
        teams = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(teams), 200
    except Exception:
        return jsonify({"error": "Failed to get all teams"}), 500


@app.route('/api/get/challengesProgress', methods=['GET'])
@rate_limit(limit=100)
def get_challenge_progress():
    if 'team_name' not in session:
        return jsonify({"error": "User not logged in"}), 401

    team_name = session['team_name']

    try:
        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute("""
            SELECT challenge_id, flag_submitted, score
            FROM challenge_progress
            WHERE team_name = %s
        """, (team_name,))

        progress = cursor.fetchall()

        if not progress:
            return jsonify({"message": "No progress found for the team"}), 404

        progress_data = [
            {
                "challenge_id": challenge_id,
                "flag_submitted": flag_submitted,
                "score": score
            }
            for challenge_id, flag_submitted, score in progress
        ]

        return jsonify(progress_data), 200

    except DatabaseError:
        return jsonify({"error": "Database error has occurred - Function get_challenge_progress"}), 500
    except Exception:
        return jsonify({"error": "An error occurred - Function get_challenge_progress"}), 500

    finally:
        cursor.close()
        conn.close()


@app.route('/api/get/leaderboard', methods=['GET'])
@rate_limit(limit=100)
def get_leaderboard():
    try:
        page = int(request.args.get('page', 1))  # Default to page 1
        per_page = int(request.args.get('per_page', 10))  # Default to 10 teams per page

        # Calculate offset for pagination
        offset = (page - 1) * per_page

        # Fetch leaderboard data from the database
        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute("""
            SELECT team_name, score 
            FROM teams
            ORDER BY score DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        leaderboard_local = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify([{"team_name": team_name, "score": score} for team_name, score in leaderboard_local]), 200
    except Exception:
        return jsonify({"error": "Failed to get leaderboard"}), 500


# ------------------------ GET/Tables --------------------------#
@app.route('/api/get/tables', methods=['GET'])
@admin_required
def get_tables():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            AND table_name NOT LIKE 'pg_%'
            AND table_name NOT LIKE 'sql_%'
        """)
        tables = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify([table[0] for table in tables]), 200
    except Exception:
        return jsonify({"error": "Getting the tables failed"}), 500


@app.route('/api/get/tables/<table_name>', methods=['GET'])
@admin_required
def get_table_rows(table_name: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = sql.SQL("SELECT * FROM {} LIMIT 100").format(sql.Identifier(table_name))
        cursor.execute(query)
        rows = cursor.fetchall()

        cursor.close()
        conn.close()
        return jsonify(rows), 200
    except Exception:
        return jsonify({"error": "Getting the table rows failed"}), 500


@app.route('/api/get/tables/<table_name>/schema', methods=['GET'])
@admin_required
def get_table_schema(table_name: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = %s
        """, (table_name,))
        schema = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(schema), 200
    except Exception:
        return jsonify({"error": "Getting the table schema failed"}), 500


@app.route('/api/get/tables/headers/<string:table_name>')
@admin_required
def get_table_headers(table_name: str):
    try:
        # Assuming we have a function to get the table headers from the database
        conn = get_db_connection()
        cursor = conn.cursor()

        query = sql.SQL("SELECT * FROM {} LIMIT 1").format(sql.Identifier(table_name))
        cursor.execute(query)
        row = cursor.fetchone()

        if row is None:
            raise Exception("Table is empty")

        headers = [desc[0] for desc in cursor.description]
        cursor.close()
        conn.close()

        # Reformat all the headers to be human-readable
        return jsonify([header.replace("_", " ").title() for header in headers])
    except Exception:
        return jsonify({"error": "Getting the table rows headers failed"}), 500


# ------------------------- DELETE ----------------------------#


@app.route('/api/delete/tables/<table_name>/<int:row_id>', methods=['DELETE'])
@admin_required
def delete_table_item(table_name: str, row_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get the primary key column name for the table
        cursor.execute("""
            SELECT a.attname
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = %s AND c.contype = 'p'
        """, (table_name,))
        primary_key_column = cursor.fetchone()[0]

        # Use the primary key column name in the delete query
        query = sql.SQL("DELETE FROM {} WHERE {} = %s").format(sql.Identifier(table_name),
                                                               sql.Identifier(primary_key_column))
        cursor.execute(query, (row_id,))
        conn.commit()

        cursor.close()
        conn.close()
        return jsonify({"message": "Item deleted successfully."}), 200
    except Exception:
        return jsonify({"error": f"Failed to delete item"}), 500


@app.route('/api/delete/tables/<table_name>', methods=['DELETE'])
@admin_required
def delete_table(table_name: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(table_name))
        cursor.execute(query)
        conn.commit()

        cursor.close()
        conn.close()
        return jsonify({"message": "Table deleted successfully."}), 200
    except Exception:
        return jsonify({"error": "Deleting the table failed"}), 500


@app.route('/api/delete/database', methods=['POST'])
@admin_required
def delete_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS teams")
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Database deleted successfully."}), 200
    except Exception:
        return jsonify({"error": "Deleting the database failed"}), 500


# ------------------------ GET/User ---------------------------#
@app.route('/api/get/user/profile', methods=['GET'])
@rate_limit(limit=100)
def get_user_profile():
    try:
        if 'team_name' not in session:
            return jsonify({"error": "User not logged in"}), 401

        team_name = session['team_name']

        # Fetch user profile data from the database
        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute('SELECT team_name, score, flags_submitted FROM teams WHERE team_name = %s', (team_name,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result:
            team_name, score, flags_submitted = result
            return jsonify({
                "team_name": team_name,
                "score": score,
                "flags_submitted": flags_submitted.split(',')
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception:
        return jsonify({"error": "Failed to get user profile"}), 500


@app.route('/api/get/user/rank', methods=['GET'])
@rate_limit(limit=100)
def get_team_rank():
    try:
        if 'team_name' not in session:
            return jsonify({"error": "User not logged in"}), 401

        team_name = session['team_name']

        # Fetch the team's score and rank from the database
        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute("""
            SELECT team_name, score 
            FROM teams 
            ORDER BY score DESC
        """)
        teams = cursor.fetchall()
        cursor.close()
        conn.close()

        # Calculate the rank of the logged-in team
        rank = next((i + 1 for i, (name, score) in enumerate(teams) if name == team_name), None)

        if rank:
            # Find the score of the next team to compare
            next_team_score = teams[rank] if rank < len(teams) else None
            return jsonify({"rank": rank, "next_team_score": next_team_score}), 200
        else:
            return jsonify({"error": "Team not found"}), 404
    except Exception:
        return jsonify({"error": "Failed to get team rank"}), 500


@app.route('/api/get/user/history', methods=['GET'])
@rate_limit(limit=100)
def get_team_history():
    try:
        if 'team_name' not in session:
            return jsonify({"error": "User not logged in"}), 401

        team_name = session['team_name']

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, flags_submitted, score 
                FROM team_history
                WHERE team_name = %s
                ORDER BY timestamp DESC
            """, (team_name,))

            history = cursor.fetchall()

            if not history:
                return jsonify({"message": "No history found for the team"}), 404

            history_data = [
                {
                    "timestamp": timestamp,
                    "flags_submitted": flags_submitted.split(",") if flags_submitted else [],
                    "score": score
                }
                for timestamp, flags_submitted, score in history
            ]

            return jsonify(history_data), 200

        except DatabaseError:
            return jsonify({"error": "Database error - Getting team history"}), 500
        except Exception:
            return jsonify({"error": "An error occurred - Getting team history"}), 500

        finally:
            cursor.close()
            conn.close()
    except Exception:
        return jsonify({"error": "Failed to get team history"}), 500


@app.route('/api/get/user/submissions', methods=['GET'])
@rate_limit(limit=100)
def get_submission_history():
    try:
        if 'team_name' not in session:
            return jsonify({"error": "User not logged in"}), 401

        team_name = session['team_name']

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            cursor.execute("""
                SELECT flag, timestamp 
                FROM flag_submissions
                WHERE team_name = %s
                ORDER BY timestamp DESC
            """, (team_name,))

            submissions = cursor.fetchall()

            if not submissions:
                return jsonify({"message": "No submissions found for the team"}), 404

            submission_data = [
                {"flag": flag, "timestamp": timestamp}
                for flag, timestamp in submissions
            ]

            return jsonify(submission_data), 200

        except DatabaseError:
            return jsonify({"error": "Database error - Get submission history"}), 500
        except Exception:
            return jsonify({"error": "An error occurred - Get submission history"}), 500

        finally:
            cursor.close()
            conn.close()
    except Exception:
        return jsonify({"error": "Failed to get submission history"}), 500


# -------------------------- Bank -----------------------------#

@app.route("/api/bank/add_user", methods=["POST"])
def add_user():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    data = request.json
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Insert the new user and get the UUID of the newly added user
                cur.execute("INSERT INTO credit_card (name, scraps) VALUES (%s, %s) RETURNING uuid",
                            (data["name"], data["scraps"]))
                new_uuid = cur.fetchone()[0]  # Get the first column of the first row (the UUID)
                conn.commit()

        # Return the success message with the newly created UUID
        return jsonify({
            "success": True,
            "message": "✅ User added successfully!",
            "uuid": str(new_uuid)
        })

    except Exception as e:
        print(f"Error adding user: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"❌ Error adding user: {str(e)}"
        })


@app.route("/api/bank/purchase", methods=["POST"])
def purchase():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    data = request.json
    try:
        scraps_amount = int(data["scraps"])
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE credit_card SET scraps = scraps - %s WHERE uuid = %s AND scraps >= %s RETURNING scraps",
                    (scraps_amount, data["uuid"], scraps_amount))

                if not cur.rowcount:
                    return jsonify({"message": "❌ Not enough scraps!"})

                # Include the amount in the reason for better tracking
                reason = f"{data['reason']} (-{scraps_amount} scraps)"

                cur.execute("INSERT INTO transaction_logs (uuid, name, reason) VALUES (%s, %s, %s)",
                            (data["uuid"], "Purchase", reason))
                conn.commit()
        return jsonify({"message": "💸 Purchase successful!"})
    except Exception as e:
        print(f"Error in purchase: {str(e)}")
        return jsonify({"message": f"❌ Error processing purchase: {str(e)}"})


@app.route("/api/bank/reimbursement", methods=["POST"])
def reimbursement():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    data = request.json
    try:
        scraps_amount = int(data["scraps"])
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE credit_card SET scraps = scraps + %s WHERE uuid = %s RETURNING scraps",
                            (scraps_amount, data["uuid"]))

                if not cur.rowcount:
                    return jsonify({"message": "❌ User not found!"})

                # Include the amount in the reason for better tracking
                reason = f"{data['reason']} (+{scraps_amount} scraps)"

                cur.execute("INSERT INTO transaction_logs (uuid, name, reason) VALUES (%s, %s, %s)",
                            (data["uuid"], "Reimbursement", reason))
                conn.commit()
        return jsonify({"message": "🔁 Reimbursement successful!"})
    except Exception as e:
        print(f"Error in reimbursement: {str(e)}")
        return jsonify({"message": f"❌ Error processing reimbursement: {str(e)}"})


@app.route("/api/bank/batch-operation", methods=["POST"])
def batch_operation():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Not authorized"}), 403

    data = request.json
    operation_type = data.get("operation_type")
    filter_query = data.get("filter", "")
    amount = data.get("amount", 0)
    reason = data.get("reason", "Batch Operation")

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                if operation_type == "add_scraps":
                    # Add scraps to filtered users
                    if filter_query:
                        cur.execute(
                            "UPDATE credit_card SET scraps = scraps + %s WHERE name ILIKE %s RETURNING uuid, name",
                            (amount, '%' + filter_query + '%'))
                    else:
                        cur.execute("UPDATE credit_card SET scraps = scraps + %s RETURNING uuid, name",
                                    (amount,))

                    affected_users = cur.fetchall()
                    affected_count = len(affected_users)

                    # Log the batch transaction for each user
                    for user in affected_users:
                        cur.execute("INSERT INTO transaction_logs (uuid, name, reason) VALUES (%s, %s, %s)",
                                    (user[0], "Batch Add", f"{reason} (+{amount} scraps)"))

                    message = f"✅ Added {amount} scraps to {affected_count} users!"

                elif operation_type == "remove_scraps":
                    # Remove scraps from filtered users (only if they have enough)
                    if filter_query:
                        cur.execute(
                            "UPDATE credit_card SET scraps = scraps - %s WHERE name ILIKE %s AND scraps >= %s RETURNING uuid, name",
                            (amount, '%' + filter_query + '%', amount))
                    else:
                        cur.execute(
                            "UPDATE credit_card SET scraps = scraps - %s WHERE scraps >= %s RETURNING uuid, name",
                            (amount, amount))

                    affected_users = cur.fetchall()
                    affected_count = len(affected_users)

                    # Log the batch transaction for each user
                    for user in affected_users:
                        cur.execute("INSERT INTO transaction_logs (uuid, name, reason) VALUES (%s, %s, %s)",
                                    (user[0], "Batch Remove", f"{reason} (-{amount} scraps)"))

                    message = f"✅ Removed {amount} scraps from {affected_count} users!"

                else:
                    return jsonify({"success": False, "message": "Invalid operation type"})

                conn.commit()

        return jsonify({
            "success": True,
            "message": message,
            "affected_count": affected_count
        })
    except Exception as e:
        print(f"Error in batch operation: {str(e)}")
        return jsonify({"success": False, "message": f"❌ Error in batch operation: {str(e)}"})


@app.route("/api/bank/export-users", methods=["GET"])
def export_users():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT uuid, name, scraps FROM credit_card ORDER BY name ASC")
                users = cur.fetchall()

        # Create CSV content
        csv_content = "UUID,Name,Scraps\n"
        for user in users:
            # Escape commas in names
            name = f'"{user[1]}"' if ',' in user[1] else user[1]
            csv_content += f"{user[0]},{name},{user[2]}\n"

        # Create response with CSV file
        response = Response(
            csv_content,
            mimetype="text/csv",
            headers={
                "Content-disposition": f"attachment; filename=users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
        return response
    except Exception as e:
        print(f"Error exporting users: {str(e)}")
        return f"Error exporting users: {str(e)}", 500


@app.route("/api/bank/export-transactions", methods=["GET"])
def export_transactions():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT uuid, name, reason, timestamp FROM transaction_logs ORDER BY timestamp DESC")
                transactions_ = cur.fetchall()

        # Create CSV content
        csv_content = "UUID,Type,Reason,Timestamp\n"
        for transaction in transactions_:
            # Escape commas in reason
            reason = f'"{transaction[2]}"' if ',' in transaction[2] else transaction[2]
            csv_content += f"{transaction[0]},{transaction[1]},{reason},{transaction[3]}\n"

        # Create response with CSV file
        response = Response(
            csv_content,
            mimetype="text/csv",
            headers={
                "Content-disposition": f"attachment; filename=transactions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
        return response
    except Exception as e:
        print(f"Error exporting transactions: {str(e)}")
        return f"Error exporting transactions: {str(e)}", 500


@app.route("/api/bank/user-transactions", methods=["GET"])
def user_transactions():
    uuid_ = request.args.get("uuid")

    if not uuid_:
        return jsonify({"success": False, "message": "UUID is required"}), 400

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Get user transactions
                cur.execute("""
                    SELECT name, reason, timestamp 
                    FROM transaction_logs 
                    WHERE uuid = %s 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """, (uuid_,))

                transactions_ = []
                for row in cur.fetchall():
                    transaction_type = row[0]
                    reason = row[1]
                    timestamp = row[2]

                    transactions_.append({
                        "type": transaction_type,
                        "reason": reason,
                        "timestamp": timestamp.isoformat()
                    })

                return jsonify({
                    "success": True,
                    "transactions": transactions_
                })

    except Exception as e:
        print(f"Error in user_transactions: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/bank/transaction-analytics", methods=["GET"])
def transaction_analytics():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Not authorized"}), 403

    hours = int(request.args.get("hours", 24))
    transaction_type = request.args.get("type", "all")

    try:
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Build query based on transaction type
                if transaction_type == "all":
                    query = """
                        SELECT 
                            DATE_TRUNC('hour', timestamp) as hour_timestamp,
                            name,
                            COUNT(*) as count
                        FROM transaction_logs
                        WHERE timestamp >= %s AND timestamp <= %s
                        GROUP BY DATE_TRUNC('hour', timestamp), name
                        ORDER BY hour_timestamp
                    """
                    cur.execute(query, (start_time, end_time))
                else:
                    query = """
                        SELECT 
                            DATE_TRUNC('hour', timestamp) as hour_timestamp,
                            name,
                            COUNT(*) as count
                        FROM transaction_logs
                        WHERE timestamp >= %s AND timestamp <= %s AND name = %s
                        GROUP BY DATE_TRUNC('hour', timestamp), name
                        ORDER BY hour_timestamp
                    """
                    cur.execute(query, (start_time, end_time, transaction_type))

                results = cur.fetchall()

        # Process results into a format suitable for charts
        hours_labels = []
        purchases = []
        reimbursements = []

        # Create a dictionary to store counts by hour
        hour_data = {}

        for row in results:
            hour_str = row[0].strftime("%Y-%m-%d %H:00")
            if hour_str not in hour_data:
                hour_data[hour_str] = {"Purchase": 0, "Reimbursement": 0}

            transaction_name = row[1]
            if transaction_name in ["Purchase", "Reimbursement"]:
                hour_data[hour_str][transaction_name] = row[2]

        # Fill in missing hours in the range
        current_hour = start_time.replace(minute=0, second=0, microsecond=0)
        while current_hour <= end_time:
            hour_str = current_hour.strftime("%Y-%m-%d %H:00")
            if hour_str not in hour_data:
                hour_data[hour_str] = {"Purchase": 0, "Reimbursement": 0}
            current_hour += timedelta(hours=1)

        # Sort hours and create final arrays
        sorted_hours = sorted(hour_data.keys())
        for hour in sorted_hours:
            hours_labels.append(hour)
            purchases.append(hour_data[hour]["Purchase"])
            reimbursements.append(hour_data[hour]["Reimbursement"])

        return jsonify({
            "success": True,
            "data": {
                "labels": hours_labels,
                "purchases": purchases,
                "reimbursements": reimbursements
            }
        })
    except Exception as e:
        print(f"Error in transaction_analytics: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/bank/dashboard-stats", methods=["GET"])
def dashboard_stats():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Not authorized"}), 403

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Get total users
                cur.execute("SELECT COUNT(*) FROM credit_card")
                total_users = cur.fetchone()[0]

                # Get total transactions
                cur.execute("SELECT COUNT(*) FROM transaction_logs")
                total_transactions = cur.fetchone()[0]

                # Get total scraps
                cur.execute("SELECT SUM(scraps) FROM credit_card")
                total_scraps = cur.fetchone()[0] or 0

        return jsonify({
            "success": True,
            "totalUsers": total_users,
            "totalTransactions": total_transactions,
            "totalScraps": total_scraps
        })
    except Exception as e:
        print(f"Error in dashboard_stats: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/bank/fraud-detection", methods=["GET"])
def fraud_detection():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Not authorized"}), 403

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Get time range (hours by default)
                hours = int(request.args.get("hours", 12))
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=hours)

                # 1. Detect frequent transactions from same UUID
                cur.execute("""
                    SELECT uuid, COUNT(*) as transaction_count
                    FROM transaction_logs
                    WHERE timestamp >= %s
                    GROUP BY uuid
                    HAVING COUNT(*) > 5
                    ORDER BY transaction_count DESC
                    LIMIT 10
                """, (start_time,))

                frequent_users = []
                for row in cur.fetchall():
                    # Get username
                    cur.execute("SELECT name FROM credit_card WHERE uuid = %s", (row[0],))
                    user_name = cur.fetchone()[0] if cur.rowcount > 0 else "Unknown"

                    frequent_users.append({
                        "uuid": row[0],
                        "name": user_name,
                        "transaction_count": row[1],
                        "risk_level": "high" if row[1] > 30 else "medium"
                    })

                # 2. Detect duplicate reasons (same reason used multiple times)
                cur.execute("""
                    SELECT uuid, reason, COUNT(*) as reason_count
                    FROM transaction_logs
                    WHERE timestamp >= %s AND name = 'Purchase'
                    GROUP BY uuid, reason
                    HAVING COUNT(*) > 2
                    ORDER BY reason_count DESC
                    LIMIT 10
                """, (start_time,))

                duplicate_reasons = []
                for row in cur.fetchall():
                    # Get username
                    cur.execute("SELECT name FROM credit_card WHERE uuid = %s", (row[0],))
                    user_name = cur.fetchone()[0] if cur.rowcount > 0 else "Unknown"

                    duplicate_reasons.append({
                        "uuid": row[0],
                        "name": user_name,
                        "reason": row[1],
                        "count": row[2],
                        "risk_level": "high" if row[2] > 5 else "medium"
                    })

                # 3. Detect unusual transaction patterns (purchase followed by reimbursement)
                cur.execute("""
                    WITH user_transactions AS (
                        SELECT 
                            uuid, 
                            name as transaction_type, 
                            timestamp,
                            LAG(name) OVER (PARTITION BY uuid ORDER BY timestamp) as prev_type,
                            LAG(timestamp) OVER (PARTITION BY uuid ORDER BY timestamp) as prev_timestamp
                        FROM transaction_logs
                        WHERE timestamp >= %s
                    )
                    SELECT 
                        uuid, 
                        COUNT(*) as pattern_count
                    FROM user_transactions
                    WHERE 
                        transaction_type = 'Reimbursement' AND 
                        prev_type = 'Purchase' AND
                        timestamp - prev_timestamp < interval '1 hour'
                    GROUP BY uuid
                    HAVING COUNT(*) > 2
                    ORDER BY pattern_count DESC
                    LIMIT 10
                """, (start_time,))

                unusual_patterns = []
                for row in cur.fetchall():
                    # Get username
                    cur.execute("SELECT name FROM credit_card WHERE uuid = %s", (row[0],))
                    user_name = cur.fetchone()[0] if cur.rowcount > 0 else "Unknown"

                    unusual_patterns.append({
                        "uuid": row[0],
                        "name": user_name,
                        "pattern": "Purchase-Reimbursement cycle",
                        "count": row[1],
                        "risk_level": "high" if row[1] > 3 else "medium"
                    })

                # 4. Detect unusual transaction times (outside normal hours 8am-8pm)
                unusual_times = []  # Empty list since we're removing this risk factor

                # 5. Detect sudden balance changes
                cur.execute(r"""
                    WITH balance_changes AS (
                        SELECT 
                            tl.uuid,
                            tl.name AS transaction_type,
                            CASE 
                                WHEN tl.name IN ('Purchase', 'Batch Remove') THEN -1
                                WHEN tl.name IN ('Reimbursement', 'Batch Add') THEN 1
                                ELSE 0
                            END AS direction,
                            tl.reason,
                            tl.timestamp
                        FROM transaction_logs tl
                        WHERE timestamp >= %s
                    )
                    SELECT 
                        uuid, 
                        COUNT(*) AS large_changes
                    FROM balance_changes
                    WHERE 
                        reason ~ '[-+]?\d{2,}'  -- Matches numbers 30 and above (positive or negative)
                        AND ABS(CAST((regexp_match(reason, '[-+]?\d{2,}'))[1] AS INTEGER)) >= 30
                    GROUP BY uuid
                    HAVING COUNT(*) > 2
                    ORDER BY large_changes DESC
                    LIMIT 10;
                """, (start_time,))

                large_changes = []
                for row in cur.fetchall():
                    # Get username
                    cur.execute("SELECT name FROM credit_card WHERE uuid = %s", (row[0],))
                    user_name = cur.fetchone()[0] if cur.rowcount > 0 else "Unknown"

                    large_changes.append({
                        "uuid": row[0],
                        "name": user_name,
                        "count": row[1],
                        "risk_level": "high" if row[1] > 4 else "medium"
                    })

                # Calculate overall risk score for each user
                all_uuids = set()
                for item in frequent_users + duplicate_reasons + unusual_patterns + unusual_times + large_changes:
                    all_uuids.add(item["uuid"])

                risk_scores = {}
                for uuid_ in all_uuids:
                    risk_score = 0

                    # Add scores from frequent transactions
                    for item in frequent_users:
                        if item["uuid"] == uuid_:
                            risk_score += 30 if item["risk_level"] == "high" else 15

                    # Add scores from duplicate reasons
                    for item in duplicate_reasons:
                        if item["uuid"] == uuid_:
                            risk_score += 25 if item["risk_level"] == "high" else 10

                    # Add scores from unusual patterns
                    for item in unusual_patterns:
                        if item["uuid"] == uuid_:
                            risk_score += 40 if item["risk_level"] == "high" else 20

                    # Add scores from large changes
                    for item in large_changes:
                        if item["uuid"] == uuid_:
                            risk_score += 35 if item["risk_level"] == "high" else 15

                    # Get username
                    cur.execute("SELECT name FROM credit_card WHERE uuid = %s", (uuid_,))
                    user_name = cur.fetchone()[0] if cur.rowcount > 0 else "Unknown"

                    risk_scores[uuid_] = {
                        "uuid": uuid_,
                        "name": user_name,
                        "score": risk_score,
                        "level": "high" if risk_score > 70 else "medium" if risk_score > 30 else "low"
                    }

                # Sort risk scores by score (descending)
                sorted_risk_scores = sorted(
                    risk_scores.values(),
                    key=lambda x: x["score"],
                    reverse=True
                )

                return jsonify({
                    "success": True,
                    "frequent_users": frequent_users,
                    "duplicate_reasons": duplicate_reasons,
                    "unusual_patterns": unusual_patterns,
                    "unusual_times": unusual_times,
                    "large_changes": large_changes,
                    "risk_scores": sorted_risk_scores[:10]  # Top 10 highest risk users
                })

    except Exception as e:
        print(f"Error in fraud_detection: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# ------------------------ END APIs ------------------------- #

# ------------------------ RESOURCES ------------------------ #


@app.route('/favicon.ico', methods=['GET'])
def get_favicon():
    try:
        return send_from_directory('static', 'static/favicon.png', mimetype='image/vnd.microsoft.icon'), 200
    except FileNotFoundError:
        return abort(404, description="Favicon not found")
    except Exception:
        return abort(500, description="Favicon fetching failed")


@app.route('/retry/<path:url_to_check>', methods=['POST'])
@rate_limit(limit=30)
def retry(url_to_check: str):
    try:
        # Validate and sanitize URL (remove protocol and www.)
        sanitized_url = re.sub(r'^(https?://)?(www\.)?', '', url_to_check)

        # Prevent SSRF by checking if the URL is in the whitelist
        if not any(re.fullmatch(pattern, sanitized_url) for pattern in allowed_urls()):
            return jsonify({
                "error_code": "URL_NOT_ALLOWED",
                "error_message": "URL not in whitelist. Contact the developer if this is unexpected.",
                "status_code": 406
            }), 406

        # Prevent retry loops
        if "retry" in url_to_check:
            return jsonify({
                "error_code": "INVALID_RETRY_CALL",
                "error_message": "You can't have a retry call within another retry call!",
                "status_code": 400
            }), 400

        # Attempt the request
        response = requests.get(url_to_check)

        # Return a structured JSON response
        return jsonify({
            "message": "Retry successful" if response.status_code == 200 else "Retry failed",
            "retried_url": url_to_check,
            "status_code": response.status_code,
            "response_text": response.text[:250]  # Limit response to prevent excessive logging
        }), response.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({
            "error_code": "CONNECTION_ERROR",
            "error_message": "Failed to establish a connection to the server.",
            "status_code": 503
        }), 503

    except requests.exceptions.Timeout:
        return jsonify({
            "error_code": "TIMEOUT_ERROR",
            "error_message": "The request timed out.",
            "status_code": 504
        }), 504

    except requests.RequestException as e:
        app.logger.error(f"Request error: {str(e)}")
        return jsonify({
            "error_code": "REQUEST_FAILED",
            "error_message": "An error occurred while processing your request.",
            "status_code": 500
        }), 500

    except Exception as e:
        app.logger.error(f"Unexpected server error: {str(e)}")
        return jsonify({
            "error_code": "SERVER_ERROR",
            "error_message": "An unexpected error occurred on the server.",
            "status_code": 500
        }), 500


def allowed_urls() -> List[str]:
    allowed = []
    for rule in app.url_map.iter_rules():
        url = "scrapyard-bounty.vercel.app" + str(rule)
        # Convert Flask URL rules to regex patterns
        url_pattern = re.sub(r'<[^>]+>', r'[^/]+', url)
        allowed.append(url_pattern)
    return allowed


def generate_receipt_image(user_email: str, item_name: str, item_price: float | int, item_image_url: str) -> BytesIO:
    receipt_id = str(uuid.uuid4())[:8]  # Shortened UUID
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Create an image for the receipt
    img = Image.new("RGB", (400, 400), "white")
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("arial.ttf", 20)  # Change if missing
    except IOError:
        font = ImageFont.load_default()

    # Receipt text
    text = f"Receipt ID: {receipt_id}\nUser: {user_email}\nItem: {item_name}\nPrice: {item_price} scraps\nDate: {timestamp}"
    draw.text((20, 20), text, fill="black", font=font)

    # Fetch the image from the URL
    try:
        response = requests.get(item_image_url)
        if response.status_code == 200:
            item_image = Image.open(BytesIO(response.content))  # Load image from the URL content
            item_image = item_image.resize((100, 100))  # Resize if necessary
            img.paste(item_image, (20, 150))  # Paste the image onto the receipt
        else:
            raise Exception(f"Failed to fetch image: {response.status_code}")
    except Exception:
        abort(500, description=f"Error loading item image")

    # Generate the image in memory
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return img_io


def extract_amount_from_reason(transaction_type: str, reason: str) -> int | None:
    """
    Here are the data types for the parameters and return value of the `extract_amount_from_reason` function:

    :param transaction_type: `str` (expected to be one of ["Purchase", "Batch Remove", "Reimbursement", "Batch Add"]).
    :param reason: `str` (a string containing the reason text, which may include numeric patterns).

    :return:
        `int`: If a valid amount is extracted from the `reason`.
        `None`: If no valid amount is found or an exception occurs.
    """
    try:
        # Log the input for debugging
        print(f"Extracting amount from: Type={transaction_type}, Reason={reason}")

        # Different patterns based on transaction type
        if transaction_type in ["Purchase", "Batch Remove"]:
            # Look for pattern like "(-X scraps)" or just numbers
            minus_pattern = r'$$-(\d+)\s*scraps$$'
            minus_match = re.search(minus_pattern, reason)
            if minus_match:
                amount = int(minus_match.group(1))
                print(f"Found amount with minus pattern: {amount}")
                return amount

            # Try another pattern like "- X scraps"
            alt_minus_pattern = r'-\s*(\d+)\s*scraps'
            alt_minus_match = re.search(alt_minus_pattern, reason)
            if alt_minus_match:
                amount = int(alt_minus_match.group(1))
                print(f"Found amount with alt minus pattern: {amount}")
                return amount

        elif transaction_type in ["Reimbursement", "Batch Add"]:
            # Look for pattern like "(+X scraps)" or just numbers
            plus_pattern = r'$$\+(\d+)\s*scraps$$'
            plus_match = re.search(plus_pattern, reason)
            if plus_match:
                amount = int(plus_match.group(1))
                print(f"Found amount with plus pattern: {amount}")
                return amount

            # Try another pattern like "+ X scraps"
            alt_plus_pattern = r'\+\s*(\d+)\s*scraps'
            alt_plus_match = re.search(alt_plus_pattern, reason)
            if alt_plus_match:
                amount = int(alt_plus_match.group(1))
                print(f"Found amount with alt plus pattern: {amount}")
                return amount

        # If specific patterns fail, try to find any number in the reason
        numbers = re.findall(r'\d+', reason)
        if numbers:
            amount = int(numbers[0])
            print(f"Found amount with generic number pattern: {amount}")
            return amount

        # If no amount found, log it and return default
        print(f"No amount found in reason: {reason}")
        return None
    except Exception as e:
        print(f"Error extracting amount: {str(e)}")
        return None


# ---------------------- ERROR HANDLERS --------------------- #

@app.errorhandler(400)
def bad_request(e):
    is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if is_browser_request:
        return render_template_string(ERROR_400_TEMPLATE, error_message=e.description), 403
    else:
        return jsonify({"error": e.description}), 403


@app.errorhandler(403)
def forbidden(e):
    is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if is_browser_request:
        return render_template_string(ERROR_403_TEMPLATE, error_message=e.description), 403
    else:
        return jsonify({"error": e.description}), 403


@app.errorhandler(404)
def page_not_found(e):
    is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if is_browser_request:
        return render_template_string(ERROR_404_TEMPLATE, error_message=e.description), 404
    else:
        return jsonify({"error": e.description}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if is_browser_request:
        return render_template_string(ERROR_405_TEMPLATE, error_message=e.description), 405
    else:
        return jsonify({"error": e.description}), 405


@app.errorhandler(429)
def too_many_requests(e):
    is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if is_browser_request:
        return render_template_string(ERROR_429_TEMPLATE, error_message=e.description), 429
    else:
        return jsonify({"error": e.description}), 429


@app.errorhandler(500)
def internal_server_error(e):
    is_browser_request = request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html"
    if is_browser_request:
        return render_template_string(ERROR_500_TEMPLATE, error_message=e.description), 500
    else:
        return jsonify({"error": e.description}), 500


# -------------------------- PAGES -------------------------- #

@app.route('/')
def home():
    if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
        return redirect(url_for('signin'))
    if 'start_time' not in session:
        session['start_time'] = time.time()
    return render_template_string(HOME_TEMPLATE), 200


@app.route('/admin')
@admin_required
def admin():
    return render_template_string(ADMIN_TEMPLATE), 200


@app.route('/admin/airtable')
@admin_required
def airtable():
    airtable_url = os.getenv("AIR_TABLE_LINK_SECRET")
    if not airtable_url:
        abort(400, description="Missing Environment Variable for AIRTABLE")
    return render_template_string(AIR_TABLE_TEMPLATE, airtable_url=airtable_url), 200


@app.route('/admin/shop')
@admin_required
def volunteer():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    # Perform a join to fetch item details alongside receipts
    cur.execute('''
        SELECT receipt.id, receipt.user_email, receipt.status, item.name, item.price
        FROM receipt
        JOIN item ON receipt.item_id = item.id
    ''')
    receipts = cur.fetchall()
    cur.close()
    conn.close()
    return render_template_string(ADMIN_RECEIPTS_TEMPLATE, receipts=receipts), 200


@app.route('/transactions', methods=['GET'])
def transactions():
    try:
        response = requests.get('https://hcb.hackclub.com/api/v3/organizations/scrapyard-sharjah/transactions')
        if response.status_code != 200:
            return abort(response.status_code, description="Transactions API failed (External -> HCB)")
        transaction_data = response.json()

        # Modify the transaction data to convert cents to dollars
        for transaction in transaction_data:
            if 'amount_cents' in transaction:
                transaction['amount_dollars'] = transaction['amount_cents'] / 100
                del transaction['amount_cents']  # Optionally remove 'amount_cents'

        return render_template_string(TRANSACTIONS_TEMPLATE, transactions=transaction_data), 200
    except Exception:
        return abort(500, description="Transactions")


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        team_name = request.form.get('team_name')
        password = request.form.get('password')
        if not team_name or not password:
            return render_template_string(SIGNIN_TEMPLATE, error="Team name and password are required."), 400

        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute('SELECT password, ip_address FROM teams WHERE team_name = %s', (team_name,))
        result = cursor.fetchone()

        if result:
            stored_password, stored_ip = result
            if check_password_hash(stored_password, password):
                if stored_ip and stored_ip != request.remote_addr and team_name != 'ADMIN':
                    return render_template_string(SIGNIN_TEMPLATE,
                                                  error="Account is already in use from another device, only 1 account per device (Uses IP tracking) - To fix, please contact ADMIN"), 409
                session['team_name'] = team_name
                cursor.execute('UPDATE teams SET ip_address = %s WHERE team_name = %s',
                               (request.remote_addr, team_name))
            else:
                return render_template_string(SIGNIN_TEMPLATE, error="Invalid password."), 401
        else:
            hashed_password = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO teams (team_name, password, ip_address, flags_submitted) VALUES (%s, %s, %s, %s)',
                (team_name, hashed_password, request.remote_addr, ''))
            session['team_name'] = team_name

        conn.commit()
        cursor.close()
        conn.close()

        resp = make_response(redirect(url_for('home')))
        resp.set_cookie('team_name', team_name, secure=True, samesite='Strict')
        return resp
    return render_template_string(SIGNIN_TEMPLATE), 200


@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
        return redirect(url_for('signin'))
    points = 0
    if request.method == 'POST':
        flag = request.form.get('flag')
        team_name = session.get('team_name')
        if not team_name:
            return redirect(url_for('signin'))

        if flag in [FLAG_1, FLAG_2, FLAG_3, FLAG_4, FLAG_5]:
            flag_scores = {
                FLAG_1: FLAG_1_SCORE,
                FLAG_2: FLAG_2_SCORE,
                FLAG_3: FLAG_3_SCORE,
                FLAG_4: FLAG_4_SCORE,
                FLAG_5: FLAG_5_SCORE
            }
            points = round(flag_scores[flag], 2)

        conn = get_db_connection()

        cursor = conn.cursor()
        cursor.execute('SELECT flags_submitted FROM teams WHERE team_name = %s', (team_name,))
        result = cursor.fetchone()
        flags_submitted = result[0].split(',') if result else []

        if flag in flags_submitted:
            return render_template_string(SUBMIT_TEMPLATE, error="Flag already submitted."), 406

        if flag in [FLAG_1, FLAG_2, FLAG_3, FLAG_4, FLAG_5]:
            flags_submitted.append(flag)
            cursor.execute('UPDATE teams SET score = score + %s, flags_submitted = %s WHERE team_name = %s',
                           (round(points, 2), ','.join(flags_submitted), team_name))
            conn.commit()
            cursor.close()
            conn.close()
            return render_template_string(SUBMIT_TEMPLATE, success=True, points=round(points, 2)), 200
        else:
            return render_template_string(SUBMIT_TEMPLATE, error="Invalid flag."), 400
    return render_template_string(SUBMIT_TEMPLATE), 200


@app.route('/leaderboard')
def leaderboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT team_name, score FROM teams ORDER BY score DESC')
    teams = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template_string(LEADERBOARD_TEMPLATE, teams=teams), 200


@app.route('/shop')
def shop():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM item;')
    items = cur.fetchall()
    cur.close()
    conn.close()
    return render_template_string(STORE_TEMPLATE, items=items), 200


@app.route('/shop/modify_stock', methods=['GET'])
@admin_required
def modify_stock():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM item;')
    items = cur.fetchall()
    cur.close()
    conn.close()
    return render_template_string(MODIFY_STOCKS_TEMPLATE, items=items), 200


@app.route('/shop/add_item', methods=['GET', 'POST'])
@admin_required
def add_item():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        image = request.form.get('image')
        description = request.form.get('description')
        stock = request.form.get('stock')

        if not name or not price or not image or not stock:
            flash("All fields except description are required!", "error")
            return redirect(url_for('add_item'))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO item (name, price, image, description, stock) VALUES (%s, %s, %s, %s, %s);',
                    (name, float(price), image, description, int(stock)))
        conn.commit()
        cur.close()
        conn.close()

        flash("Item added successfully!", "error")
        return redirect(url_for('shop'))

    return render_template_string(ADD_ITEM_TEMPLATE), 200


@app.route('/shop/missions')
def missions():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM missions;')
    mission = cur.fetchall()
    cur.close()
    conn.close()
    return render_template_string(MISSIONS_TEMPLATE, missions=mission), 200


@app.route('/model-answer/<int:answer_id>')
def get_model_answer(answer_id):
    if 1 <= answer_id <= 5:
        try:
            return render_template_string(MODEL_ANSWERS[answer_id - 1])
        except Exception:
            abort(500, description="Model answer fetching failed")
    else:
        abort(404, description="Invalid answer ID, Only 1-5 are available")


@app.route("/bank", methods=["GET"])
def home():
    uuid_ = request.args.get("uuid")  # Get the UUID from query parameters

    if session.get("logged_in"):
        if uuid_:
            return redirect(f"/admin?uuid={uuid_}")
        return redirect(f"/admin")
    if uuid_:
        try:
            # Convert string to UUID object for validation
            uuid_obj = uid.UUID(uuid_)
            # Convert back to string for database query
            uuid_str = str(uuid_obj)
        except ValueError:
            # Return a proper error page for invalid UUID format
            return render_template(
                "error.html",
                icon="fa-exclamation-triangle",
                title="Invalid UUID Format",
                message="The UUID you entered is not in a valid format.",
                error_details="Please check the UUID and try again. A valid UUID should look like: 123e4567-e89b-12d3-a456-426614174000",
                show_retry=True
            ), 400

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT name, scraps FROM credit_card WHERE uuid = %s", (uuid_str,))
                    user = cur.fetchone()

            if user:
                return render_template("balance.html", name=user[0], scraps=user[1], uuid=uuid_str)
            else:
                # Return a proper error page for user not found
                return render_template(
                    "error.html",
                    icon="fa-user-slash",
                    title="User Not Found",
                    message="We couldn't find a user with the provided UUID.",
                    error_details="Please check if you entered the correct UUID or contact an administrator for assistance.",
                    show_retry=True
                ), 404
        except Exception as e:
            print(f"Error in home route: {str(e)}")
            return render_template(
                "error.html",
                icon="fa-exclamation-circle",
                title="Server Error",
                message="An error occurred while processing your request.",
                error_details=f"Error details: {str(e)}",
                show_retry=True
            ), 500

    return render_template("index.html")


@app.route("/admin/bank", methods=["GET"])
def admin_panel():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("admin.html")


@app.route("/bank/logs", methods=["GET", "POST"])
def admin_logs():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    search_query = request.form.get("search", "")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT uuid, name, reason, timestamp FROM transaction_logs WHERE name ILIKE %s ORDER BY timestamp DESC",
                    ('%' + search_query + '%',))
                logs = cur.fetchall()
        return render_template("logs.html", logs=logs, search_query=search_query)
    except Exception as e:
        print(f"Error in admin_logs: {str(e)}")
        return render_template(
            "error.html",
            icon="fa-exclamation-circle",
            title="Server Error",
            message="An error occurred while retrieving logs.",
            error_details=f"Error details: {str(e)}",
            show_retry=True
        ), 500


@app.route("/bank/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check the credentials
        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("admin_panel"))
        else:
            error = "Invalid username or password. Please try again."

    return render_template("login.html", error=error)


@app.route("/bank/logout", methods=["GET"])
def logout():
    # Clear the session
    session.clear()
    # Redirect to home page
    return redirect(url_for("home"))


@app.route("/bank/users", methods=["GET", "POST"])
def admin_users():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    search_query = request.form.get("search", "")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT uuid, name, scraps FROM credit_card WHERE name ILIKE %s ORDER BY name ASC",
                            ('%' + search_query + '%',))
                users = cur.fetchall()
        return render_template("users.html", users=users, search_query=search_query)
    except Exception as e:
        print(f"Error in admin_users: {str(e)}")
        return render_template(
            "error.html",
            icon="fa-exclamation-circle",
            title="Server Error",
            message="An error occurred while retrieving users.",
            error_details=f"Error details: {str(e)}",
            show_retry=True
        ), 500


# ------------------------ CHALLENGES ------------------------ #


# Challenge 1: Cryptography
@app.route('/cryptography', methods=['GET', 'POST'])
def cryptography():
    try:
        if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
            return redirect(url_for('signin'))
        description = "Decrypt a ROT13-encrypted message to uncover the flag."
        encrypted_message = "GUVF_VF_GUR_SYNT"

        if request.method == 'POST':
            user_input = request.form.get('decrypted')
            if user_input == "THIS_IS_THE_FLAG":
                return render_template_string(COMP_TEMPLATE, challenge=1, success=True, flag=FLAG_1,
                                              description=description, encrypted=encrypted_message), 200
            else:
                return render_template_string(COMP_TEMPLATE, challenge=1, error="Incorrect decryption.",
                                              description=description, encrypted=encrypted_message), 400

        return render_template_string(COMP_TEMPLATE, challenge=1, description=description,
                                      encrypted=encrypted_message), 200
    except Exception:
        abort(500, description="Challenge 1")


# Challenge 2: Web Exploitation
@app.route('/weblogin', methods=['GET', 'POST'])
def weblogin():
    try:
        if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
            return redirect(url_for('signin'))
        description = "Bypass the login page using SQL Injection to discover the flag."
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')

            conn = get_db_connection()
            cursor = conn.cursor()
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            cursor.execute(query)
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user:
                return render_template_string(COMP_TEMPLATE, challenge=2, success=True, flag=FLAG_2,
                                              description=description), 200
            else:
                return render_template_string(COMP_TEMPLATE, challenge=2, error="Invalid credentials.",
                                              description=description), 400

        return render_template_string(COMP_TEMPLATE, challenge=2, description=description), 200
    except Exception:
        abort(500, description="Challenge 2")


# Challenge 3: Reverse Engineering
@app.route('/binary', methods=['GET', 'POST'])
def binary():
    try:
        if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
            return redirect(url_for('signin'))
        description = "Analyze a binary file to find a hardcoded key (Format KEY{xxxx}). First you must find the correct BIN file, then the correct line number."
        if request.method == 'POST':
            uploaded_file = request.files['file']
            if not uploaded_file:
                return render_template_string(COMP_TEMPLATE, challenge=3,
                                              error="No file uploaded",
                                              description=description), 400
            if not uploaded_file.filename.endswith('.bin'):
                return render_template_string(COMP_TEMPLATE, challenge=3,
                                              error="Invalid file type",
                                              description=description), 400
            binary_data = uploaded_file.read()
            if KEY.encode() in binary_data and request.form.get('line', '') == '136':  # File C3_79.bin
                return render_template_string(COMP_TEMPLATE, challenge=3, success=True, flag=FLAG_3,
                                              description=description), 200
            else:
                return render_template_string(COMP_TEMPLATE, challenge=3,
                                              error="Flag not found in the binary or Line number incorrect.",
                                              description=description), 400

        return render_template_string(COMP_TEMPLATE, challenge=3, description=description), 200
    except Exception:
        abort(500, description="Challenge 3")


# Challenge 4: Forensics
@app.route('/forensics', methods=['GET', 'POST'])
def forensics():
    try:
        if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
            return redirect(url_for('signin'))
        description = "Analyze a PCAP file in [Wireshark] to find a hidden key (Format KEY{xxxx}). First you must find the correct PCAP file, then the correct line number."
        if request.method == 'POST':
            uploaded_file = request.files['file']
            if not uploaded_file:
                return render_template_string(COMP_TEMPLATE, challenge=4,
                                              error="No file uploaded",
                                              description=description), 400

            if not uploaded_file.filename.endswith('.pcap'):
                return render_template_string(COMP_TEMPLATE, challenge=4,
                                              error="Invalid file type",
                                              description=description), 400

            try:
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(uploaded_file.read())
                    temp_file_path = temp_file.name
            finally:
                packets = rdpcap(temp_file_path)
                os.remove(temp_file_path)  # Clean up the temporary file

            for packet in packets:
                if (packet.haslayer('Raw') and KEY in packet['Raw'].load.decode(
                        'utf-8', errors='ignore')
                        and request.form.get('line', '') == '452'):  # File C4_68.pcap
                    return render_template_string(COMP_TEMPLATE, challenge=4, success=True, flag=FLAG_4,
                                                  description=description), 200
            return render_template_string(COMP_TEMPLATE, challenge=4,
                                          error="Flag not found in PCAP or Line number incorrect.",
                                          description=description), 400

        return render_template_string(COMP_TEMPLATE, challenge=4, description=description), 200
    except Exception:
        abort(500, description="Challenge 4")


# Challenge 5: Steganography
@app.route('/steganography', methods=['GET', 'POST'])
def steganography():
    if 'team_name' not in session or request.cookies.get('team_name') != session['team_name']:
        return redirect(url_for('signin'))
    description = "Extract hidden data (Format KEY{xxxx}) from an image file using a automated script. First you must find the correct JPEG file, then the correct line number."
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if not uploaded_file:
            return render_template_string(COMP_TEMPLATE, challenge=5,
                                          error="No file uploaded",
                                          description=description), 400

        if not uploaded_file.filename.endswith('.jpeg'):
            return render_template_string(COMP_TEMPLATE, challenge=5,
                                          error="Invalid file type",
                                          description=description), 400

        try:
            # Read the entire file content
            file_content = uploaded_file.read()
            flag = KEY.encode()
            if flag in file_content and request.form.get('line', '') == '206':  # File C5_51.jpeg
                return render_template_string(COMP_TEMPLATE, challenge=5, success=True, flag=FLAG_5,
                                              description=description), 200
            else:
                return render_template_string(COMP_TEMPLATE, challenge=5,
                                              error="Hidden flag not found or Line number incorrect.",
                                              description=description), 400
        except Exception:
            abort(500, description="Challenge 5")

    return render_template_string(COMP_TEMPLATE, challenge=5, description=description)


# --------------------------- HTML --------------------------- #

try:
    # HTML template for home page
    with open("src/html/home.html", "r") as f:
        HOME_TEMPLATE = f.read()

    # HTML template for challenges
    with open("src/html/competition.html", "r") as f:
        COMP_TEMPLATE = f.read()

    # HTML templates for sign-in, submit and leaderboard pages
    with open("src/html/signin.html", "r") as f:
        SIGNIN_TEMPLATE = f.read()

    with open("src/html/submit.html", "r", encoding="UTF-8") as f:
        SUBMIT_TEMPLATE = f.read()

    with open("src/html/leaderboard.html", "r") as f:
        LEADERBOARD_TEMPLATE = f.read()

    # HTML template for admin page
    with open("src/html/admin.html", "r") as f:
        ADMIN_TEMPLATE = f.read()

    with open("src/html/airtable.html", "r") as f:
        AIR_TABLE_TEMPLATE = f.read()

    # HTML template for transactions page
    with open("src/html/transactions.html", "r") as f:
        TRANSACTIONS_TEMPLATE = f.read()

    # Error templates
    with open("src/html/error/400.html", "r") as f:
        ERROR_400_TEMPLATE = f.read()

    with open("src/html/error/403.html", "r") as f:
        ERROR_403_TEMPLATE = f.read()

    with open("src/html/error/404.html", "r") as f:
        ERROR_404_TEMPLATE = f.read()

    with open("src/html/error/405.html", "r") as f:
        ERROR_405_TEMPLATE = f.read()

    with open("src/html/error/429.html", "r") as f:
        ERROR_429_TEMPLATE = f.read()

    with open("src/html/error/500.html", "r") as f:
        ERROR_500_TEMPLATE = f.read()

    # Shop templates
    with open("src/html/add_item.html", "r") as f:
        ADD_ITEM_TEMPLATE = f.read()

    with open("src/html/add_mission.html", "r") as f:
        ADD_MISSION_TEMPLATE = f.read()

    with open("src/html/admin.receipts.html", "r") as f:
        ADMIN_RECEIPTS_TEMPLATE = f.read()

    with open("src/html/missions.html", "r") as f:
        MISSIONS_TEMPLATE = f.read()

    with open("src/html/modify_stock.html", "r") as f:
        MODIFY_STOCKS_TEMPLATE = f.read()

    with open("src/html/store.html", "r") as f:
        STORE_TEMPLATE = f.read()

    # Model Answers templates
    with open("src/html/model_answers/1.html", "r") as f:
        MODEL_ANSWER_1_TEMPLATE = f.read()

    with open("src/html/model_answers/2.html", "r") as f:
        MODEL_ANSWER_2_TEMPLATE = f.read()

    with open("src/html/model_answers/3.html", "r") as f:
        MODEL_ANSWER_3_TEMPLATE = f.read()

    with open("src/html/model_answers/4.html", "r") as f:
        MODEL_ANSWER_4_TEMPLATE = f.read()

    with open("src/html/model_answers/5.html", "r") as f:
        MODEL_ANSWER_5_TEMPLATE = f.read()

    MODEL_ANSWERS = [MODEL_ANSWER_1_TEMPLATE, MODEL_ANSWER_2_TEMPLATE, MODEL_ANSWER_3_TEMPLATE, MODEL_ANSWER_4_TEMPLATE,
                     MODEL_ANSWER_5_TEMPLATE]
except FileNotFoundError:
    abort(404, description="HTML Templates not found")
except Exception:
    abort(500, description="HTML Templates failed to load")

# ------------------------- MAIN APP ------------------------- #

if __name__ == "__main__":
    print("Starting Flask application...")
    try:
        # Test database connection on startup
        with get_db_connection() as conn_main:
            with conn_main.cursor() as cur_main:
                cur_main.execute("SELECT 1")
        create_tables()
        print("Database connection successful")

        # Run with Waitress
        serve(app, host="0.0.0.0", port=5000)
    except Exception as err:
        print(f"Failed to start application: {str(err)}")
        sys.exit(1)

# --------------------------- END ---------------------------- #
