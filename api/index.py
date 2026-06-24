import os
import json
import sqlite3
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = DATA_DIR / "config.json"

# Vercel serverless has a read-only filesystem except for /tmp
IS_VERCEL = "VERCEL" in os.environ
if IS_VERCEL:
    DB_PATH = Path("/tmp/ansh9boss_global.db")
else:
    DB_PATH = DATA_DIR / "ansh9boss_global.db"

# Hybrid database engine (PostgreSQL for cloud, SQLite for local fallback)
DATABASE_URL = os.environ.get("DATABASE_URL")
USING_POSTGRES = DATABASE_URL is not None

# Configure relative template and static paths for Vercel
app = Flask(__name__, template_folder='../web/templates', static_folder='../web/static')
app.secret_key = "ansh9boss_super_secret_session_key_2026"

ADMIN_PASSCODE = os.environ.get("ANSH9BOSS_ADMIN_PASSCODE", "ansh9boss2026")

def get_db_connection():
    """Establish a connection to SQLite or PostgreSQL."""
    if USING_POSTGRES:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    else:
        # SQLite
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

def format_query(query):
    """Format SQL query placeholders based on database engine."""
    if USING_POSTGRES:
        return query.replace("?", "%s")
    return query

def fetch_all(query, params=()):
    """Helper to query all database rows."""
    conn = get_db_connection()
    cur = conn.cursor()
    formatted = format_query(query)
    cur.execute(formatted, params)
    
    result = []
    if cur.description:
        columns = [desc[0] for desc in cur.description]
        rows = cur.fetchall()
        result = [dict(zip(columns, row)) for row in rows]
    else:
        conn.commit()
        
    cur.close()
    conn.close()
    return result

def fetch_one(query, params=()):
    """Helper to query a single database row."""
    res = fetch_all(query, params)
    return res[0] if res else None

def execute_query(query, params=()):
    """Helper to execute INSERT/UPDATE queries."""
    conn = get_db_connection()
    cur = conn.cursor()
    formatted = format_query(query)
    cur.execute(formatted, params)
    conn.commit()
    
    lastrowid = None
    if not USING_POSTGRES:
        lastrowid = cur.lastrowid
        
    cur.close()
    conn.close()
    return lastrowid

def load_config():
    """Load configuration from database with config.json / hardcoded fallback."""
    default_config = {
        "version": "1.0.0",
        "known_cheats": [
            "wurst", "meteor", "sigma", "impact", "aristois", "future", "liquidbounce", 
            "wolfram", "inertia", "ares", "sentry", "entropy", "reflex", "bleach", 
            "ancientaura", "killaura", "huzuni", "nodus", "vape", "badlion", "mathax",
            "kamiblue", "kami", "salhack", "rusherhack"
        ],
        "known_packages": [
            "meteorclient", "wurst", "sigma", "future", "liquidbounce", "mathax", 
            "ares", "wolfram", "kamiblue", "salhack", "rusherhack", "aristois", "huzuni", "vape"
        ],
        "cheat_strings": [
            "aimbot", "killaura", "esp", "wallhack", "xray", "freecam", 
            "nofall", "scaffold", "triggerbot", "autoclick", "baritone", "pathfind", 
            "autototem", "fastplace", "criticals", "antiknockback", "nuker", 
            "jesus", "automine", "cheatengine"
        ]
    }
    
    # Try reading from config.json first if it exists, to seed defaults if custom
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                file_defaults = json.load(f)
                for k, v in file_defaults.items():
                    default_config[k] = v
        except Exception:
            pass

    # Now load from database
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if table exists
        if USING_POSTGRES:
            cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'config')")
            table_exists = cur.fetchone()[0]
        else:
            cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='config'")
            table_exists = cur.fetchone()[0] > 0
            
        if not table_exists:
            cur.close()
            conn.close()
            return default_config
            
        formatted = format_query("SELECT key, value FROM config")
        cur.execute(formatted)
        rows = cur.fetchall()
        
        if not rows:
            # Seed the database
            for k, v in default_config.items():
                if USING_POSTGRES:
                    cur.execute("INSERT INTO config (key, value) VALUES (%s, %s)", (k, json.dumps(v)))
                else:
                    cur.execute("INSERT INTO config (key, value) VALUES (?, ?)", (k, json.dumps(v)))
            conn.commit()
            cur.close()
            conn.close()
            return default_config
            
        config_data = {}
        for row in rows:
            # SQLite row is sqlite3.Row if row_factory is set, Postgres row is tuple or dict depending on setup
            if hasattr(row, 'keys') or isinstance(row, dict):
                config_data[row["key"]] = json.loads(row["value"])
            else:
                config_data[row[0]] = json.loads(row[1])
                
        cur.close()
        conn.close()
        return config_data
    except Exception as e:
        print(f"Error loading configuration from database: {e}")
        return default_config

def save_config(config_data):
    """Save configuration to database (and fallback local file)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if table exists, create if not
        if USING_POSTGRES:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key VARCHAR(100) PRIMARY KEY,
                value TEXT
            )
            """)
            conn.commit()
        else:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """)
            conn.commit()
            
        for k, v in config_data.items():
            if USING_POSTGRES:
                cur.execute(
                    "INSERT INTO config (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    (k, json.dumps(v))
                )
            else:
                cur.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (k, json.dumps(v)))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error saving config to database: {e}")
        
    if not IS_VERCEL:
        try:
            DATA_DIR.mkdir(exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(config_data, f, indent=2)
        except Exception:
            pass


def init_db():
    """Ensure database tables exist on SQLite or PostgreSQL."""
    if not USING_POSTGRES:
        DATA_DIR.mkdir(exist_ok=True)
        if IS_VERCEL:
            DB_PATH.parent.mkdir(exist_ok=True)
            
    conn = get_db_connection()
    cur = conn.cursor()
    
    if USING_POSTGRES:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_files INTEGER,
            flagged_files INTEGER,
            highest_risk VARCHAR(50),
            platform VARCHAR(50)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER,
            file_name VARCHAR(255),
            file_path TEXT,
            risk_level VARCHAR(50),
            detection_layer TEXT,
            matched_details TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS verified_hashes (
            hash VARCHAR(100) PRIMARY KEY,
            clean BOOLEAN,
            source VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key VARCHAR(100) PRIMARY KEY,
            value TEXT
        )
        """)
    else:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_files INTEGER,
            flagged_files INTEGER,
            highest_risk TEXT,
            platform TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            file_name TEXT,
            file_path TEXT,
            risk_level TEXT,
            detection_layer TEXT,
            matched_details TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS verified_hashes (
            hash TEXT PRIMARY KEY,
            clean INTEGER,
            source TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)
        
    conn.commit()
    cur.close()
    conn.close()

def get_stats():
    """Query statistics from SQLite or PostgreSQL."""
    init_db()
    stats = {
        "total_scans": 0,
        "total_files_scanned": 0,
        "total_flagged_files": 0,
        "detection_layers": {},
        "common_threats": [],
        "recent_scans": []
    }
    
    try:
        # 1. Total Scans Summary
        row = fetch_one("SELECT COUNT(*) as total_scans, SUM(total_files) as total_files, SUM(flagged_files) as total_flagged FROM scans")
        if row and row["total_scans"] > 0:
            stats["total_scans"] = row["total_scans"]
            stats["total_files_scanned"] = row["total_files"] or 0
            stats["total_flagged_files"] = row["total_flagged"] or 0
            
        # 2. Layers Breakdown
        layers_list = fetch_all("SELECT detection_layer, COUNT(*) as count FROM detections GROUP BY detection_layer")
        for r in layers_list:
            layer_name = r["detection_layer"] or "Unknown"
            stats["detection_layers"][layer_name] = r["count"]
            
        # 3. Common Threats
        stats["common_threats"] = fetch_all("SELECT file_name, risk_level, COUNT(*) as count FROM detections GROUP BY file_name, risk_level ORDER BY count DESC LIMIT 5")
        
        # 4. Recent Scans
        stats["recent_scans"] = fetch_all("SELECT id, timestamp, total_files, flagged_files, highest_risk, platform FROM scans ORDER BY timestamp DESC LIMIT 15")
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        
    return stats

@app.route("/download/ansh9boss.apk")
def download_apk():
    apk_path = BASE_DIR / "web" / "static" / "ansh9boss.apk"
    if not apk_path.exists():
        return render_template("apk_placeholder.html")
    from flask import send_from_directory
    return send_from_directory(os.path.join(app.root_path, '../web/static'), 'ansh9boss.apk', as_attachment=True)

@app.route("/")
def index():
    config = load_config()
    return render_template("index.html", version=config.get("version", "1.0.0"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin"))
        
    if request.method == "POST":
        passcode = request.form.get("passcode")
        if passcode == ADMIN_PASSCODE:
            session["admin_logged_in"] = True
            return redirect(url_for("admin"))
        else:
            flash("Invalid admin passcode! Please try again.", "error")
            
    return render_template("login.html")

@app.route("/admin")
def admin():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
        
    stats = get_stats()
    config = load_config()
    return render_template("admin.html", stats=stats, config=config)

@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("index"))

@app.route("/api/report_scan", methods=["POST"])
def report_scan():
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "message": "No payload received"}), 400
            
        platform = data.get("platform", "Unknown")
        total_files = data.get("total_files", 0)
        flagged_files = data.get("flagged_files", 0)
        highest_risk = data.get("highest_risk", "CLEAN")
        detections = data.get("detections", [])
        
        init_db()
        
        if USING_POSTGRES:
            res = fetch_one(
                "INSERT INTO scans (total_files, flagged_files, highest_risk, platform) VALUES (?, ?, ?, ?) RETURNING id",
                (total_files, flagged_files, highest_risk, platform)
            )
            scan_id = res["id"] if res else None
        else:
            scan_id = execute_query(
                "INSERT INTO scans (total_files, flagged_files, highest_risk, platform) VALUES (?, ?, ?, ?)",
                (total_files, flagged_files, highest_risk, platform)
            )
        
        for det in detections:
            execute_query(
                """INSERT INTO detections 
                   (scan_id, file_name, file_path, risk_level, detection_layer, matched_details) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    det.get("file_name"),
                    "Telemetry Upload (Anonymized)",
                    det.get("risk_level"),
                    det.get("detection_layer"),
                    ", ".join(det.get("matched_details")) if isinstance(det.get("matched_details"), list) else det.get("matched_details")
                )
            )
            
        return jsonify({"success": True, "message": "Global telemetry logged successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Telemetry processing error: {str(e)}"}), 500

@app.route("/api/live_feed")
def live_feed():
    try:
        init_db()
        # Query total counters
        stats_row = fetch_one("SELECT COUNT(*) as scans, SUM(total_files) as files, SUM(flagged_files) as flagged FROM scans")
        
        global_stats = {
            "total_scans": stats_row["scans"] if stats_row else 0,
            "total_files": stats_row["files"] if stats_row and stats_row["files"] else 0,
            "total_flagged": stats_row["flagged"] if stats_row and stats_row["flagged"] else 0
        }
        
        # Query latest 8 flagged detections
        recent_rows = fetch_all("""
            SELECT d.file_name, d.risk_level, d.detection_layer, s.platform, s.timestamp 
            FROM detections d
            JOIN scans s ON d.scan_id = s.id
            ORDER BY s.timestamp DESC LIMIT 8
        """)
        
        recent_detections = []
        for r in recent_rows:
            # Handle possible datetime parsing issues
            timestamp_str = str(r["timestamp"])
            recent_detections.append({
                "file_name": r["file_name"],
                "risk_level": r["risk_level"],
                "detection_layer": r["detection_layer"],
                "platform": r["platform"],
                "timestamp": timestamp_str
            })
            
        return jsonify({
            "success": True,
            "stats": global_stats,
            "recent": recent_detections
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/update_config", methods=["POST"])
def update_config():
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
        
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "message": "No data received"}), 400
            
        config = load_config()
        
        if "version" in data:
            config["version"] = data["version"].strip()
            
        if "known_cheats" in data:
            config["known_cheats"] = [x.strip().lower() for x in data["known_cheats"] if x.strip()]
            
        if "known_packages" in data:
            config["known_packages"] = [x.strip().lower() for x in data["known_packages"] if x.strip()]
            
        if "cheat_strings" in data:
            config["cheat_strings"] = [x.strip().lower() for x in data["cheat_strings"] if x.strip()]
            
        save_config(config)
        return jsonify({"success": True, "message": "Configuration updated successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route("/api/rules")
def get_rules():
    """Endpoint to return current known cheats, packages, and cheat strings configuration."""
    config = load_config()
    return jsonify({
        "version": config.get("version", "1.0.0"),
        "known_cheats": config.get("known_cheats", []),
        "known_packages": config.get("known_packages", []),
        "cheat_strings": config.get("cheat_strings", [])
    })

@app.route("/api/verify_hash")
def verify_hash():
    """Verify if a SHA-1 hash corresponds to a clean, known mod from Modrinth or local cache."""
    sha1 = request.args.get("hash", "").strip().lower()
    if not sha1 or len(sha1) != 40:
        return jsonify({"valid": False, "error": "Invalid SHA-1 hash"}), 400

    # 1. Check local cache
    try:
        cached = fetch_one("SELECT clean, source FROM verified_hashes WHERE hash = ?", (sha1,))
        if cached:
            return jsonify({
                "valid": True,
                "hash": sha1,
                "clean": bool(cached["clean"]),
                "source": cached["source"],
                "cached": True
            })
    except Exception as e:
        # DB may not be initialized yet or cache missing
        print(f"Cache read error: {e}")

    # 2. Query Modrinth API
    import urllib.request
    import urllib.error
    url = f"https://api.modrinth.com/v2/version_file/{sha1}?algorithm=sha1"
    
    clean_mod = False
    source = "Unverified"
    
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'ANSH9BOSS-Validator/1.0 (contact@ansh9boss.app)'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "id" in data:
                clean_mod = True
                source = "Modrinth Verified"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            clean_mod = False
            source = "Modrinth Unknown (Unverified)"
        else:
            return jsonify({"valid": False, "error": f"Cloud API error: {e.reason}"}), 502
    except Exception as e:
        return jsonify({"valid": False, "error": f"Lookup failed: {str(e)}"}), 500

    # 3. Save to cache
    try:
        execute_query(
            "INSERT INTO verified_hashes (hash, clean, source) VALUES (?, ?, ?)",
            (sha1, 1 if clean_mod else 0, source)
        )
    except Exception as e:
        print(f"Cache save error: {e}")

    return jsonify({
        "valid": True,
        "hash": sha1,
        "clean": clean_mod,
        "source": source,
        "cached": False
    })

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
