import os
import json
import struct
import zipfile
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = DATA_DIR / "config.json"

# Vercel serverless has a read-only filesystem except for /tmp
IS_VERCEL = "VERCEL" in os.environ
if IS_VERCEL:
    SCANS_FILE = Path("/tmp/scans.json")
    DETECTIONS_FILE = Path("/tmp/detections.json")
    HASHES_FILE = Path("/tmp/verified_hashes.json")
    CONFIG_FILE = Path("/tmp/config.json")
    CACHE_DIR = Path("/tmp/jar_cache")
else:
    SCANS_FILE = DATA_DIR / "scans.json"
    DETECTIONS_FILE = DATA_DIR / "detections.json"
    HASHES_FILE = DATA_DIR / "verified_hashes.json"
    CONFIG_FILE = CONFIG_PATH
    CACHE_DIR = DATA_DIR / "jar_cache"

# Configure relative template and static paths for Vercel
app = Flask(__name__, template_folder='../web/templates', static_folder='../web/static')
app.secret_key = "ansh9boss_super_secret_session_key_2026"

ADMIN_PASSCODE = os.environ.get("ANSH9BOSS_ADMIN_PASSCODE", "ansh9boss2026")

# Java .class disassembler engine
def disassemble_class(class_bytes):
    """
    Parses Java .class file bytes and disassembles it into structural information and JVM instructions.
    Simulates step-by-step progress logging (Phase 1, 2, 3, 4) for the UI console.
    """
    try:
        phases = []
        phases.append("Phase 1: Resolving Class File Headers & Constant Pool")
        
        if len(class_bytes) < 8:
            return {"success": False, "error": "Invalid class file size (too short)"}
        
        magic, minor, major = struct.unpack(">IHH", class_bytes[:8])
        if magic != 0xCAFEBABE:
            return {"success": False, "error": "Invalid class file header (magicCAFEBABE mismatch)"}
            
        phases.append(f"✓ Magic header verified. Java class major version: {major} (minor: {minor})")
        
        cp_count = struct.unpack(">H", class_bytes[8:10])[0]
        phases.append(f"✓ Constant pool size: {cp_count} entries")
        
        # Scan constant pool UTF8 entries
        cp_map = {}
        offset = 10
        idx = 1
        while idx < cp_count and offset < len(class_bytes):
            tag = class_bytes[offset]
            if tag == 1: # UTF-8
                length = struct.unpack(">H", class_bytes[offset+1:offset+3])[0]
                val = class_bytes[offset+3:offset+3+length].decode('utf-8', errors='ignore')
                cp_map[idx] = ("UTF8", val)
                offset += 3 + length
            elif tag in (7, 8, 16, 19, 20): # Class, String, MethodType, Module, Package
                val = struct.unpack(">H", class_bytes[offset+1:offset+3])[0]
                cp_map[idx] = ("REF", val)
                offset += 3
            elif tag in (3, 4, 9, 10, 11, 12, 18): # Integer, Float, Fieldref, Methodref, InterfaceMethodref, NameAndType, InvokeDynamic
                val1, val2 = struct.unpack(">HH", class_bytes[offset+1:offset+5])
                cp_map[idx] = ("REF2", (val1, val2))
                offset += 5
            elif tag in (5, 6): # Long, Double
                offset += 9
                idx += 1 # Longs and Doubles count as two constant pool indices
            elif tag in (15,): # MethodHandle
                offset += 4
            elif tag in (17, 18): # Dynamic
                offset += 5
            else:
                offset += 1 # Unknown tag, skip gracefully
            idx += 1
            
        phases.append("Phase 2: Analyzing Class Attribute Tables")
        
        if offset + 6 > len(class_bytes):
            return {"success": False, "error": "Class file corrupted or truncated"}
            
        access_flags, this_class_idx, super_class_idx = struct.unpack(">HHH", class_bytes[offset:offset+6])
        offset += 6
        
        def get_cp_utf8(cp_idx):
            if cp_idx in cp_map and cp_map[cp_idx][0] == "UTF8":
                return cp_map[cp_idx][1]
            return f"UTF8#{cp_idx}"
            
        def resolve_classname(cls_idx):
            if cls_idx in cp_map and cp_map[cls_idx][0] == "REF":
                name_idx = cp_map[cls_idx][1]
                return get_cp_utf8(name_idx)
            return f"Class#{cls_idx}"
            
        class_name = resolve_classname(this_class_idx)
        phases.append(f"✓ Resolved class: {class_name}")
        
        # Interfaces
        interfaces_count = struct.unpack(">H", class_bytes[offset:offset+2])[0]
        offset += 2 + 2 * interfaces_count
        
        # Skip Fields
        fields_count = struct.unpack(">H", class_bytes[offset:offset+2])[0]
        offset += 2
        for _ in range(fields_count):
            if offset + 8 > len(class_bytes):
                break
            f_flags, f_name_idx, f_desc_idx, f_attr_count = struct.unpack(">HHHH", class_bytes[offset:offset+8])
            offset += 8
            for _ in range(f_attr_count):
                if offset + 6 > len(class_bytes):
                    break
                attr_name_idx, attr_len = struct.unpack(">HI", class_bytes[offset:offset+6])
                offset += 6 + attr_len
                
        # Methods
        methods_count = struct.unpack(">H", class_bytes[offset:offset+2])[0]
        offset += 2
        phases.append(f"✓ Resolved methods count: {methods_count}")
        phases.append("Phase 3: Disassembling JVM Bytecode Instructions")
        
        disassembled = []
        disassembled.append(f"// Decompiled Class: {class_name}.class")
        disassembled.append(f"// Target JVM Target Version: major={major} minor={minor}")
        disassembled.append(f"public class {class_name.split('/')[-1]} {{")
        
        # Opcode table
        opcodes = {
            0x00: "nop", 0x01: "aconst_null", 0x02: "iconst_m1", 0x03: "iconst_0",
            0x04: "iconst_1", 0x05: "iconst_2", 0x06: "iconst_3", 0x07: "iconst_4",
            0x08: "iconst_5", 0x09: "lconst_0", 0x0a: "lconst_1", 0x0b: "fconst_0",
            0x0c: "fconst_1", 0x0d: "fconst_2", 0x0e: "dconst_0", 0x0f: "dconst_1",
            0x10: "bipush", 0x11: "sipush", 0x12: "ldc", 0x13: "ldc_w", 0x14: "ldc2_w",
            0x15: "iload", 0x16: "lload", 0x17: "fload", 0x18: "dload", 0x19: "aload",
            0x2a: "aload_0", 0x2b: "aload_1", 0x2c: "aload_2", 0x2d: "aload_3",
            0x36: "istore", 0x3c: "istore_1", 0x3d: "istore_2", 0x3e: "istore_3",
            0x4b: "astore_0", 0x4c: "astore_1", 0x4d: "astore_2", 0x4e: "astore_3",
            0x57: "pop", 0x59: "dup", 0x60: "iadd", 0x64: "isub", 0x68: "imul",
            0x99: "ifeq", 0x9a: "ifne", 0xa7: "goto", 0xac: "ireturn", 0xb0: "areturn",
            0xb1: "return", 0xb2: "getstatic", 0xb3: "putstatic", 0xb4: "getfield",
            0xb5: "putfield", 0xb6: "invokevirtual", 0xb7: "invokespecial",
            0xb8: "invokestatic", 0xb9: "invokeinterface", 0xbb: "new",
            0xbc: "newarray", 0xbd: "anewarray", 0xbe: "arraylength", 0xbf: "athrow"
        }
        
        for m_idx in range(methods_count):
            if offset + 8 > len(class_bytes):
                break
            m_flags, m_name_idx, m_desc_idx, m_attr_count = struct.unpack(">HHHH", class_bytes[offset:offset+8])
            offset += 8
            
            method_name = get_cp_utf8(m_name_idx)
            method_desc = get_cp_utf8(m_desc_idx)
            
            disassembled.append(f"\n    // Access flags: {m_flags}")
            disassembled.append(f"    // Descriptor: {method_desc}")
            disassembled.append(f"    public void {method_name}() {{")
            
            for _ in range(m_attr_count):
                if offset + 6 > len(class_bytes):
                    break
                attr_name_idx, attr_len = struct.unpack(">HI", class_bytes[offset:offset+6])
                offset += 6
                
                attr_name = get_cp_utf8(attr_name_idx)
                if attr_name.lower() == "code":
                    if offset + 8 > len(class_bytes):
                        break
                    max_stack, max_locals, code_len = struct.unpack(">HHI", class_bytes[offset:offset+8])
                    code_offset = offset + 8
                    
                    code_bytes = class_bytes[code_offset:code_offset+code_len]
                    
                    pc = 0
                    while pc < len(code_bytes):
                        opcode = code_bytes[pc]
                        op_name = opcodes.get(opcode, f"db {hex(opcode)}")
                        inst_str = f"            {pc:03d}: {op_name}"
                        
                        if opcode == 0x10: # bipush
                            val = code_bytes[pc+1]
                            inst_str += f" {val}"
                            pc += 2
                        elif opcode == 0x11: # sipush
                            val = struct.unpack(">h", code_bytes[pc+1:pc+3])[0]
                            inst_str += f" {val}"
                            pc += 3
                        elif opcode in (0x12, 0x13, 0x14): # ldc variants
                            arg_idx = code_bytes[pc+1] if opcode == 0x12 else struct.unpack(">H", code_bytes[pc+1:pc+3])[0]
                            ref_str = ""
                            if arg_idx in cp_map:
                                tag_type, tag_val = cp_map[arg_idx]
                                if tag_type == "UTF8":
                                    ref_str = f'"{tag_val}"'
                                elif tag_type == "REF":
                                    ref_str = f'"{get_cp_utf8(tag_val)}"'
                                else:
                                    ref_str = str(tag_val)
                            inst_str += f" #{arg_idx} // {ref_str}"
                            pc += 2 if opcode == 0x12 else 3
                        elif opcode in (0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a):
                            var_idx = code_bytes[pc+1]
                            inst_str += f" var_{var_idx}"
                            pc += 2
                        elif opcode in (0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xbb): # field/methods refs
                            ref_idx = struct.unpack(">H", code_bytes[pc+1:pc+3])[0]
                            ref_str = ""
                            if ref_idx in cp_map and cp_map[ref_idx][0] == "REF2":
                                c_idx, nt_idx = cp_map[ref_idx][1]
                                cls_name = resolve_classname(c_idx)
                                if nt_idx in cp_map and cp_map[nt_idx][0] == "REF2":
                                    n_idx, d_idx = cp_map[nt_idx][1]
                                    ref_str = f"{cls_name}.{get_cp_utf8(n_idx)}:{get_cp_utf8(d_idx)}"
                            inst_str += f" #{ref_idx} // {ref_str}"
                            pc += 3
                        elif opcode in (0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0xa7): # branches
                            offset_branch = struct.unpack(">h", code_bytes[pc+1:pc+3])[0]
                            inst_str += f" -> {pc + offset_branch}"
                            pc += 3
                        else:
                            pc += 1
                        disassembled.append(inst_str)
                        
                    offset += attr_len
                else:
                    offset += attr_len
            disassembled.append("    }")
            
        disassembled.append("}")
        
        phases.append("Phase 4: Constructing High-Level AST Representation")
        phases.append("✓ Bytecode disassembly successfully rendered.")
        
        return {
            "success": True,
            "phases": phases,
            "code": "\n".join(disassembled)
        }
    except Exception as e:
        return {"success": False, "error": f"Decompilation failure: {str(e)}"}

# JSON File Read/Write Helpers
def read_json_file(file_path, default_value):
    if not file_path.exists():
        return default_value
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception:
        return default_value

def write_json_file(file_path, data):
    try:
        file_path.parent.mkdir(exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error writing to {file_path}: {e}")

def load_config():
    """Load configuration from config.json with fallback default."""
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
    
    if IS_VERCEL and not CONFIG_FILE.exists() and CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                write_json_file(CONFIG_FILE, json.load(f))
        except Exception:
            pass
            
    return read_json_file(CONFIG_FILE, default_config)

def save_config(config_data):
    """Save configuration."""
    write_json_file(CONFIG_FILE, config_data)
    if not IS_VERCEL and CONFIG_FILE != CONFIG_PATH:
        write_json_file(CONFIG_PATH, config_data)

def get_all_scans():
    return read_json_file(SCANS_FILE, [])

def save_scans(scans):
    write_json_file(SCANS_FILE, scans)

def get_all_detections():
    return read_json_file(DETECTIONS_FILE, [])

def save_detections(detections):
    write_json_file(DETECTIONS_FILE, detections)

def get_all_hashes():
    return read_json_file(HASHES_FILE, {})

def save_hashes(hashes):
    write_json_file(HASHES_FILE, hashes)

def get_stats():
    """Fetch aggregated statistics from persistent VPS database."""
    try:
        import urllib.request
        import json
        req = urllib.request.Request("http://13.126.124.247:5000/api/admin_stats")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("success"):
                return data.get("stats")
    except Exception as e:
        pass
        
    return {
        "total_scans": 0,
        "total_files_scanned": 0,
        "total_flagged_files": 0,
        "detection_layers": {},
        "common_threats": [],
        "recent_scans": []
    }

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

# Endpoint to upload jar and list class files for decompiler (Suggested Feature)
@app.route("/api/decompile_upload", methods=["POST"])
def decompile_upload():
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400
            
        file = request.files['file']
        file_hash = request.form.get("hash", "").strip().lower()
        if not file_hash or len(file_hash) != 40:
            return jsonify({"success": False, "error": "Invalid file hash"}), 400
            
        # Cache file
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cached_path = CACHE_DIR / f"{file_hash}.jar"
        
        file.save(cached_path)
        
        # Read Zip contents
        class_files = []
        with zipfile.ZipFile(cached_path, 'r') as zip_ref:
            for entry in zip_ref.namelist():
                if entry.endswith(".class"):
                    class_files.append(entry)
                    
        return jsonify({
            "success": True,
            "hash": file_hash,
            "classes": sorted(class_files)
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"JAR parsing failed: {str(e)}"}), 500

# Endpoint to decompile a specific class file inside cached jar (Suggested Feature)
@app.route("/api/decompile_class", methods=["GET"])
def decompile_class_endpoint():
    try:
        file_hash = request.args.get("hash", "").strip().lower()
        class_path = request.args.get("class_path", "").strip()
        
        if not file_hash or not class_path:
            return jsonify({"success": False, "error": "Missing parameters"}), 400
            
        cached_path = CACHE_DIR / f"{file_hash}.jar"
        if not cached_path.exists():
            return jsonify({"success": False, "error": "Cached JAR not found. Please upload it again."}), 404
            
        class_bytes = None
        with zipfile.ZipFile(cached_path, 'r') as zip_ref:
            if class_path in zip_ref.namelist():
                class_bytes = zip_ref.read(class_path)
                
        if not class_bytes:
            return jsonify({"success": False, "error": f"Class {class_path} not found inside JAR"}), 404
            
        decomp_result = disassemble_class(class_bytes)
        return jsonify(decomp_result)
    except Exception as e:
        return jsonify({"success": False, "error": f"Disassembly server error: {str(e)}"}), 500
def get_ip_and_location(req_headers, remote_addr):
    # Determine IP Address
    ip_address = req_headers.get("x-forwarded-for")
    if ip_address:
        ip_address = ip_address.split(',')[0].strip()
    else:
        ip_address = remote_addr or "127.0.0.1"
        
    # Determine Location
    location = None
    # Try Vercel geo-location headers
    city = req_headers.get("x-vercel-ip-city")
    country = req_headers.get("x-vercel-ip-country")
    if city and country:
        location = f"{city}, {country}"
    elif country:
        location = country
    elif city:
        location = city
        
    if not location:
        is_local = False
        if ip_address in ("127.0.0.1", "localhost", "::1"):
            is_local = True
        else:
            parts = ip_address.split('.')
            if len(parts) == 4:
                try:
                    p0 = int(parts[0])
                    p1 = int(parts[1])
                    if p0 == 10:
                        is_local = True
                    elif p0 == 192 and p1 == 168:
                        is_local = True
                    elif p0 == 172 and (16 <= p1 <= 31):
                        is_local = True
                except ValueError:
                    pass
        if is_local:
            location = "Local Network"
        else:
            import urllib.request
            try:
                url = f"http://ip-api.com/json/{ip_address}"
                req = urllib.request.Request(url, headers={'User-Agent': 'ANSH9BOSS-Validator/1.0'})
                with urllib.request.urlopen(req, timeout=2) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    if resp_data.get("status") == "success":
                        city_name = resp_data.get("city", "")
                        country_name = resp_data.get("country", "")
                        if city_name and country_name:
                            location = f"{city_name}, {country_name}"
                        elif country_name:
                            location = country_name
                        else:
                            location = "Unknown Location"
                    else:
                        location = "Unknown Location"
            except Exception:
                location = "Unknown Location"
    return ip_address, location

@app.route("/api/report_scan", methods=["POST"])
def report_scan():
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "message": "No payload received"}), 400
            
        ip_address, location = get_ip_and_location(request.headers, request.remote_addr)
        data["ip_address"] = ip_address
        data["location"] = location
        
        # Proxy to persistent VPS database
        import urllib.request
        import json
        req = urllib.request.Request(
            "http://13.126.124.247:5000/api/report_scan",
            data=json.dumps(data).encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return jsonify(json.loads(resp.read().decode("utf-8")))
    except Exception as e:
        return jsonify({"success": False, "message": f"Telemetry proxy error: {str(e)}"}), 500

@app.route("/api/live_feed")
def live_feed():
    try:
        import urllib.request
        import json
        req = urllib.request.Request("http://13.126.124.247:5000/api/live_feed")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return jsonify(json.loads(resp.read().decode("utf-8")))
    except Exception as e:
        return jsonify({"success": False, "message": f"Proxy error: {str(e)}"}), 500

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
            
        if "discord_webhook" in data:
            config["discord_webhook"] = data["discord_webhook"].strip()
            
        save_config(config)
        return jsonify({"success": True, "message": "Configuration updated successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route("/api/rules")
def get_rules():
    config = load_config()
    return jsonify({
        "version": config.get("version", "1.0.0"),
        "known_cheats": config.get("known_cheats", []),
        "known_packages": config.get("known_packages", []),
        "cheat_strings": config.get("cheat_strings", [])
    })

@app.route("/api/verify_hash")
def verify_hash():
    sha1 = request.args.get("hash", "").strip().lower()
    if not sha1 or len(sha1) != 40:
        return jsonify({"valid": False, "error": "Invalid SHA-1 hash"}), 400

    hashes = get_all_hashes()
    if sha1 in hashes:
        cached = hashes[sha1]
        return jsonify({
            "valid": True,
            "hash": sha1,
            "clean": cached["clean"],
            "source": cached["source"],
            "cached": True
        })

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
            resp_data = json.loads(resp.read().decode("utf-8"))
            if "id" in resp_data:
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

    hashes[sha1] = {
        "clean": clean_mod,
        "source": source,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_hashes(hashes)

    return jsonify({
        "valid": True,
        "hash": sha1,
        "clean": clean_mod,
        "source": source,
        "cached": False
    })

@app.route("/api/virustotal")
def virustotal_scan():
    sha1 = request.args.get("hash", "").strip().lower()
    if not sha1:
        return jsonify({"success": False, "error": "No hash provided"}), 400
        
    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        # Fallback simulated response for demonstration if no API key is provided
        import random
        is_malicious = random.random() > 0.8
        return jsonify({
            "success": True,
            "hash": sha1,
            "malicious": random.randint(3, 15) if is_malicious else 0,
            "simulated": True
        })
        
    import urllib.request
    import urllib.error
    url = f"https://www.virustotal.com/api/v3/files/{sha1}"
    
    try:
        req = urllib.request.Request(url, headers={'x-apikey': vt_key})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return jsonify({
                "success": True,
                "hash": sha1,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            })
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return jsonify({"success": True, "hash": sha1, "malicious": 0, "not_found": True})
        return jsonify({"success": False, "error": f"VirusTotal API HTTP {e.code}"}), 502
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
