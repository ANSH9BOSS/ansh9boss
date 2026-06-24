#!/usr/bin/env python3
import os
import sys
import json
import time
import zipfile
import sqlite3
from pathlib import Path
from datetime import datetime

# Import rich components
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich import box
except ImportError:
    print("Error: 'rich' library is required. Install it using: pip install rich")
    sys.exit(1)

# Import pyfiglet for banner
try:
    import pyfiglet
except ImportError:
    print("Error: 'pyfiglet' library is required. Install it using: pip install pyfiglet")
    sys.exit(1)

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "ansh9boss.db"

console = Console()

def load_config():
    """Load configuration from config.json or return defaults."""
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
    
    if not CONFIG_PATH.exists():
        DATA_DIR.mkdir(exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(default_config, f, indent=2)
        return default_config
    
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to load config.json ({e}). Using default settings.[/yellow]")
        return default_config

def init_db():
    """Initialize the local SQLite database for scan tracking."""
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        total_files INTEGER,
        flagged_files INTEGER,
        highest_risk TEXT,
        platform TEXT
    )
    """)
    
    cursor.execute("""
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
    
    conn.commit()
    conn.close()

def save_scan_results(total_files, flagged_files, highest_risk, detections):
    """Save scan metrics to SQLite database."""
    try:
        is_windows = os.name == 'nt' or sys.platform == 'win32'
        is_android = os.path.exists('/system') or 'ANDROID_ROOT' in os.environ or 'com.termux' in os.environ.get('PREFIX', '')
        platform = "Windows" if is_windows else ("Android (Termux)" if is_android else "Linux/macOS")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO scans (total_files, flagged_files, highest_risk, platform) VALUES (?, ?, ?, ?)",
            (total_files, flagged_files, highest_risk, platform)
        )
        scan_id = cursor.lastrowid
        
        for det in detections:
            cursor.execute(
                """INSERT INTO detections 
                   (scan_id, file_name, file_path, risk_level, detection_layer, matched_details) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    det["file_name"],
                    det["file_path"],
                    det["risk_level"],
                    det["detection_layer"],
                    ", ".join(det["matched_details"]) if isinstance(det["matched_details"], list) else det["matched_details"]
                )
            )
            
        conn.commit()
        conn.close()
    except Exception as e:
        console.print(f"[red]Error saving scan stats to database: {e}[/red]")

def report_scan_telemetry(total_files, flagged_files, highest_risk, detections):
    """Report anonymous scan telemetry to the global web server tracker."""
    api_url = os.environ.get("ANSH9BOSS_API_URL", "https://ansh9boss.vercel.app")
    report_endpoint = f"{api_url}/api/report_scan"
    
    # Anonymize detections list for global dashboard (hide local user directory filepaths)
    anon_detections = []
    for det in detections:
        anon_detections.append({
            "file_name": det["file_name"],
            "risk_level": det["risk_level"],
            "detection_layer": det["detection_layer"],
            "matched_details": det["matched_details"]
        })
        
    is_windows = os.name == 'nt' or sys.platform == 'win32'
    is_android = os.path.exists('/system') or 'ANDROID_ROOT' in os.environ or 'com.termux' in os.environ.get('PREFIX', '')
    platform = "Windows" if is_windows else ("Android (Termux)" if is_android else "Linux/macOS")
    
    payload = {
        "platform": platform,
        "total_files": total_files,
        "flagged_files": flagged_files,
        "highest_risk": highest_risk,
        "detections": anon_detections
    }
    
    import urllib.request
    import urllib.error
    
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            report_endpoint,
            data=data,
            headers={'Content-Type': 'application/json', 'User-Agent': 'ANSH9BOSS-Scanner/1.0'}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            return True
    except Exception:
        return False

def display_banner(version):
    """Display the application startup banner."""
    ascii_art = pyfiglet.figlet_format("ANSH9BOSS")
    
    console.print(f"[cyan]{ascii_art}[/cyan]", style="bold")
    console.print("[bold aquamarine1]Minecraft Mod Analyzer — Detecting cheats & malicious mods since 2026[/bold aquamarine1]")
    console.print(f"[cyan]Version:[/cyan] [white]{version}[/white] | [cyan]Platform:[/cyan] [white]{sys.platform.upper()}[/white]")
    
    disclaimer = (
        "DISCLAIMER: This software is provided for defensive security audits, testing,\n"
        "and educational purposes only. Do not use this tool for unauthorized malicious purposes."
    )
    console.print(Panel(disclaimer, style="bold red", border_style="cyan", box=box.ROUNDED))
    console.print()

def detect_platform_paths():
    """Detect platform and return standard directories to search."""
    is_windows = os.name == 'nt' or sys.platform == 'win32'
    is_android = os.path.exists('/system') or 'ANDROID_ROOT' in os.environ or 'com.termux' in os.environ.get('PREFIX', '')
    
    paths = []
    
    if is_android:
        console.print("[cyan]System Type: Android (Termux) detected.[/cyan]")
        home = Path.home()
        raw_paths = [
            "/sdcard/.minecraft/mods",
            "/sdcard/games/com.mojang/",
            str(home / ".local/share/PojavLauncher/mods"),
            str(home / "storage/shared/PojavLauncher/mods"),
            str(home / "ZalithLauncher/mods"),
            str(home / "MojoLauncher/mods"),
            str(home / "instances")  # will search subdirectories for /mods
        ]
        
        for p in raw_paths:
            path_obj = Path(p)
            if "*" in p or "instances" in p:
                # Handle instances wildcard expansion
                if path_obj.exists():
                    for inst in path_obj.iterdir():
                        if inst.is_dir() and (inst / "mods").exists():
                            paths.append(inst / "mods")
            else:
                if path_obj.exists():
                    paths.append(path_obj)
                    
    elif is_windows:
        console.print("[cyan]System Type: Windows detected.[/cyan]")
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        
        # Build search list
        search_templates = []
        if appdata:
            appdata_path = Path(appdata)
            search_templates.extend([
                appdata_path / ".minecraft/mods",
                appdata_path / "CurseForge/minecraft/Instances",
                appdata_path / "GDLauncher/instances",
                appdata_path / "PrismLauncher/instances",
                appdata_path / "ATLauncher/instances"
            ])
        if localappdata:
            local_path = Path(localappdata)
            search_templates.extend([
                local_path / "Packages/MultiMC/instances"
            ])
            
        for path_obj in search_templates:
            if not path_obj.exists():
                continue
                
            # If it's an instance folder, look inside each instance's mods folder
            if "Instances" in path_obj.parts or "instances" in path_obj.parts:
                for inst in path_obj.iterdir():
                    if inst.is_dir() and (inst / "mods").exists():
                        paths.append(inst / "mods")
            else:
                paths.append(path_obj)
    else:
        # Generic Linux / macOS fallback
        console.print("[cyan]System Type: Linux/macOS standard detected.[/cyan]")
        home = Path.home()
        standard_minecraft = home / ".minecraft/mods"
        if standard_minecraft.exists():
            paths.append(standard_minecraft)
            
    # Clean duplicates and format
    paths = list(set([p.resolve() for p in paths]))
    return paths

def check_usb_injection(filepath):
    """Check if file was modified or added within the last 24 hours."""
    try:
        mtime = os.path.getmtime(filepath)
        if os.name == 'nt':
            ctime = os.path.getctime(filepath)
            latest = max(mtime, ctime)
        else:
            latest = mtime
        hours_diff = (time.time() - latest) / 3600
        return hours_diff <= 24
    except Exception:
        return False

def extract_jar_zip(filepath):
    """Attempt to open and read JAR using ZipFile. Returns zipfile object or raises exception."""
    # Method 1: Standard ZipFile
    return zipfile.ZipFile(filepath, 'r')

def calculate_sha1(filepath):
    import hashlib
    try:
        sha1 = hashlib.sha1()
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest().lower()
    except Exception:
        return ""

def check_cloud_hash_verify(sha1):
    try:
        api_url = os.environ.get("ANSH9BOSS_API_URL", "https://ansh9boss.vercel.app")
        url = f"{api_url}/api/verify_hash?hash={sha1}"
        import urllib.request
        import json
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'ANSH9BOSS-Scanner/1.0'}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("valid"):
                return data.get("clean"), data.get("source")
    except Exception:
        pass
    return False, None

def scan_jar(filepath, config):
    """
    Perform 3-layer scan on a jar file.
    Returns: (risk_level, layers_triggered, match_details, obfuscated)
    """
    filename = filepath.name.lower()
    
    # 0. Cloud Whitelist Hash Check
    sha1 = calculate_sha1(filepath)
    if len(sha1) == 40:
        is_clean, source = check_cloud_hash_verify(sha1)
        if is_clean:
            return "CLEAN", ["Cloud Whitelist"], [f"Verified clean mod matching cloud database ({source})"], False

    risk_level = "CLEAN"
    layers_triggered = []
    match_details = []
    obfuscated = False
    
    # Check USB Injection
    is_recent = check_usb_injection(filepath)

    # Layer 1: Filename Check
    for cheat in config["known_cheats"]:
        # Allow special case for badlion (flag only if modified)
        if cheat == "badlion":
            if "badlion" in filename and "official" not in filename and "original" not in filename:
                # We flag as suspicious until verified in Layer 2/3
                if risk_level != "DANGEROUS":
                    risk_level = "SUSPICIOUS"
                layers_triggered.append("Layer 1 (Filename)")
                match_details.append("Filename contains 'badlion' (Modified verification required)")
        elif cheat in filename:
            risk_level = "DANGEROUS"
            layers_triggered.append("Layer 1 (Filename)")
            match_details.append(f"Filename matches known cheat: '{cheat}'")
            break

    # Layer 2 & 3: Inside the JAR Check
    zip_ref = None
    try:
        zip_ref = extract_jar_zip(filepath)
        file_list = zip_ref.namelist()
        
        # Check for Obfuscation indicators
        class_files = [f for f in file_list if f.endswith('.class')]
        total_classes = len(class_files)
        
        # Heuristic 1: Large number of classes with 1 or 2 letter names in root/deep folders
        short_names = 0
        for cf in class_files:
            class_name = Path(cf).stem
            if len(class_name) <= 2:
                short_names += 1
                
        if total_classes > 15 and (short_names / total_classes) > 0.85:
            obfuscated = True
            
        # Heuristic 2: Known protectors in files/paths
        protector_keywords = ["yguard", "allatori", "zelix", "proguard", "stringer", "loaderencrypt"]
        for cf in file_list:
            cf_lower = cf.lower()
            if any(p in cf_lower for p in protector_keywords):
                obfuscated = True
                
        if obfuscated:
            if risk_level != "DANGEROUS":
                risk_level = "SUSPICIOUS"
            layers_triggered.append("Obfuscation Check")
            match_details.append("Heavily obfuscated or protected jar file structure")

        # Layer 2: Package/Manifest Check
        manifest_files = ["meta-inf/manifest.mf", "fabric.mod.json", "mods.toml", "mcmod.info"]
        manifest_found = False
        
        # Scan zip entries for known cheat packages
        for entry in file_list:
            entry_lower = entry.lower()
            for pkg in config["known_packages"]:
                # Match package directory structure
                if f"/{pkg}/" in entry_lower or entry_lower.startswith(f"{pkg}/"):
                    risk_level = "DANGEROUS"
                    if "Layer 2 (Package)" not in layers_triggered:
                        layers_triggered.append("Layer 2 (Package)")
                    match_details.append(f"Found cheat package: '{pkg}' ({entry})")

        # Read specific manifest metadata
        for meta_file in file_list:
            if meta_file.lower() in manifest_files:
                manifest_found = True
                try:
                    meta_content = zip_ref.read(meta_file).decode('utf-8', errors='ignore').lower()
                    for pkg in config["known_packages"]:
                        if pkg in meta_content:
                            risk_level = "DANGEROUS"
                            if "Layer 2 (Package)" not in layers_triggered:
                                layers_triggered.append("Layer 2 (Package)")
                            match_details.append(f"Cheat signature '{pkg}' found in {meta_file}")
                except Exception:
                    pass

        # Layer 3: Cheat String Scanner
        matched_strings = set()
        # Scan .class (as binary bytes) and text files for cheat strings
        scan_extensions = ('.class', '.json', '.txt', '.toml', '.properties', '.yml')
        
        for entry in file_list:
            if entry.endswith(scan_extensions):
                try:
                    content_bytes = zip_ref.read(entry).lower()
                    for cheat_str in config["cheat_strings"]:
                        # Convert to bytes for scanning
                        cheat_str_bytes = cheat_str.encode('utf-8')
                        if cheat_str_bytes in content_bytes:
                            matched_strings.add(cheat_str)

                    # Advanced Check: Layer 4 Payload Analysis
                    if b"discord.com/api/webhooks" in content_bytes or b"discordapp.com/api/webhooks" in content_bytes:
                        risk_level = "DANGEROUS"
                        if "Layer 4 (Webhook Stealer)" not in layers_triggered:
                            layers_triggered.append("Layer 4 (Webhook Stealer)")
                        match_details.append(f"Malicious Discord Webhook Stealer pattern found in: {entry}")

                    if b"runtime.getruntime().exec" in content_bytes or b"processbuilder" in content_bytes:
                        if risk_level != "DANGEROUS":
                            risk_level = "SUSPICIOUS"
                        if "Layer 4 (Execution Hijack)" not in layers_triggered:
                            layers_triggered.append("Layer 4 (Execution Hijack)")
                        match_details.append(f"Suspicious native execution methods found in: {entry}")

                    if b"defineclass" in content_bytes and b"urlclassloader" in content_bytes:
                        risk_level = "DANGEROUS"
                        if "Layer 4 (Reflective Loader)" not in layers_triggered:
                            layers_triggered.append("Layer 4 (Reflective Loader)")
                        match_details.append(f"Suspicious reflective ClassLoader injection found in: {entry}")
                except Exception:
                    pass
                    
        if len(matched_strings) > 0:
            if len(matched_strings) >= 3:
                risk_level = "DANGEROUS"
                layers_triggered.append("Layer 3 (String Scan)")
                match_details.append(f"Dangerous cheat keywords ({len(matched_strings)} matches): {list(matched_strings)}")
            elif len(matched_strings) == 2:
                if risk_level != "DANGEROUS":
                    risk_level = "SUSPICIOUS"
                layers_triggered.append("Layer 3 (String Scan)")
                match_details.append(f"Suspicious cheat keywords ({len(matched_strings)} matches): {list(matched_strings)}")
                
    except zipfile.BadZipFile:
        # Obfuscation & Blocker Handling: Try multiple extraction methods
        # Attempt to see if we can read bytes or if it's just corrupt
        obfuscated = True
        risk_level = "SUSPICIOUS"
        layers_triggered.append("Obfuscation Check")
        match_details.append("Protected or corrupt JAR structure (Unzip failed)")
    except Exception as e:
        obfuscated = True
        risk_level = "SUSPICIOUS"
        layers_triggered.append("Error / Obfuscation")
        match_details.append(f"Failed to extract/read files: {str(e)}")
    finally:
        if zip_ref:
            zip_ref.close()
            
    if is_recent and risk_level != "CLEAN":
        layers_triggered.append("Recent Modification")
        match_details.append("File was modified/added recently (within 24 hours)")

    # Risk levels fallback
    if len(layers_triggered) == 0:
        risk_level = "CLEAN"
        
    return risk_level, layers_triggered, match_details, obfuscated

def sync_cloud_rules(config):
    """Fetch latest threat rules database from cloud and update configuration in memory."""
    console.print("[cyan]Syncing scanner threat rules from cloud database...[/cyan]")
    try:
        api_url = os.environ.get("ANSH9BOSS_API_URL", "https://ansh9boss.vercel.app")
        url = f"{api_url}/api/rules"
        import urllib.request
        import json
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'ANSH9BOSS-Scanner/1.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if "known_cheats" in data:
                config["known_cheats"] = data["known_cheats"]
            if "known_packages" in data:
                config["known_packages"] = data["known_packages"]
            if "cheat_strings" in data:
                config["cheat_strings"] = data["cheat_strings"]
            console.print(f"[green]✓ Dynamic rules synced successfully (v{data.get('version', '1.0.0')}).[/green]")
    except Exception as e:
        console.print(f"[yellow]! Offline fallback: Using local rules signature database ({e}).[/yellow]")

def audit_running_java_agents():
    """Audit running Java processes for suspicious -javaagent parameters."""
    console.print("[cyan]Auditing active JVM processes for runtime hijack agents...[/cyan]")
    detections = []
    
    import subprocess
    is_windows = os.name == 'nt' or sys.platform == 'win32'
    
    try:
        if is_windows:
            cmd = ['wmic', 'process', 'where', "name='java.exe' or name='javaw.exe'", 'get', 'CommandLine']
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            lines = output.split('\n')
        else:
            cmd = ['ps', 'aux']
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            lines = [l for l in output.split('\n') if 'java' in l.lower()]
            
        for line in lines:
            line_lower = line.lower()
            if '-javaagent:' in line_lower:
                parts = line.split('-javaagent:')
                if len(parts) > 1:
                    agent_path = parts[1].split()[0]
                    suspicious = False
                    reason = ""
                    if 'temp' in agent_path.lower() or 'tmp' in agent_path.lower():
                        suspicious = True
                        reason = "Agent loaded from temporary directories"
                    for cheat in ["wurst", "meteor", "liquidbounce", "vape", "sigma"]:
                        if cheat in agent_path.lower():
                            suspicious = True
                            reason = f"Agent matches known cheat keyword: '{cheat}'"
                            
                    if suspicious:
                        detections.append({
                            "process": "java/javaw",
                            "agent": agent_path,
                            "reason": reason,
                            "commandline": line.strip()[:100] + "..."
                        })
    except Exception:
        pass
        
    if detections:
        console.print("[bold red]🔴 RUNTIME WARNING: Suspicious JVM Javaagent detected![/bold red]")
        for det in detections:
            console.print(f"  [red]- Agent Path:[/red] {det['agent']}")
            console.print(f"    [yellow]Reason:[/yellow] {det['reason']}")
            console.print(f"    [dim white]Command:[/dim white] {det['commandline']}")
        console.print()
    else:
        console.print("[green]✓ Active JVM memory audit: No malicious javaagent injections found.[/green]\n")

def main():
    config = load_config()
    init_db()
    
    # Sync rules and audit active JVMs at startup
    sync_cloud_rules(config)
    audit_running_java_agents()
    
    display_banner(config.get("version", "1.0.0"))
    
    # Check if directory argument is provided via command line
    if len(sys.argv) > 1:
        cli_path = sys.argv[1]
        console.print(f"[cyan]Scanning folder specified via command line argument: [bold]{cli_path}[/bold][/cyan]")
        selected_folders = [Path(cli_path)]
    else:
        # Platform detection and path loading
        detected_folders = detect_platform_paths()
        selected_folders = []
        
        if detected_folders:
            console.print("[cyan]Auto-detected Minecraft Mod folders:[/cyan]")
            for idx, folder in enumerate(detected_folders):
                console.print(f"  [{idx + 1}] {folder}")
            console.print(f"  [{len(detected_folders) + 1}] Scan a custom mods folder")
            
            choice = console.input("\n[bold cyan]Select options (or press Enter for default auto-scan): [/bold cyan]").strip()
            
            if not choice:
                # Run auto-scan of all detected folders
                selected_folders = detected_folders
            else:
                try:
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(detected_folders):
                        selected_folders = [detected_folders[choice_idx]]
                    else:
                        # Custom folder prompt
                        custom_path = console.input("[bold cyan]Enter custom mods folder path: [/bold cyan]").strip()
                        selected_folders = [Path(custom_path)]
                except ValueError:
                    selected_folders = detected_folders
        else:
            console.print("[yellow]No default Minecraft mods folder could be detected on this system.[/yellow]")
            custom_path = console.input("[bold cyan]Please enter your mods folder path: [/bold cyan]").strip()
            if not custom_path:
                console.print("[red]Error: Path cannot be empty.[/red]")
                sys.exit(1)
            selected_folders = [Path(custom_path)]
        
    # Gather jar files
    jar_files = []
    for folder in selected_folders:
        folder_path = Path(folder)
        if folder_path.exists() and folder_path.is_dir():
            jar_files.extend(list(folder_path.rglob("*.jar")))
        elif folder_path.exists() and folder_path.is_file() and folder_path.suffix == ".jar":
            jar_files.append(folder_path)
            
    # De-duplicate jar files list
    jar_files = list(set([p.resolve() for p in jar_files]))
    
    if not jar_files:
        console.print("[yellow]No Mod (.jar) files found in the specified path(s).[/yellow]")
        sys.exit(0)
        
    console.print(f"\n[cyan]Found [bold]{len(jar_files)}[/bold] mod file(s) to analyze.[/cyan]\n")
    
    detections = []
    total_scanned = len(jar_files)
    flagged_count = 0
    highest_risk = "CLEAN"
    
    # Progress scanner
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="cyan", finished_style="aquamarine1"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        scan_task = progress.add_task("Analyzing mods...", total=total_scanned)
        
        for jar in jar_files:
            progress.update(scan_task, description=f"Scanning {jar.name[:30]}...")
            
            risk_level, layers, details, obfuscated = scan_jar(jar, config)
            
            # Map highest risk
            if risk_level == "DANGEROUS":
                highest_risk = "DANGEROUS"
            elif risk_level == "SUSPICIOUS" and highest_risk != "DANGEROUS":
                highest_risk = "SUSPICIOUS"
                
            if risk_level != "CLEAN":
                flagged_count += 1
                detections.append({
                    "file_name": jar.name,
                    "file_path": str(jar),
                    "risk_level": risk_level,
                    "detection_layer": " & ".join(layers),
                    "matched_details": details
                })
                
            progress.advance(scan_task)
            
    # Save scan results in DB
    save_scan_results(total_scanned, flagged_count, highest_risk, detections)
    
    # Report telemetry to global server
    with console.status("[cyan]Transmitting anonymous scan telemetry to global tracker...[/cyan]"):
        reported = report_scan_telemetry(total_scanned, flagged_count, highest_risk, detections)
        if reported:
            console.print("[green]✓ Anonymized telemetry successfully reported to global tracker.[/green]")
        else:
            console.print("[yellow]! Global tracker offline. Scanning completed offline.[/yellow]")
    
    # Output Scan Results Table
    console.print("\n[bold cyan]Analysis Results[/bold cyan]")
    
    if detections:
        table = Table(
            show_header=True, 
            header_style="bold cyan", 
            box=box.MINIMAL_DOUBLE_HEAD,
            border_style="cyan"
        )
        table.add_column("File Name", style="white", no_wrap=False)
        table.add_column("Risk Level", justify="center")
        table.add_column("Detection Layer", style="yellow")
        table.add_column("Details", style="dim white")
        
        # Separate normal flagged and recently added
        recent_flagged = []
        normal_flagged = []
        
        for det in detections:
            if "USB Injection" in det["detection_layer"]:
                recent_flagged.append(det)
            else:
                normal_flagged.append(det)
                
        # Display normal detections
        for det in normal_flagged:
            risk_colored = ""
            if det["risk_level"] == "DANGEROUS":
                risk_colored = "[bold red]🔴 DANGEROUS[/bold red]"
            elif det["risk_level"] == "SUSPICIOUS":
                risk_colored = "[bold yellow]🟡 SUSPICIOUS[/bold yellow]"
            else:
                risk_colored = "[bold green]🟢 CLEAN[/bold green]"
                
            details_str = "\n".join(det["matched_details"]) if isinstance(det["matched_details"], list) else det["matched_details"]
            table.add_row(det["file_name"], risk_colored, det["detection_layer"], details_str)
            
        # Display recent USB injections
        for det in recent_flagged:
            risk_colored = "[bold red]🔴 DANGEROUS[/bold red]"
            details_str = f"Recently added — verify manually!\n" + "\n".join(det["matched_details"])
            table.add_row(det["file_name"], risk_colored, det["detection_layer"], details_str)
            
        console.print(table)
    else:
        console.print(Panel(
            "[bold green]🟢 Scan Complete: No threats found! All scanned mods are clean.[/bold green]",
            border_style="green",
            box=box.ROUNDED
        ))
        
    # Summary report
    summary_panel = (
        f"[cyan]Total Files Scanned:[/cyan] [bold]{total_scanned}[/bold]\n"
        f"[cyan]Flagged Files:[/cyan] [bold red if flagged_count > 0 else green]{flagged_count}[/bold red if flagged_count > 0 else green]\n"
        f"[cyan]Highest Risk Found:[/cyan] "
    )
    if highest_risk == "DANGEROUS":
        summary_panel += "[bold red]🔴 DANGEROUS[/bold red]"
    elif highest_risk == "SUSPICIOUS":
        summary_panel += "[bold yellow]🟡 SUSPICIOUS[/bold yellow]"
    else:
        summary_panel += "[bold green]🟢 CLEAN[/bold green]"
        
    console.print(Panel(summary_panel, title="Scan Summary", border_style="cyan", box=box.ROUNDED))
    console.print()

if __name__ == "__main__":
    main()
