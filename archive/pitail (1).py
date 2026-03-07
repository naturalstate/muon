#!/usr/bin/env python3
"""
piTail – WiFi Manager v2
Multi-interface management for NetHunter / Kali on Raspberry Pi and Android
"""

import os
import sys
import subprocess
import time
import json
import threading
import signal

# ═══════════════════════════════════════════════════════════════════════════════
#  PATHS & CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
CONFIG_DIR     = os.path.expanduser("~/.pitail")
PROFILES_FILE  = os.path.join(CONFIG_DIR, "profiles.json")
WPA_SUPPLICANT = "/usr/sbin/wpa_supplicant"
PITAIL_IP      = "192.168.43.254"
WATCHDOG_INTERVAL = 30

# ═══════════════════════════════════════════════════════════════════════════════
#  COLORS  — all-green theme, black terminal background
#  LIME    brightest  → for UP/connected/OK
#  BRIGHT  light      → menu numbers, prompts
#  MED     teal-green → section headers
#  BORDER  medium     → box lines, dividers
#  DARK    forest     → dim/secondary labels
# ═══════════════════════════════════════════════════════════════════════════════
class C:
    LIME   = '\033[38;5;118m'
    BRIGHT = '\033[38;5;82m'
    MED    = '\033[38;5;35m'
    BORDER = '\033[38;5;28m'
    DARK   = '\033[38;5;22m'
    ERR    = '\033[91m'
    WARN   = '\033[93m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

# ═══════════════════════════════════════════════════════════════════════════════
#  STATE
# ═══════════════════════════════════════════════════════════════════════════════
active_iface         = "wlan1"
protected_ifaces     = ["wlan0"]   # never managed unless user explicitly allows
watchdog_running     = False
watchdog_thread      = None
watchdog_target_ssid = None        # if set, watchdog enforces this SSID

# Pi-Tail keepalive — monitors wlan0 and reconnects to hotspot if it drops
PITAIL_IFACE         = "wlan0"
PITAIL_SSID          = "sepultura"
PITAIL_PASS          = "R4t4m4h4tt4"
PITAIL_KEEPALIVE_INT = 20          # seconds between keepalive checks
keepalive_running    = False
keepalive_thread     = None

# Last known connection per interface — used for auto-recovery
last_known = {}      # { "wlan1": {"ssid": "...", "password": "..."}, ... }

_cache               = {}          # simple TTL cache for slow queries

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def run(cmd, capture=True, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=capture,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timed out"
    except Exception as e:
        return 1, "", str(e)

def cached(key, fn, ttl=60):
    """Run fn(), cache result for ttl seconds."""
    now = time.time()
    if key in _cache and now - _cache[key][1] < ttl:
        return _cache[key][0]
    val = fn()
    _cache[key] = (val, now)
    return val

def ok(msg):   print(f"{C.LIME}[+]{C.RESET} {msg}")
def err(msg):  print(f"{C.ERR}[-]{C.RESET} {msg}")
def info(msg): print(f"{C.BRIGHT}[*]{C.RESET} {msg}")
def warn(msg): print(f"{C.WARN}[!]{C.RESET} {msg}")

def pause():
    input(f"\n{C.BORDER}  Press Enter to continue...{C.RESET}")

def wpa_conf(iface):
    return os.path.join(CONFIG_DIR, f"wpa_{iface}.conf")

def wpa_pid(iface):
    return f"/tmp/wpa_{iface}.pid"

def ensure_dirs():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(PROFILES_FILE):
        with open(PROFILES_FILE, 'w') as f:
            json.dump([], f)

def load_profiles():
    try:
        with open(PROFILES_FILE) as f:
            return json.load(f)
    except:
        return []

def save_profiles(profiles):
    with open(PROFILES_FILE, 'w') as f:
        json.dump(profiles, f, indent=2)

def save_profile(ssid, password):
    profiles = load_profiles()
    for p in profiles:
        if p['ssid'] == ssid:
            p['password'] = password
            save_profiles(profiles)
            return
    profiles.append({'ssid': ssid, 'password': password})
    save_profiles(profiles)
    ok(f"Profile saved: '{ssid}'")

# ═══════════════════════════════════════════════════════════════════════════════
#  INTERFACE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
def get_wireless_ifaces():
    """Detect all wireless interfaces currently present on the system."""
    _, out, _ = run("ls /sys/class/net/")
    ifaces = []
    for name in out.split():
        c, _, _ = run(f"test -d /sys/class/net/{name}/wireless")
        if c == 0:
            ifaces.append(name)
    return sorted(ifaces)

# ═══════════════════════════════════════════════════════════════════════════════
#  STATUS QUERIES
# ═══════════════════════════════════════════════════════════════════════════════
def iface_state(iface):
    _, out, _ = run(f"ip link show {iface} 2>/dev/null")
    if not out:       return "MISSING"
    if "LOWER_UP" in out: return "UP"
    if "UP" in out:   return "UP (no link)"
    return "DOWN"

def iface_ip(iface):
    _, out, _ = run(
        f"ip addr show {iface} 2>/dev/null | grep 'inet ' | awk '{{print $2}}'")
    return out or "no IP"

def iface_ssid(iface):
    _, out, _ = run(f"iwgetid {iface} --raw 2>/dev/null")
    return out or "—"

def check_pitail():
    c, _, _ = run(f"ping -c 1 -W 2 {PITAIL_IP} 2>/dev/null")
    return c == 0

def check_internet():
    c, _, _ = run("ping -c 1 -W 3 8.8.8.8 2>/dev/null")
    return c == 0

def get_public_ip():
    _, out, _ = run("curl -4 --connect-timeout 5 -s ifconfig.me 2>/dev/null", timeout=8)
    return out or "unavailable"

def wpa_running(iface):
    c, _, _ = run(f"pgrep -f 'wpa_supplicant.*{iface}' 2>/dev/null")
    return c == 0

def iface_mode(iface):
    """Return AP, managed, monitor, or unknown."""
    _, out, _ = run(f"iw dev {iface} info 2>/dev/null")
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split()[1]  # AP, managed, monitor, etc.
    return "unknown"

def get_ap_clients(iface):
    """Return list of dicts {mac, signal, inactive_ms} for stations on AP iface."""
    _, out, _ = run(f"iw dev {iface} station dump 2>/dev/null")
    clients = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Station "):
            if current:
                clients.append(current)
            current = {"mac": line.split()[1]}
        elif "signal:" in line:
            try: current["signal"] = line.split(":")[1].strip().split()[0]
            except: pass
        elif "inactive time:" in line:
            try: current["inactive_ms"] = int(line.split(":")[1].strip().split()[0])
            except: pass
    if current:
        clients.append(current)
    return clients

# ═══════════════════════════════════════════════════════════════════════════════
#  DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════
LOGO = (
    f"\n{C.BORDER}  ┌──────────────────────────────────┐\n"
    f"  │  {C.LIME}{C.BOLD}≫ piTail{C.RESET}{C.BORDER}  "
    f"{C.MED}WiFi Manager  v2.0{C.BORDER}  │\n"
    f"  │  {C.DARK}Kali · NetHunter · Raspberry Pi{C.BORDER}   │\n"
    f"  └──────────────────────────────────┘{C.RESET}"
)

def print_header():
    os.system("clear")
    print(LOGO)
    print()

def show_status():
    ifaces = get_wireless_ifaces()

    print(f"{C.MED}{C.BOLD}  ── Interfaces {'─' * 28}{C.RESET}")

    for iface in ifaces:
        state = iface_state(iface)
        ip    = iface_ip(iface)
        ssid  = iface_ssid(iface)
        is_active    = (iface == active_iface)
        is_protected = (iface in protected_ifaces)

        if state == "UP":
            sc = C.LIME
        elif "no link" in state:
            sc = C.WARN
        elif state == "MISSING":
            sc = C.ERR
        else:
            sc = C.DARK

        tags = ""
        if is_active:    tags += f"  {C.LIME}[ACTIVE]{C.RESET}"
        if is_protected: tags += f"  {C.DARK}[protected]{C.RESET}"

        wpa  = f"{C.DARK}wpa:{'on' if wpa_running(iface) else 'off'}{C.RESET}"
        mode = iface_mode(iface)

        print(f"  {C.WHITE}{C.BOLD}{iface:<8}{C.RESET}"
              f"  {sc}{state:<14}{C.RESET}"
              f"  {C.BORDER}IP {C.BRIGHT}{ip:<18}{C.RESET}"
              f"  {C.BORDER}SSID {C.BRIGHT}{ssid:<22}{C.RESET}"
              f"  {wpa}{tags}")

        # If interface is in AP mode, list connected clients
        if mode == "AP":
            clients = get_ap_clients(iface)
            if clients:
                for cl in clients:
                    inactive = cl.get("inactive_ms", 0)
                    inactive_s = f"{inactive // 1000}s ago"
                    sig = cl.get("signal", "?")
                    print(f"    {C.LIME}↳{C.RESET}  {C.BRIGHT}{cl['mac']}{C.RESET}"
                          f"  {C.DARK}sig {sig} dBm  last seen {inactive_s}{C.RESET}")
            else:
                print(f"    {C.DARK}↳  no clients connected{C.RESET}")

    print()
    print(f"{C.MED}{C.BOLD}  ── Connectivity {'─' * 26}{C.RESET}")

    pitail_ok   = check_pitail()
    internet_ok = check_internet()
    pub_ip      = cached("pub_ip", get_public_ip, ttl=90)

    def dot(ok_val):
        return f"{C.LIME}●{C.RESET}" if ok_val else f"{C.ERR}●{C.RESET}"

    print(f"  {dot(pitail_ok)}  {C.DARK}Pi-Tail{C.RESET}    "
          f"{PITAIL_IP:<18}  "
          f"{C.LIME+'REACHABLE'+C.RESET if pitail_ok else C.ERR+'UNREACHABLE'+C.RESET}")
    print(f"  {dot(internet_ok)}  {C.DARK}Internet{C.RESET}   "
          f"{'8.8.8.8':<18}  "
          f"{C.LIME+'ONLINE'+C.RESET if internet_ok else C.ERR+'OFFLINE'+C.RESET}")
    print(f"  {C.BORDER}◈{C.RESET}  {C.DARK}Public IP{C.RESET}  "
          f"  {C.BRIGHT}{pub_ip}{C.RESET}")

    kl_color = C.LIME if keepalive_running else C.DARK
    kl_label = "ON" if keepalive_running else "OFF"
    print(f"  {kl_color}⟳  Pi-Tail keepalive: {kl_label}{C.RESET}")

    if watchdog_target_ssid:
        print(f"\n  {C.LIME}⟳{C.RESET}  {C.DARK}Watchdog locked →{C.RESET} "
              f"{C.LIME}{watchdog_target_ssid}{C.RESET}"
              f"  {C.DARK}on {active_iface}{C.RESET}")
    print()

# ═══════════════════════════════════════════════════════════════════════════════
#  SWITCH ACTIVE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════
def switch_interface():
    global active_iface
    ifaces = get_wireless_ifaces()
    if not ifaces:
        err("No wireless interfaces detected"); pause(); return

    print(f"\n{C.MED}{C.BOLD}  ── Select Active Interface {'─' * 15}{C.RESET}\n")
    for i, iface in enumerate(ifaces, 1):
        state    = iface_state(iface)
        ssid     = iface_ssid(iface)
        cur_mark = f"  {C.LIME}← current{C.RESET}" if iface == active_iface else ""
        prot     = f"  {C.DARK}[protected]{C.RESET}" if iface in protected_ifaces else ""
        print(f"  {C.BRIGHT}{i}{C.RESET}.  {C.WHITE}{iface:<10}{C.RESET}"
              f"  {C.DARK}{state:<14}{C.RESET}"
              f"  SSID: {C.BRIGHT}{ssid}{C.RESET}"
              f"{cur_mark}{prot}")
    print()

    choice = input(f"  {C.BRIGHT}Interface number (Enter to cancel): {C.RESET}").strip()
    if not choice:
        return
    try:
        chosen = ifaces[int(choice) - 1]
        if chosen in protected_ifaces:
            warn(f"{chosen} is marked protected.")
            confirm = input(f"  {C.BRIGHT}Select it anyway? [y/N]: {C.RESET}").strip().lower()
            if confirm != 'y':
                return
        active_iface = chosen
        ok(f"Active interface → {C.WHITE}{active_iface}{C.RESET}")
        pause()
    except (ValueError, IndexError):
        err("Invalid selection"); pause()

# ═══════════════════════════════════════════════════════════════════════════════
#  INTERFACE CONTROL
# ═══════════════════════════════════════════════════════════════════════════════
def _kill_wpa(iface):
    run(f"pkill -f 'wpa_supplicant.*{iface}' 2>/dev/null")
    time.sleep(0.5)

def bring_up(iface=None):
    iface = iface or active_iface
    info(f"Bringing {iface} UP...")
    c, _, e = run(f"ip link set {iface} up")
    ok(f"{iface} is UP") if c == 0 else err(f"Failed: {e}")
    pause()

def bring_down(iface=None):
    iface = iface or active_iface
    warn(f"Bringing {iface} DOWN...")
    _kill_wpa(iface)
    run(f"dhclient -r {iface} 2>/dev/null")
    c, _, e = run(f"ip link set {iface} down")
    ok(f"{iface} is DOWN") if c == 0 else err(f"Failed: {e}")
    pause()

def disconnect_iface(iface=None):
    iface = iface or active_iface
    warn(f"Disconnecting {iface}...")
    _kill_wpa(iface)
    run(f"dhclient -r {iface} 2>/dev/null")
    ok(f"{iface} disconnected")
    pause()

# ═══════════════════════════════════════════════════════════════════════════════
#  SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
def scan_networks(iface=None):
    iface = iface or active_iface
    info(f"Scanning on {iface} ...")
    run(f"ip link set {iface} up")
    time.sleep(2)   # give adapter time to fully initialize
    # retry up to 3 times — adapter may need a moment after being brought up
    out = ""
    for attempt in range(3):
        c, out, _ = run(f"iwlist {iface} scan 2>/dev/null")
        if c == 0 and out and "ESSID" in out:
            break
        if attempt < 2:
            info(f"Scan attempt {attempt + 1} empty, retrying...")
            time.sleep(2)
    if not out or "ESSID" not in out:
        err("Scan failed or no networks found"); pause(); return []

    networks, cur = [], {}
    for line in out.split('\n'):
        line = line.strip()
        if 'Address:' in line:
            if cur.get('ssid'):
                networks.append(dict(cur))
            cur = {}
        if 'ESSID:"' in line:
            cur['ssid'] = line.split('ESSID:"')[1].rstrip('"')
        if 'Encryption key:' in line:
            cur['enc'] = 'on' in line
        if 'Signal level=' in line:
            try:
                cur['signal'] = line.split('Signal level=')[1].split()[0]
            except:
                cur['signal'] = '?'
    if cur.get('ssid'):
        networks.append(cur)

    seen, unique = set(), []
    for n in networks:
        if n['ssid'] and n['ssid'] not in seen:
            seen.add(n['ssid'])
            unique.append(n)

    if not unique:
        warn("No networks found"); pause(); return []

    current_ssid = iface_ssid(iface)
    print(f"\n  {C.MED}{C.BOLD}{'#':<4} {'SSID':<34} {'Signal':<10} Enc{C.RESET}")
    print(f"  {C.BORDER}{'─' * 56}{C.RESET}")
    for i, n in enumerate(unique, 1):
        conn  = f"  {C.LIME}← connected{C.RESET}" if n['ssid'] == current_ssid else ""
        lock  = "🔒" if n.get('enc') else "🔓"
        print(f"  {C.BRIGHT}{i:<4}{C.RESET}"
              f"{C.WHITE}{n['ssid']:<34}{C.RESET}"
              f"{C.DARK}{n.get('signal','?'):<10}{C.RESET}"
              f"{lock}{conn}")
    return unique

# ═══════════════════════════════════════════════════════════════════════════════
#  CONNECTION
# ═══════════════════════════════════════════════════════════════════════════════
def _write_wpa(iface, ssid, password):
    conf = wpa_conf(iface)
    c, out, _ = run(f"wpa_passphrase '{ssid}' '{password}'")
    if c != 0:
        out = (f'\nnetwork={{\n    ssid="{ssid}"\n'
               f'    psk="{password}"\n    priority=10\n}}\n')
    header = ("ctrl_interface=DIR=/var/run/wpa_supplicant "
              "GROUP=netdev\nupdate_config=1\n")
    with open(conf, 'w') as f:
        f.write(header + out)

def _start_wpa(iface):
    _kill_wpa(iface)
    c, _, _ = run(
        f"{WPA_SUPPLICANT} -B -i {iface} -c {wpa_conf(iface)} -P {wpa_pid(iface)}",
        timeout=10)
    return c == 0

def connect_to_network(ssid=None, password=None, iface=None, force=False):
    """
    Connect iface to ssid.
    If already connected and ssid not specified, prompt to switch.
    force=True skips the 'already connected' check (used by switch_network flow).
    """
    iface = iface or active_iface

    if not force:
        current = iface_ssid(iface)
        if current != "—" and not ssid:
            print(f"\n  {C.DARK}Currently on:{C.RESET} {C.WHITE}{current}{C.RESET}")
            choice = input(
                f"  {C.BRIGHT}Switch to a different network? [y/N]: {C.RESET}").strip().lower()
            if choice != 'y':
                return

    if not ssid:
        ssid = input(f"\n  {C.BRIGHT}SSID: {C.RESET}").strip()
    if not password:
        password = input(f"  {C.BRIGHT}Password (blank for open network): {C.RESET}").strip()

    info(f"Connecting {iface} → '{ssid}' ...")

    # Tear down existing connection first
    _kill_wpa(iface)
    run(f"dhclient -r {iface} 2>/dev/null")
    time.sleep(1)

    run(f"ip link set {iface} up")
    time.sleep(0.5)
    _write_wpa(iface, ssid, password)

    info("Starting wpa_supplicant...")
    if not _start_wpa(iface):
        err("Failed to start wpa_supplicant"); pause(); return False

    info("Waiting for association...")
    for i in range(15):
        time.sleep(1)
        _, out, _ = run(f"iwgetid {iface} --raw 2>/dev/null")
        if out == ssid:
            ok(f"Associated with '{ssid}'")
            break
        print(f"  {C.DARK}waiting... {i + 1}/15{C.RESET}", end='\r')
    else:
        err("Association timed out — check credentials"); pause(); return False

    info("Requesting IP via DHCP...")
    run(f"dhclient -r {iface} 2>/dev/null")
    time.sleep(0.5)
    run(f"dhclient -v {iface} 2>&1", timeout=20)

    ip = iface_ip(iface)
    if ip != "no IP":
        ok(f"IP: {ip}")
        last_known[iface] = {"ssid": ssid, "password": password}
        save_profile(ssid, password)
        _cache.pop("pub_ip", None)   # invalidate public IP cache
        ok("Internet confirmed") if check_internet() else warn("No internet (check routing)")
        pause()
        return True
    else:
        err("DHCP failed — no IP assigned"); pause(); return False

def switch_network():
    """Scan then let user pick a network to switch to."""
    print_header()
    networks = scan_networks()
    if not networks:
        return
    print()
    choice = input(f"  {C.BRIGHT}Number to switch to (Enter to cancel): {C.RESET}").strip()
    if not choice:
        return
    try:
        n = networks[int(choice) - 1]
        pw = ""
        if n.get('enc'):
            pw = input(f"  {C.BRIGHT}Password for '{n['ssid']}': {C.RESET}").strip()
        connect_to_network(n['ssid'], pw, force=True)
    except (ValueError, IndexError):
        err("Invalid selection"); pause()

# ═══════════════════════════════════════════════════════════════════════════════
#  SAVED PROFILES
# ═══════════════════════════════════════════════════════════════════════════════
def manage_profiles():
    while True:
        print_header()
        profiles = load_profiles()
        print(f"{C.MED}{C.BOLD}  ── Saved Profiles {'─' * 24}{C.RESET}\n")
        if not profiles:
            warn("No saved profiles")
        else:
            for i, p in enumerate(profiles, 1):
                print(f"  {C.BRIGHT}{i}{C.RESET}.  {C.WHITE}{p['ssid']}{C.RESET}")
        print(f"\n  {C.BRIGHT}c{C.RESET}.  Connect to profile")
        print(f"  {C.BRIGHT}d{C.RESET}.  Delete profile")
        print(f"  {C.BRIGHT}b{C.RESET}.  Back")
        choice = input(f"\n  {C.BRIGHT}>{C.RESET} ").strip().lower()
        if choice == 'b':
            break
        elif choice == 'c':
            if not profiles:
                warn("No profiles"); pause(); continue
            num = input("  Profile number: ").strip()
            try:
                p = profiles[int(num) - 1]
                connect_to_network(p['ssid'], p['password'])
            except:
                err("Invalid"); pause()
        elif choice == 'd':
            if not profiles:
                continue
            num = input("  Profile number to delete: ").strip()
            try:
                removed = profiles.pop(int(num) - 1)
                save_profiles(profiles)
                ok(f"Removed '{removed['ssid']}'")
                pause()
            except:
                err("Invalid"); pause()

# ═══════════════════════════════════════════════════════════════════════════════
#  WATCHDOG
# ═══════════════════════════════════════════════════════════════════════════════
def watchdog_loop():
    global watchdog_running
    while watchdog_running:
        time.sleep(WATCHDOG_INTERVAL)
        if not watchdog_running:
            break

        ip   = iface_ip(active_iface)
        ssid = iface_ssid(active_iface)

        if watchdog_target_ssid:
            if ssid != watchdog_target_ssid:
                warn(f"[watchdog] {active_iface} left '{watchdog_target_ssid}' — reconnecting...")
                for p in load_profiles():
                    if p['ssid'] == watchdog_target_ssid:
                        connect_to_network(p['ssid'], p['password'], force=True)
                        break
                else:
                    warn(f"[watchdog] No saved profile for '{watchdog_target_ssid}'")
        elif ip == "no IP" or ssid == "—":
            warn(f"[watchdog] {active_iface} lost connection — attempting reconnect...")
            profiles = load_profiles()
            if profiles:
                p = profiles[-1]
                connect_to_network(p['ssid'], p['password'], force=True)
            else:
                warn("[watchdog] No saved profiles to reconnect with")

        # Auto-recover non-active managed interfaces that dropped unexpectedly
        for iface in get_wireless_ifaces():
            if iface == active_iface or iface == PITAIL_IFACE:
                continue
            if iface_mode(iface) == "managed":
                cur_ssid = iface_ssid(iface)
                cur_ip   = iface_ip(iface)
                if (cur_ssid == "—" or cur_ip == "no IP") and iface in last_known:
                    prev = last_known[iface]
                    warn(f"[watchdog] {iface} dropped from '{prev['ssid']}' — recovering...")
                    connect_to_network(prev["ssid"], prev["password"], iface=iface, force=True)

        if not check_pitail():
            warn(f"[watchdog] Pi-Tail unreachable at {PITAIL_IP}")

def toggle_watchdog():
    global watchdog_running, watchdog_thread
    if watchdog_running:
        watchdog_running = False
        ok("Watchdog stopped")
    else:
        watchdog_running = True
        watchdog_thread = threading.Thread(target=watchdog_loop, daemon=True)
        watchdog_thread.start()
        ok(f"Watchdog started  (interval: {WATCHDOG_INTERVAL}s)")
    pause()

def set_watchdog_target():
    global watchdog_target_ssid
    print(f"\n  {C.MED}Lock watchdog to a specific SSID.{C.RESET}")
    print(f"  {C.DARK}Watchdog will reconnect if {active_iface} leaves this network.{C.RESET}\n")
    if watchdog_target_ssid:
        print(f"  Current target: {C.LIME}{watchdog_target_ssid}{C.RESET}\n")
    val = input(f"  {C.BRIGHT}SSID to lock to (blank to clear): {C.RESET}").strip()
    watchdog_target_ssid = val or None
    if watchdog_target_ssid:
        ok(f"Watchdog locked → '{watchdog_target_ssid}'")
    else:
        ok("Watchdog target cleared — will reconnect to last known network on drop")
    pause()

# ═══════════════════════════════════════════════════════════════════════════════
#  PI-TAIL HOTSPOT KEEPALIVE
# ═══════════════════════════════════════════════════════════════════════════════
def _connect_pitail_hotspot():
    """Attempt to connect PITAIL_IFACE to the Pi-Tail hotspot."""
    info(f"[keepalive] Connecting {PITAIL_IFACE} → \'{PITAIL_SSID}\'...")
    run(f"pkill -f \'wpa_supplicant.*{PITAIL_IFACE}\' 2>/dev/null")
    run(f"dhclient -r {PITAIL_IFACE} 2>/dev/null")
    time.sleep(1)
    run(f"ip link set {PITAIL_IFACE} up")
    time.sleep(1)
    _write_wpa(PITAIL_IFACE, PITAIL_SSID, PITAIL_PASS)
    if not _start_wpa(PITAIL_IFACE):
        warn(f"[keepalive] wpa_supplicant failed on {PITAIL_IFACE}")
        return False
    for _ in range(12):
        time.sleep(1)
        _, ssid, _ = run(f"iwgetid {PITAIL_IFACE} --raw 2>/dev/null")
        if ssid == PITAIL_SSID:
            run(f"dhclient -v {PITAIL_IFACE} 2>&1", timeout=20)
            ok(f"[keepalive] Connected to \'{PITAIL_SSID}\'")
            return True
    warn(f"[keepalive] Association timed out — hotspot may be off")
    return False

def keepalive_loop():
    global keepalive_running
    while keepalive_running:
        time.sleep(PITAIL_KEEPALIVE_INT)
        if not keepalive_running:
            break

        ssid  = iface_ssid(PITAIL_IFACE)
        state = iface_state(PITAIL_IFACE)

        if ssid != PITAIL_SSID or "UP" not in state:
            warn(f"[keepalive] {PITAIL_IFACE} not on \'{PITAIL_SSID}\' "
                 f"(state={state}, ssid={ssid}) — reconnecting...")
            _connect_pitail_hotspot()
            continue

        if not check_pitail():
            warn(f"[keepalive] Pi-Tail unreachable despite association — renewing DHCP...")
            run(f"dhclient -r {PITAIL_IFACE} 2>/dev/null")
            time.sleep(0.5)
            run(f"dhclient -v {PITAIL_IFACE} 2>&1", timeout=20)
            if not check_pitail():
                warn(f"[keepalive] Still unreachable — attempting full reconnect...")
                _connect_pitail_hotspot()

def toggle_keepalive():
    global keepalive_running, keepalive_thread
    if keepalive_running:
        keepalive_running = False
        ok("Pi-Tail keepalive stopped")
    else:
        keepalive_running = True
        keepalive_thread = threading.Thread(target=keepalive_loop, daemon=True)
        keepalive_thread.start()
        ok(f"Pi-Tail keepalive started  (SSID: {PITAIL_SSID} | every {PITAIL_KEEPALIVE_INT}s)")
        info(f"Will reconnect {PITAIL_IFACE} to hotspot whenever connection drops")
    pause()

def configure_keepalive():
    global PITAIL_SSID, PITAIL_PASS, PITAIL_IFACE, PITAIL_KEEPALIVE_INT
    print(f"\n{C.MED}{C.BOLD}  ── Pi-Tail Keepalive Config {'─' * 14}{C.RESET}\n")
    print(f"  {C.DARK}Current settings:{C.RESET}")
    print(f"    Interface : {C.WHITE}{PITAIL_IFACE}{C.RESET}")
    print(f"    SSID      : {C.WHITE}{PITAIL_SSID}{C.RESET}")
    print(f"    Password  : {C.WHITE}{PITAIL_PASS}{C.RESET}")
    print(f"    Interval  : {C.WHITE}{PITAIL_KEEPALIVE_INT}s{C.RESET}\n")
    print(f"  {C.DARK}Leave blank to keep current value.{C.RESET}\n")
    v = input(f"  {C.BRIGHT}Interface [{PITAIL_IFACE}]: {C.RESET}").strip()
    if v: PITAIL_IFACE = v
    v = input(f"  {C.BRIGHT}Hotspot SSID [{PITAIL_SSID}]: {C.RESET}").strip()
    if v: PITAIL_SSID = v
    v = input(f"  {C.BRIGHT}Hotspot Password [{PITAIL_PASS}]: {C.RESET}").strip()
    if v: PITAIL_PASS = v
    v = input(f"  {C.BRIGHT}Check interval in seconds [{PITAIL_KEEPALIVE_INT}]: {C.RESET}").strip()
    if v:
        try: PITAIL_KEEPALIVE_INT = int(v)
        except: warn("Invalid interval, keeping current")
    ok("Keepalive config updated")
    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    global active_iface
    ensure_dirs()
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    # Auto-select first non-protected interface if default not present
    ifaces = get_wireless_ifaces()
    if active_iface not in ifaces:
        candidates = [i for i in ifaces if i not in protected_ifaces]
        if candidates:
            active_iface = candidates[0]

    while True:
        print_header()
        show_status()

        wd_on  = watchdog_running
        wd_lbl = (f"{C.LIME}ON{C.RESET}" if wd_on else f"{C.DARK}OFF{C.RESET}")
        tgt    = (f"  {C.LIME}→ {watchdog_target_ssid}{C.RESET}"
                  if watchdog_target_ssid else "")

        print(f"{C.MED}{C.BOLD}  ── Active: {C.WHITE}{active_iface}"
              f"{C.MED} {'─' * 27}{C.RESET}")
        print()
        print(f"  {C.BRIGHT}1{C.RESET}.  Bring {active_iface} UP")
        print(f"  {C.BRIGHT}2{C.RESET}.  Bring {active_iface} DOWN")
        print(f"  {C.BRIGHT}3{C.RESET}.  Scan networks")
        print(f"  {C.BRIGHT}4{C.RESET}.  Scan & connect")
        print(f"  {C.BRIGHT}5{C.RESET}.  Connect manually {C.DARK}(enter SSID/pass){C.RESET}")
        print(f"  {C.BRIGHT}6{C.RESET}.  Switch network   {C.DARK}(disconnect & pick new){C.RESET}")
        print(f"  {C.BRIGHT}7{C.RESET}.  Disconnect {active_iface}")
        print(f"  {C.BRIGHT}8{C.RESET}.  Saved profiles")
        print(f"  {C.BRIGHT}9{C.RESET}.  Watchdog [{wd_lbl}]{tgt}")
        print(f"  {C.BRIGHT}t{C.RESET}.  Set watchdog target SSID")
        kl_on = keepalive_running
        kl_lbl = C.LIME + "ON" + C.RESET if kl_on else C.DARK + "OFF" + C.RESET
        print(f"  {C.BRIGHT}k{C.RESET}.  Pi-Tail keepalive [{kl_lbl}]")
        print(f"  {C.BRIGHT}K{C.RESET}.  Configure keepalive  {C.DARK}(SSID / password / interval){C.RESET}")
        print(f"  {C.BRIGHT}i{C.RESET}.  Switch active interface"
              f"  {C.DARK}(now: {active_iface}){C.RESET}")
        print(f"  {C.BRIGHT}r{C.RESET}.  Refresh")
        print(f"  {C.BRIGHT}0{C.RESET}.  Exit")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()

        if   choice == '1': bring_up()
        elif choice == '2': bring_down()
        elif choice == '3':
            print_header()
            scan_networks()
            pause()
        elif choice == '4': scan_and_connect_flow()
        elif choice == '5': connect_to_network()
        elif choice == '6': switch_network()
        elif choice == '7': disconnect_iface()
        elif choice == '8': manage_profiles()
        elif choice == '9': toggle_watchdog()
        elif choice == 't': set_watchdog_target()
        elif choice == 'i': switch_interface()
        elif choice == 'k': toggle_keepalive()
        elif choice == 'K': configure_keepalive()
        elif choice == 'r': continue
        elif choice == '0':
            info("Goodbye.")
            sys.exit(0)

def scan_and_connect_flow():
    """Scan then connect — separated from switch_network for menu clarity."""
    print_header()
    networks = scan_networks()
    if not networks:
        return
    print()
    choice = input(f"  {C.BRIGHT}Number to connect (Enter to cancel): {C.RESET}").strip()
    if not choice:
        return
    try:
        n = networks[int(choice) - 1]
        pw = ""
        if n.get('enc'):
            pw = input(f"  {C.BRIGHT}Password for '{n['ssid']}': {C.RESET}").strip()
        connect_to_network(n['ssid'], pw)
    except (ValueError, IndexError):
        err("Invalid selection"); pause()

# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"\033[91mRun as root: sudo python3 pitail.py\033[0m")
        sys.exit(1)
    main()
