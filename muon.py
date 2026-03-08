#!/usr/bin/env python3
"""
Muon – WiFi Manager v2
Multi-interface management for NetHunter / Kali on Raspberry Pi and Android.
Also runs in limited mode on non-rooted Android via Termux:API.
"""

import os
import sys
import subprocess
import time
import json
import re
import datetime
import threading
import signal
import getpass
import tty
import termios
import select
import readline

# ═══════════════════════════════════════════════════════════════════════════════
#  ROOT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
IS_ROOT = os.geteuid() == 0

# ═══════════════════════════════════════════════════════════════════════════════
#  HARDWARE & OS DETECTION
#  Detected once at startup; displayed in header and used for hints/warnings.
# ═══════════════════════════════════════════════════════════════════════════════
def _detect_platform():
    """Return (hw_tag, os_tag, sudo_hint) strings describing this device.

    hw_tag  — e.g. 'Raspberry Pi 4B', 'Nexus 5 (NetHunter)', 'Generic ARM', ...
    os_tag  — e.g. 'Kali Linux ARM', 'Kali NetHunter', 'Termux (Android)', ...
    sudo_hint — non-empty string if the user should re-launch with sudo
    """
    hw_tag = ''
    os_tag = ''
    sudo_hint = ''

    # ── Hardware ─────────────────────────────────────────────────────────────
    # Raspberry Pi: /proc/device-tree/model or /proc/cpuinfo Model line
    model = ''
    try:
        with open('/proc/device-tree/model', 'r') as f:
            model = f.read().rstrip('\x00').strip()
    except OSError:
        pass
    if not model:
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.lower().startswith('model') and ':' in line:
                        model = line.split(':', 1)[1].strip()
                        break
        except OSError:
            pass

    if 'raspberry pi' in model.lower():
        hw_tag = model  # e.g. "Raspberry Pi 4 Model B Rev 1.4"
    else:
        # Generic ARM vs x86 detection
        machine = os.uname().machine if hasattr(os, 'uname') else ''
        if machine.startswith('aarch64') or machine.startswith('armv'):
            hw_tag = f'ARM ({machine})'
        elif machine in ('x86_64', 'amd64'):
            hw_tag = f'x86_64'
        elif machine:
            hw_tag = machine

    # ── OS / distro ──────────────────────────────────────────────────────────
    # Check for Termux (Android, non-rooted)
    if 'com.termux' in os.environ.get('PREFIX', '') or \
       os.path.isdir('/data/data/com.termux'):
        os_tag = 'Termux (Android)'
    else:
        # Read /etc/os-release
        osrel = {}
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        osrel[k] = v.strip('"\'')
        except OSError:
            pass

        distro   = osrel.get('ID', '').lower()
        variant  = osrel.get('VARIANT_ID', '').lower()
        pretty   = osrel.get('PRETTY_NAME', '')

        if 'nethunter' in pretty.lower() or variant == 'nethunter':
            os_tag = 'Kali NetHunter'
        elif distro == 'kali':
            machine = os.uname().machine if hasattr(os, 'uname') else ''
            if machine.startswith('aarch64') or machine.startswith('armv'):
                os_tag = 'Kali Linux ARM'
            else:
                os_tag = 'Kali Linux'
        elif pretty:
            os_tag = pretty
        elif distro:
            os_tag = distro.capitalize()

    # ── sudo hint ────────────────────────────────────────────────────────────
    if not IS_ROOT and os_tag not in ('Termux (Android)',):
        sudo_hint = 'run with sudo for full functionality'

    return hw_tag, os_tag, sudo_hint


_HW_TAG, _OS_TAG, _SUDO_HINT = _detect_platform()

# ═══════════════════════════════════════════════════════════════════════════════
#  PATHS & CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
CONFIG_DIR     = os.path.expanduser("~/.muon")
PROFILES_FILE  = os.path.join(CONFIG_DIR, "profiles.json")
PROJECTS_DIR   = os.path.join(CONFIG_DIR, "projects")
WPA_SUPPLICANT = "/usr/sbin/wpa_supplicant"
PITAIL_IP      = "192.168.43.254"
WATCHDOG_INTERVAL = 30

# ═══════════════════════════════════════════════════════════════════════════════
#  COLORS  — all-green theme, black terminal background
#  LIME    brightest  → for UP/connected/OK
#  BRIGHT  light      → menu numbers, prompts
#  MED     teal-green → section headers
#  BORDER  medium     → box lines, dividers
#  DARK    forest     → dim/secondary labels, grayed-out menu items
# ═══════════════════════════════════════════════════════════════════════════════
class C:
    LIME   = '\033[38;5;118m'
    BRIGHT = '\033[38;5;82m'
    MED    = '\033[38;5;35m'
    BORDER = '\033[38;5;28m'
    DARK   = '\033[38;5;29m'
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
PITAIL_SSID          = "sepultura"     # Pi-Tail project default hotspot SSID (public default)
PITAIL_PASS          = "R4t4m4h4tt4"  # Pi-Tail project default hotspot password (public default)
PITAIL_KEEPALIVE_INT = 20          # seconds between keepalive checks
keepalive_running    = False
keepalive_thread     = None

# Last known connection per interface — used for auto-recovery
last_known = {}      # { "wlan1": {"ssid": "...", "password": "..."}, ... }

_cache               = {}          # simple TTL cache for slow queries

# Command reference — user-settable variables substituted into commands
CMD_VARS = {
    'IFACE':   'wlan1',
    'IFACE2':  'wlan0',
    'GATEWAY': '192.168.1.1',
    'SSID':    '',
    'IP':      '192.168.1.100',
    'PORT':    '8080',
    'BSSID':   '',        # Target AP MAC  e.g. AA:BB:CC:DD:EE:FF
    'CHANNEL': '6',       # WiFi channel for targeted capture
    'IFACE_MON': 'wlan1mon',  # Monitor interface — auto-updated when monitor mode is enabled
    'WORDLIST': '/usr/share/wordlists/rockyou.txt',  # Default wordlist for cracking / wifite
}

# Current operating mode — configures the app for a specific use case
CURRENT_MODE = None    # None | 'pitail' | 'nethunter' | 'rpi' | 'pentest'

MODE_DEFS = {
    'pitail': {
        'name': 'Pi-Tail',
        'desc': 'Raspberry Pi Zero as WiFi bridge / hotspot',
    },
    'nethunter': {
        'name': 'NetHunter',
        'desc': 'External adapter for monitor mode and packet injection',
    },
    'rpi': {
        'name': 'Raspberry Pi AP',
        'desc': 'Raspberry Pi as access point or network bridge',
    },
    'pentest': {
        'name': 'Pentest',
        'desc': 'Pi-Tail bridge + external adapter for wireless auditing',
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
#  DRIVER DATABASE
#  USB vendor:product → chip name, adapter examples, module, install options
#  ★  monitor=True  →  adapter supports monitor mode & packet injection
#  apt              →  install via: apt install -y <package>
#  git + git_build  →  install via: git clone … && make && make dkms_install
#  note             →  kernel built-in — no external driver needed
# ═══════════════════════════════════════════════════════════════════════════════
DRIVER_DB = {
    # ── Realtek RTL88xxAU (AC1200–AC1900, dual-band, ★ monitor mode) ──────────
    '0bda:8812': {'chip':'RTL8812AU', 'adapter':'Alfa AWUS036ACH · AWUS036EAC · various AC1200',
                  'module':'88XXau',  'monitor':True,
                  'apt':'realtek-rtl88xxau-dkms',
                  'git':'https://github.com/aircrack-ng/rtl8812au',
                  'git_build':'make && make dkms_install'},
    '0bda:8821': {'chip':'RTL8821AU', 'adapter':'Various AC600 adapters',
                  'module':'88XXau',  'monitor':True,
                  'apt':'realtek-rtl88xxau-dkms',
                  'git':'https://github.com/aircrack-ng/rtl8812au',
                  'git_build':'make && make dkms_install'},
    '0bda:881a': {'chip':'RTL8821AU', 'adapter':'Various AC600 adapters (alt ID)',
                  'module':'88XXau',  'monitor':True,
                  'apt':'realtek-rtl88xxau-dkms',
                  'git':'https://github.com/aircrack-ng/rtl8812au',
                  'git_build':'make && make dkms_install'},
    '0bda:8813': {'chip':'RTL8813AU', 'adapter':'Various AC1900 adapters',
                  'module':'88XXau',  'monitor':True,
                  'apt':'realtek-rtl88xxau-dkms',
                  'git':'https://github.com/aircrack-ng/rtl8812au',
                  'git_build':'make && make dkms_install'},
    '0bda:8814': {'chip':'RTL8814AU', 'adapter':'Alfa AWUS1900 (AC1900 4x4 MIMO)',
                  'module':'8814au',  'monitor':True,
                  'apt':'realtek-rtl88xxau-dkms',
                  'git':'https://github.com/morrownr/8814au',
                  'git_build':'make && make dkms_install'},
    # ── RTL8812BU / RTL8822BU ──────────────────────────────────────────────────
    '0bda:b812': {'chip':'RTL8812BU', 'adapter':'Alfa AWUS036ACU · various AC1200',
                  'module':'88x2bu',  'monitor':True,
                  'apt':'realtek-rtl88x2bu-dkms',
                  'git':'https://github.com/morrownr/88x2bu-20210702',
                  'git_build':'make && make dkms_install'},
    '0bda:b822': {'chip':'RTL8822BU', 'adapter':'Various AC1200 adapters',
                  'module':'88x2bu',  'monitor':True,
                  'apt':'realtek-rtl88x2bu-dkms',
                  'git':'https://github.com/morrownr/88x2bu-20210702',
                  'git_build':'make && make dkms_install'},
    # ── RTL8821CU / RTL8811CU ──────────────────────────────────────────────────
    '0bda:c811': {'chip':'RTL8811CU', 'adapter':'Various AC600 adapters',
                  'module':'8821cu',  'monitor':True,
                  'apt':'realtek-rtl8821cu-dkms',
                  'git':'https://github.com/morrownr/8821cu-20210916',
                  'git_build':'make && make dkms_install'},
    '0bda:c821': {'chip':'RTL8821CU', 'adapter':'Alfa AWUS036ACM · various AC600',
                  'module':'8821cu',  'monitor':True,
                  'apt':'realtek-rtl8821cu-dkms',
                  'git':'https://github.com/morrownr/8821cu-20210916',
                  'git_build':'make && make dkms_install'},
    # ── RTL8852BU (Wi-Fi 6 / AX) ───────────────────────────────────────────────
    '0bda:b85b': {'chip':'RTL8852BU', 'adapter':'Various AX1800 Wi-Fi 6 adapters',
                  'module':'8852bu',  'monitor':False,
                  'apt':None,
                  'git':'https://github.com/morrownr/rtl8852bu',
                  'git_build':'make && make dkms_install'},
    # ── RTL8188EUS / RTL8188FU ─────────────────────────────────────────────────
    '0bda:8179': {'chip':'RTL8188EUS', 'adapter':'TP-Link TL-WN722N v2/v3 · various N150',
                  'module':'8188eu',  'monitor':True,
                  'apt':'realtek-rtl8188eus-dkms',
                  'git':'https://github.com/aircrack-ng/rtl8188eus',
                  'git_build':'make && make dkms_install'},
    '0bda:0179': {'chip':'RTL8188ETV', 'adapter':'Various N150 TV adapters',
                  'module':'8188eu',  'monitor':True,
                  'apt':'realtek-rtl8188eus-dkms',
                  'git':'https://github.com/aircrack-ng/rtl8188eus',
                  'git_build':'make && make dkms_install'},
    '0bda:f179': {'chip':'RTL8188FU',  'adapter':'Various N150 adapters',
                  'module':'8188fu',  'monitor':False,
                  'apt':None,
                  'git':'https://github.com/kelebek333/rtl8188fu',
                  'git_build':'make && make dkms_install'},
    # ── RTL8192EU ───────────────────────────────────────────────────────────────
    '0bda:818b': {'chip':'RTL8192EU',  'adapter':'TP-Link TL-WN821N v6 · various N300',
                  'module':'8192eu',  'monitor':True,
                  'apt':None,
                  'git':'https://github.com/clnhub/rtl8192eu-linux',
                  'git_build':'make && make dkms_install'},
    # ── RTL8723BU ───────────────────────────────────────────────────────────────
    '0bda:b720': {'chip':'RTL8723BU',  'adapter':'Various BT+WiFi N150 combo adapters',
                  'module':'8723bu',  'monitor':False,
                  'apt':None,
                  'git':'https://github.com/lwfinger/rtl8723bu',
                  'git_build':'make && make dkms_install'},
    # ── RTL8187L (kernel built-in) ───────────────────────────────────────────────
    '0bda:8187': {'chip':'RTL8187L',   'adapter':'Alfa AWUS036H (classic pentest card)',
                  'module':'rtl8187', 'monitor':True,
                  'apt':None, 'git':None,
                  'note':'Built into kernel. Load: modprobe rtl8187'},
    # ── MediaTek / Ralink ────────────────────────────────────────────────────────
    '148f:7601': {'chip':'MT7601U',  'adapter':'Various N150 adapters (very common)',
                  'module':'mt7601u', 'monitor':False,
                  'apt':None, 'git':None,
                  'note':'Built into kernel — auto-loads on plug-in'},
    '148f:761a': {'chip':'MT7610U',  'adapter':'Various AC600 adapters',
                  'module':'mt76x0u', 'monitor':False,
                  'apt':None, 'git':None,
                  'note':'Built into kernel. Load: modprobe mt76x0u'},
    '148f:7612': {'chip':'MT7612U',  'adapter':'Alfa AWUS036ACM · various AC1200',
                  'module':'mt76x2u', 'monitor':True,
                  'apt':None, 'git':None,
                  'note':'Built into kernel. Load: modprobe mt76x2u'},
    '0e8d:7961': {'chip':'MT7961U',  'adapter':'Various AX Wi-Fi 6 adapters',
                  'module':'mt7921u', 'monitor':False,
                  'apt':None, 'git':None,
                  'note':'Built into kernel. Load: modprobe mt7921u'},
    '148f:7922': {'chip':'MT7922',   'adapter':'Various AX Wi-Fi 6 adapters (alt ID)',
                  'module':'mt7921u', 'monitor':False,
                  'apt':None, 'git':None,
                  'note':'Built into kernel. Load: modprobe mt7921u'},
    '148f:5370': {'chip':'RT5370',   'adapter':'Various N150 adapters (very common)',
                  'module':'rt2800usb', 'monitor':True,
                  'apt':None, 'git':None,
                  'note':'Built into kernel — auto-loads on plug-in'},
    '148f:3070': {'chip':'RT3070',   'adapter':'Various N150 adapters',
                  'module':'rt2800usb', 'monitor':True,
                  'apt':None, 'git':None,
                  'note':'Built into kernel — auto-loads on plug-in'},
    '148f:5572': {'chip':'RT5572',   'adapter':'Various N300 dual-band adapters',
                  'module':'rt2800usb', 'monitor':True,
                  'apt':None, 'git':None,
                  'note':'Built into kernel — auto-loads on plug-in'},
    '148f:2573': {'chip':'RT2573',   'adapter':'Various N adapters',
                  'module':'rt73usb', 'monitor':True,
                  'apt':None, 'git':None,
                  'note':'Built into kernel — auto-loads on plug-in'},
    # ── Atheros ─────────────────────────────────────────────────────────────────
    '0cf3:9271': {'chip':'AR9271',   'adapter':'Alfa AWUS036NHA · TP-Link TL-WN722N v1',
                  'module':'ath9k_htc', 'monitor':True,
                  'apt':'firmware-atheros', 'git':None,
                  'note':'Kernel module built-in; also needs: apt install firmware-atheros'},
    '0cf3:7015': {'chip':'AR9715',   'adapter':'Various Atheros AR9715 adapters',
                  'module':'ath9k_htc', 'monitor':True,
                  'apt':'firmware-atheros', 'git':None,
                  'note':'Kernel module built-in; also needs: apt install firmware-atheros'},
    '0cf3:1006': {'chip':'AR9271',   'adapter':'Various Atheros adapters (alt USB ID)',
                  'module':'ath9k_htc', 'monitor':True,
                  'apt':'firmware-atheros', 'git':None,
                  'note':'Kernel module built-in; also needs: apt install firmware-atheros'},
}

# Browse screen — ordered groups (label, [usb_id, ...])
DRIVER_GROUPS = [
    ('Realtek AC  RTL8812/8814/8822  dual-band, monitor mode',
     ['0bda:8812','0bda:8821','0bda:881a','0bda:8813','0bda:8814',
      '0bda:b812','0bda:b822']),
    ('Realtek AC  RTL8821/8811/8852  AC600 / Wi-Fi 6',
     ['0bda:c811','0bda:c821','0bda:b85b']),
    ('Realtek N   RTL8188/8192/8723/8187  2.4 GHz',
     ['0bda:8179','0bda:0179','0bda:f179','0bda:818b','0bda:b720','0bda:8187']),
    ('MediaTek / Ralink  MT7xxx / RT5xxx',
     ['148f:7601','148f:761a','148f:7612','0e8d:7961','148f:7922',
      '148f:5370','148f:3070','148f:5572','148f:2573']),
    ('Atheros  AR9xxx',
     ['0cf3:9271','0cf3:7015','0cf3:1006']),
]

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

def _lsusb_wifi_adapters():
    """Parse lsusb output; return [(usb_id, full_line)] for recognised WiFi chips."""
    rc, out, _ = run("lsusb")
    matches = []
    if rc != 0 or not out:
        return matches
    for line in out.splitlines():
        idx = line.find(' ID ')
        if idx == -1:
            continue
        uid_raw = line[idx + 4: idx + 13]       # 'XXXX:XXXX'
        if len(uid_raw) == 9 and uid_raw[4] == ':':
            uid = uid_raw.lower()
            if uid in DRIVER_DB:
                matches.append((uid, line.strip()))
    return matches

def _module_loaded(module_name):
    """Return True if the named kernel module appears in lsmod output."""
    if not module_name:
        return False
    rc, out, _ = run("lsmod")
    if rc != 0:
        return False
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].lower() == module_name.lower():
            return True
    return False

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
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)                    # owner-only: no other user can read
    if not os.path.exists(PROFILES_FILE):
        with open(PROFILES_FILE, 'w') as f:
            json.dump([], f)
    os.chmod(PROFILES_FILE, 0o600)                 # owner-only: passwords protected at rest

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

# ─── Project save / load ──────────────────────────────────────────────────────

def _project_filename(name):
    """Derive a safe filename from a project name."""
    safe = re.sub(r'[^a-zA-Z0-9_\-. ]', '', name).strip().replace(' ', '_')
    return (safe or 'project') + '.json'

def _list_projects():
    """Return list of saved project dicts (newest first). Each dict has a '_path' key."""
    projects = []
    try:
        for fn in os.listdir(PROJECTS_DIR):
            if fn.endswith('.json'):
                fp = os.path.join(PROJECTS_DIR, fn)
                try:
                    with open(fp) as f:
                        proj = json.load(f)
                    proj['_path'] = fp
                    projects.append(proj)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return sorted(projects, key=lambda p: p.get('saved', ''), reverse=True)

def _save_project(name):
    """Snapshot the current session state to a named project file."""
    data = {
        'name':         name,
        'saved':        datetime.datetime.now().isoformat(timespec='seconds'),
        'active_iface': active_iface,
        'cmd_vars':     dict(CMD_VARS),
        'mode':         CURRENT_MODE,
        'pitail': {
            'iface':    PITAIL_IFACE,
            'ssid':     PITAIL_SSID,
            'pass':     PITAIL_PASS,
            'interval': PITAIL_KEEPALIVE_INT,
        },
        'watchdog': {
            'target_ssid': watchdog_target_ssid,
            'interval':    WATCHDOG_INTERVAL,
        },
    }
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    path = os.path.join(PROJECTS_DIR, _project_filename(name))
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)
    ok(f"Project saved: '{name}'")
    return path

def _load_project(proj):
    """Restore session state from a saved project dict."""
    global active_iface, CURRENT_MODE
    global PITAIL_IFACE, PITAIL_SSID, PITAIL_PASS, PITAIL_KEEPALIVE_INT
    global watchdog_target_ssid, WATCHDOG_INTERVAL

    # Restore CMD_VARS — update existing keys only (preserves any new keys added later)
    for k, v in proj.get('cmd_vars', {}).items():
        if k in CMD_VARS:
            CMD_VARS[k] = v

    # Restore active interface
    iface = proj.get('active_iface')
    if iface:
        active_iface        = iface
        CMD_VARS['IFACE']   = iface

    # Restore operating mode
    mode = proj.get('mode')
    if mode and mode in MODE_DEFS:
        CURRENT_MODE = mode

    # Restore Pi-Tail config
    pt = proj.get('pitail', {})
    if pt.get('iface'):    PITAIL_IFACE         = pt['iface']
    if pt.get('ssid'):     PITAIL_SSID          = pt['ssid']
    if pt.get('pass'):     PITAIL_PASS          = pt['pass']
    if pt.get('interval'): PITAIL_KEEPALIVE_INT = int(pt['interval'])

    # Restore watchdog config
    wd = proj.get('watchdog', {})
    if wd.get('target_ssid'): watchdog_target_ssid = wd['target_ssid']
    if wd.get('interval'):    WATCHDOG_INTERVAL    = int(wd['interval'])

    print()
    ok(f"Project loaded:  '{proj['name']}'  (saved {proj.get('saved', '?')[:16]})")
    print()
    print(f"  {C.BORDER}Interface  {C.BRIGHT}{active_iface}{C.RESET}")
    print(f"  {C.BORDER}Mode       {C.BRIGHT}{CURRENT_MODE or '—'}{C.RESET}")
    print(f"  {C.BORDER}SSID       {C.BRIGHT}{CMD_VARS.get('SSID')  or '(none)'}{C.RESET}")
    print(f"  {C.BORDER}BSSID      {C.BRIGHT}{CMD_VARS.get('BSSID') or '(none)'}{C.RESET}")
    print(f"  {C.BORDER}CHANNEL    {C.BRIGHT}{CMD_VARS.get('CHANNEL', '?')}{C.RESET}")
    print(f"  {C.BORDER}IFACE_MON  {C.BRIGHT}{CMD_VARS.get('IFACE_MON', '?')}{C.RESET}")
    print()

    # Offer to bring the adapter up
    if IS_ROOT:
        print(f"  {C.DARK}Note: re-enable monitor mode manually if it was active.{C.RESET}")
        v = input(f"  {C.BRIGHT}Bring {active_iface} UP now? [y/N]: {C.RESET}").strip().lower()
        if v == 'y':
            rc, _, _ = run(f"ip link set {active_iface} up")
            if rc == 0:
                ok(f"{active_iface} is UP")
            else:
                warn(f"Could not bring {active_iface} up — check adapter is connected")


def requires_root():
    """Called when a grayed-out root-only option is selected in limited mode."""
    print(f"\n  {C.WARN}[!]{C.RESET}  {C.WHITE}This feature requires root access.{C.RESET}")
    print(f"       {C.DARK}Run on a rooted device (Kali NetHunter) for full functionality.{C.RESET}")
    pause()

def _menu_item(key, label, available=True):
    """Print a menu item. Grays out the entire line if not available."""
    if available:
        print(f"  {C.BRIGHT}{key}{C.RESET}.  {label}")
    else:
        print(f"  {C.DARK}{key}.  {label}  [root only]{C.RESET}")

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

def iface_mac(iface):
    _, out, _ = run(f"ip link show {iface} 2>/dev/null")
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('link/ether'):
            return line.split()[1]
    return "—"

def iface_gateway(iface):
    _, out, _ = run(f"ip route show dev {iface} 2>/dev/null")
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == 'default' and 'via' in parts:
            idx = parts.index('via')
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return "—"

def iface_signal(iface):
    _, out, _ = run(f"iwconfig {iface} 2>/dev/null")
    m = re.search(r'Signal level[=:](-?\d+)', out)
    return f"{m.group(1)} dBm" if m else "—"

def _humanize_bytes(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n} {unit}" if unit == 'B' else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def iface_txrx(iface):
    _, out, _ = run(f"ip -s link show {iface} 2>/dev/null")
    lines = out.splitlines()
    rx = tx = "—"
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('RX:') and i + 1 < len(lines):
            parts = lines[i + 1].split()
            if parts:
                rx = _humanize_bytes(parts[0])
        elif stripped.startswith('TX:') and i + 1 < len(lines):
            parts = lines[i + 1].split()
            if parts:
                tx = _humanize_bytes(parts[0])
    return rx, tx

def system_dns():
    _, out, _ = run("grep '^nameserver' /etc/resolv.conf 2>/dev/null")
    servers = [line.split()[1] for line in out.splitlines()
               if line.startswith('nameserver') and len(line.split()) >= 2]
    return '  '.join(servers[:3]) if servers else "—"

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
#  LIMITED MODE — Termux:API helpers (non-rooted Android)
# ═══════════════════════════════════════════════════════════════════════════════
def termux_wifi_info():
    """Return parsed dict from termux-wifi-connectioninfo, or None on failure."""
    c, out, _ = run("termux-wifi-connectioninfo 2>/dev/null", timeout=6)
    if c != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None

def termux_wifi_scan():
    """Return list of network dicts from termux-wifi-scaninfo, or None on failure."""
    c, out, _ = run("termux-wifi-scaninfo 2>/dev/null", timeout=10)
    if c != 0 or not out:
        return None   # None = command not available; [] = available but empty
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None

# ═══════════════════════════════════════════════════════════════════════════════
#  DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════
LOGO = (
    f"\n{C.LIME}{C.BOLD}"
    f"  _______ _______  ______________\n"
    f"  __  __ `__ \\  / / /  __ \\_  __ \\\n"
    f"  _  / / / / / /_/ // /_/ /  / / /\n"
    f"  /_/ /_/ /_/\\__,_/ \\____//_/ /_/\n"
    f"{C.RESET}"
)

def print_header():
    os.system("clear")
    print(LOGO)

    # ── hardware / OS tag line ────────────────────────────────────────────────
    hw_parts = []
    if _HW_TAG:
        hw_parts.append(f"{C.MED}{_HW_TAG}{C.RESET}")
    if _OS_TAG:
        hw_parts.append(f"{C.MED}{_OS_TAG}{C.RESET}")
    if hw_parts:
        print(f"  {C.BORDER}┄{C.RESET}  {'  ·  '.join(hw_parts)}")

    # ── mode / root / sudo tags ───────────────────────────────────────────────
    tags = []
    if not IS_ROOT:
        tags.append(f"{C.WARN}[limited mode]{C.RESET}")
        if _SUDO_HINT:
            tags.append(f"{C.DARK}({_SUDO_HINT}){C.RESET}")
    if CURRENT_MODE:
        tags.append(f"{C.LIME}[{MODE_DEFS[CURRENT_MODE]['name']} mode]{C.RESET}")
    if tags:
        print(f"  {'  '.join(tags)}")

    print()

def show_status_limited():
    """Status display for non-rooted Android using Termux:API."""
    print(f"{C.MED}{C.BOLD}  ── Connection {'─' * 28}{C.RESET}")

    wifi = termux_wifi_info()
    if wifi:
        ssid  = wifi.get('ssid', '—').strip('"')
        ip    = wifi.get('ip', 'no IP')
        rssi  = wifi.get('rssi', '?')
        speed = wifi.get('link_speed_mbps', '?')
        sc    = C.LIME if ip not in ('no IP', '', None) else C.WARN
        print(f"  {C.WHITE}{C.BOLD}{'wlan0':<8}{C.RESET}"
              f"  {sc}{'CONNECTED':<14}{C.RESET}"
              f"  {C.BORDER}IP {C.BRIGHT}{ip:<18}{C.RESET}"
              f"  {C.BORDER}SSID {C.BRIGHT}{ssid:<22}{C.RESET}"
              f"  {C.DARK}sig {rssi} dBm  {speed} Mbps{C.RESET}")
    else:
        print(f"  {C.WARN}  Termux:API not found — WiFi info unavailable{C.RESET}")
        print(f"  {C.DARK}  Termux:API is required for WiFi status and scanning.{C.RESET}")
        print(f"  {C.DARK}  Setup:{C.RESET}")
        print(f"  {C.DARK}    1. Install the Termux:API app from F-Droid (not Play Store){C.RESET}")
        print(f"  {C.DARK}       https://f-droid.org/packages/com.termux.api/{C.RESET}")
        print(f"  {C.DARK}    2. In Termux, run: pkg install termux-api{C.RESET}")

    print()
    print(f"{C.MED}{C.BOLD}  ── Connectivity {'─' * 26}{C.RESET}")

    internet_ok = check_internet()
    pub_ip      = cached("pub_ip", get_public_ip, ttl=90)

    def dot(ok_val):
        return f"{C.LIME}●{C.RESET}" if ok_val else f"{C.ERR}●{C.RESET}"

    print(f"  {dot(internet_ok)}  {C.DARK}Internet{C.RESET}   "
          f"{'8.8.8.8':<18}  "
          f"{C.LIME+'ONLINE'+C.RESET if internet_ok else C.ERR+'OFFLINE'+C.RESET}")
    print(f"  {C.BORDER}◈{C.RESET}  {C.DARK}Public IP{C.RESET}  "
          f"  {C.BRIGHT}{pub_ip}{C.RESET}")
    print()

# ─── Box rendering ───────────────────────────────────────────────────────────
# Each box is _BO chars wide visually:  │ + sp + _BI content + sp + │
# Two boxes side-by-side + 1-char indent + 2-char gap = 1+_BO+2+_BO = 79 cols
_ANSI_ESC = re.compile(r'\033\[[0-9;]*m')

def _vis_len(s):
    """Visual (printed) length of s, ignoring ANSI escape codes."""
    return len(_ANSI_ESC.sub('', s))

def _iface_uptime(iface):
    """How long this interface has been in its current operstate.
    Uses the mtime of /sys/class/net/<iface>/operstate — updated by the
    kernel each time the interface changes state."""
    try:
        mtime   = os.path.getmtime(f'/sys/class/net/{iface}/operstate')
        elapsed = int(time.time() - mtime)
        if elapsed < 60:
            return f'{elapsed}s'
        elif elapsed < 3600:
            return f'{elapsed // 60}m {elapsed % 60}s'
        else:
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            return f'{h}h {m}m'
    except OSError:
        return '—'

_BI = 34           # inner usable width (visual chars between the │ borders)
_BO = _BI + 4      # outer visual width: │ + sp + _BI + sp + │

def _bl(content=''):
    """One content line inside a box, padded to _BO visual chars."""
    pad = ' ' * max(0, _BI - _vis_len(content))
    return f"{C.LIME}│{C.RESET} {content}{pad} {C.LIME}│{C.RESET}"

def _bt():
    return f"{C.LIME}┌{'─' * (_BI + 2)}┐{C.RESET}"

def _bb():
    return f"{C.LIME}└{'─' * (_BI + 2)}┘{C.RESET}"

def _bm():
    return f"{C.LIME}├{'─' * (_BI + 2)}┤{C.RESET}"

def _be():
    return f"{C.LIME}│{' ' * (_BI + 2)}│{C.RESET}"

def _term_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80

def _print_box_row(boxes):
    """Print boxes — side-by-side when terminal is wide enough, stacked otherwise.
    Requires ~82 cols for 2 boxes (1 indent + 38 + 2 gap + 38 + 2 border)."""
    wide = _term_width() >= 82
    if wide and len(boxes) == 2:
        h = max(len(b) for b in boxes)
        for b in boxes:
            while len(b) < h:
                b.insert(-1, _be())
        for a, b in zip(boxes[0], boxes[1]):
            print(f" {a}  {b}")
    else:
        for idx, box in enumerate(boxes):
            for line in box:
                print(f" {line}")
            if idx < len(boxes) - 1:
                print()   # gap between stacked boxes; caller adds final gap


def _iface_box_lines(iface, detailed=False, num=None, show_conn=False):
    """Build list of rendered box lines for one wireless interface.
    detailed=True adds MAC / DNS / RX / TX (used by interfaces_menu).
    num=integer prepends a selector number to the header line."""
    is_p2p = iface.startswith('p2p')
    state  = iface_state(iface)
    ip     = iface_ip(iface)
    ssid   = iface_ssid(iface)
    mode   = iface_mode(iface)
    gw     = iface_gateway(iface)
    wpa    = 'on' if wpa_running(iface) else 'off'
    signal = iface_signal(iface) if not is_p2p else '—'

    if detailed:
        mac    = iface_mac(iface)
        rx, tx = iface_txrx(iface)
        dns    = system_dns()

    if state == 'UP':         sc = C.LIME
    elif 'no link' in state:  sc = C.WARN
    elif state == 'MISSING':  sc = C.ERR
    else:                     sc = C.DARK

    if mode == 'monitor':     mc = f"{C.LIME}{C.BOLD}"
    elif mode == 'AP':        mc = C.LIME
    else:                     mc = C.DARK

    tags = []
    if iface == active_iface:      tags.append(f"{C.LIME}[ACTIVE]{C.RESET}")
    if iface in protected_ifaces:  tags.append(f"{C.DARK}[prot]{C.RESET}")
    if is_p2p:                     tags.append(f"{C.DARK}[p2p]{C.RESET}")

    L = [_bt()]

    # Header: optional selector number + name + state + mode
    num_pfx = f"{C.BRIGHT}{num}.{C.RESET} " if num is not None else ""
    r1 = f"{num_pfx}{C.WHITE}{C.BOLD}{iface}{C.RESET}  {sc}{state}{C.RESET}  {mc}{mode}{C.RESET}"
    L.append(_bl(r1))

    if tags:
        L.append(_bl('  '.join(tags)))

    if is_p2p:
        L.append(_bl(f"{C.DARK}peer-to-peer / Wi-Fi Direct{C.RESET}"))
        if detailed:
            L.append(_bl(f"{C.BORDER}MAC{C.RESET}    {C.DARK}{mac}{C.RESET}"))
    else:
        ssid_show = (ssid[:25] + '…') if len(ssid) > 26 else ssid
        L.append(_bl(f"{C.BORDER}SSID{C.RESET}   {C.BRIGHT}{ssid_show}{C.RESET}"))
        L.append(_bl(f"{C.BORDER}Signal{C.RESET} {C.BRIGHT}{signal}{C.RESET}  {C.BORDER}WPA{C.RESET} {C.BRIGHT}{wpa}{C.RESET}"))
        if detailed:
            uptime = _iface_uptime(iface)
            L.append(_bl(f"{C.BORDER}Up{C.RESET}     {C.BRIGHT}{uptime}{C.RESET}"))
            L.append(_bl(f"{C.BORDER}MAC{C.RESET}    {C.DARK}{mac}{C.RESET}"))

    L.append(_bm())

    L.append(_bl(f"{C.BORDER}IP{C.RESET}  {C.BRIGHT}{ip}{C.RESET}"))
    L.append(_bl(f"{C.BORDER}GW{C.RESET}  {C.BRIGHT}{gw}{C.RESET}"))
    if show_conn and ip != 'no IP':
        pub = cached('pub_ip', get_public_ip, ttl=90)
        L.append(_bl(f"{C.BORDER}Public{C.RESET}  {C.BRIGHT}{pub}{C.RESET}"))

    if detailed:
        L.append(_bl(f"{C.BORDER}DNS{C.RESET}  {C.BRIGHT}{dns}{C.RESET}"))
        L.append(_bl(f"{C.BORDER}RX{C.RESET} {C.BRIGHT}{rx}{C.RESET}  {C.BORDER}TX{C.RESET} {C.BRIGHT}{tx}{C.RESET}"))

    if mode == 'AP':
        clients = get_ap_clients(iface)
        if clients:
            L.append(_bl(f"{C.LIME}AP clients: {len(clients)}{C.RESET}"))
            for cl in clients[:2]:
                L.append(_bl(f"  {C.BRIGHT}{cl['mac']}{C.RESET}  {C.DARK}{cl.get('signal','?')} dBm{C.RESET}"))
        else:
            L.append(_bl(f"{C.DARK}AP: no clients connected{C.RESET}"))

    L.append(_bb())
    return L


def get_cellular_ifaces():
    """Return list of cellular/mobile-data interfaces that are currently UP."""
    patterns = ('rmnet', 'ccmni', 'wwan', 'ppp0', 'ppp1', 'usb')
    _, out, _ = run("ip link show 2>/dev/null")
    result = []
    for line in out.splitlines():
        if not line or not line[0].isdigit():
            continue
        parts = line.split(':')
        if len(parts) < 2:
            continue
        name = parts[1].strip().split('@')[0]
        if any(name.startswith(p) for p in patterns) and iface_state(name) == 'UP':
            result.append(name)
    return result


def _conn_box_lines(iface, conn_type='WiFi'):
    """Build connectivity status box for a single network interface."""
    ip    = iface_ip(iface)
    gw    = iface_gateway(iface)
    state = iface_state(iface)
    has_ip = (state == 'UP' and ip != 'no IP')
    sc, label = (C.LIME, 'UP') if has_ip else (C.ERR, 'DOWN')
    L = [_bt()]
    L.append(_bl(f"{C.WHITE}{C.BOLD}{iface}{C.RESET}  {C.DARK}{conn_type}{C.RESET}  {sc}{label}{C.RESET}"))
    L.append(_bl(f"{C.BORDER}Local{C.RESET}   {C.BRIGHT}{ip}{C.RESET}"))
    if gw != '—':
        L.append(_bl(f"{C.BORDER}GW{C.RESET}      {C.BRIGHT}{gw}{C.RESET}"))
    pub = cached('pub_ip', get_public_ip, ttl=90)
    L.append(_bl(f"{C.BORDER}Public{C.RESET}  {C.BRIGHT}{pub}{C.RESET}"))
    L.append(_bb())
    return L


def _pitail_conn_box():
    """Build Pi-Tail connectivity status box."""
    pitail_ok = check_pitail()
    kl_lbl = f"{C.LIME}ON{C.RESET}" if keepalive_running else f"{C.DARK}OFF{C.RESET}"
    sc, status = (C.LIME, 'REACHABLE') if pitail_ok else (C.ERR, 'UNREACHABLE')
    L = [_bt()]
    L.append(_bl(f"{C.WHITE}{C.BOLD}Pi-Tail{C.RESET}    {sc}{status}{C.RESET}"))
    L.append(_bl(f"{C.BORDER}Target{C.RESET}      {C.BRIGHT}{PITAIL_IP}{C.RESET}"))
    L.append(_bl(f"{C.BORDER}Interface{C.RESET}   {C.BRIGHT}{PITAIL_IFACE}{C.RESET}"))
    L.append(_bl(f"{C.BORDER}Keepalive{C.RESET}   {kl_lbl}"))
    L.append(_bb())
    return L

# ─────────────────────────────────────────────────────────────────────────────

def show_status():
    if not IS_ROOT:
        show_status_limited()
        return

    ifaces      = get_wireless_ifaces()
    disp_ifaces = [i for i in ifaces if not i.startswith('p2p')]

    # ── Interfaces & Connectivity (one box per interface) ────────────────────
    _ts  = datetime.datetime.now().strftime('%H:%M')
    _tag = f'↺ {_ts}'
    _left = '  ── Interfaces '
    _dashes = max(2, _term_width() - len(_left) - len(_tag) - 2)
    print(f"{C.MED}{C.BOLD}{_left}{'─' * _dashes}{C.RESET}  {C.DARK}{_tag}{C.RESET}\n")

    boxes = [_iface_box_lines(iface, show_conn=True) for iface in disp_ifaces]

    # Cellular interfaces — one box each
    for iface in get_cellular_ifaces():
        boxes.append(_conn_box_lines(iface, 'Cellular'))

    # Pi-Tail box — only when mode is active or keepalive is running
    if CURRENT_MODE == 'pitail' or keepalive_running:
        boxes.append(_pitail_conn_box())

    if boxes:
        for i in range(0, len(boxes), 2):
            _print_box_row(boxes[i:i+2])
            print()
    else:
        print(f"  {C.DARK}No wireless interfaces detected{C.RESET}\n")

    if watchdog_target_ssid:
        print(f"  {C.LIME}⟳{C.RESET}  {C.DARK}Watchdog →{C.RESET} "
              f"{C.LIME}{watchdog_target_ssid}{C.RESET}"
              f"  {C.DARK}on {active_iface}{C.RESET}\n")

# ═══════════════════════════════════════════════════════════════════════════════
#  SWITCH ACTIVE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════
def interfaces_menu():
    """Interface browser — detailed boxes for all interfaces including p2p.
    Numbers shown inside each box; user picks a number to set the active interface."""
    global active_iface
    print_header()
    ifaces = get_wireless_ifaces()
    if not ifaces:
        err("No wireless interfaces detected"); pause(); return

    print(f"{C.MED}{C.BOLD}  ── Interfaces {'─' * 28}{C.RESET}\n")

    for i in range(0, len(ifaces), 2):
        pair  = ifaces[i:i+2]
        nums  = list(range(i + 1, i + 1 + len(pair)))
        boxes = [_iface_box_lines(pair[j], detailed=True, num=nums[j])
                 for j in range(len(pair))]
        _print_box_row(boxes)
        print()

    selectable = [x for x in ifaces if not x.startswith('p2p')]
    if not selectable:
        pause(); return

    n = len(ifaces)
    choice = input(f"  {C.BRIGHT}Set active interface [1-{n}, Enter=cancel]: {C.RESET}").strip()
    if not choice:
        return
    try:
        chosen = ifaces[int(choice) - 1]
        if chosen.startswith('p2p'):
            warn("p2p interfaces cannot be set as active."); pause(); return
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

# Keep old name as alias for any stray internal references
switch_interface = interfaces_menu

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
def _freq_to_channel(freq_mhz):
    """Convert a WiFi frequency in MHz to a channel number string."""
    try:
        f = int(freq_mhz)
        if 2412 <= f <= 2484:
            return str((f - 2407) // 5) if f != 2484 else '14'
        if 5000 <= f <= 5885:
            return str((f - 5000) // 5)
        if 5935 <= f <= 7115:          # WiFi 6E 6 GHz band
            return str((f - 5935) // 5)
    except (TypeError, ValueError):
        pass
    return '?'


def scan_networks_limited():
    """Scan using termux-wifi-scaninfo on non-rooted Android."""
    info("Scanning via Termux:API...")
    nets = termux_wifi_scan()

    if nets is None:
        err("Termux:API not found — cannot scan networks")
        print(f"  {C.DARK}  Termux:API is required for WiFi scanning.{C.RESET}")
        print(f"  {C.DARK}  Setup:{C.RESET}")
        print(f"  {C.DARK}    1. Install the Termux:API app from F-Droid (not Play Store){C.RESET}")
        print(f"  {C.DARK}       https://f-droid.org/packages/com.termux.api/{C.RESET}")
        print(f"  {C.DARK}    2. In Termux, run: pkg install termux-api{C.RESET}")
        pause()
        return []

    if not nets:
        warn("No networks found")
        pause()
        return []

    # Get current SSID for marking connected network
    current_ssid = ""
    wifi = termux_wifi_info()
    if wifi:
        current_ssid = wifi.get('ssid', '').strip('"')

    # Sort by signal strength (rssi, higher = better)
    nets.sort(key=lambda x: x.get('rssi', -100), reverse=True)

    # Deduplicate by SSID
    seen, networks = set(), []
    for n in nets:
        ssid = n.get('ssid', '').strip('"')
        if not ssid or ssid in seen:
            continue
        seen.add(ssid)
        networks.append({
            'ssid':    ssid,
            'bssid':   n.get('bssid', '').upper(),
            'channel': _freq_to_channel(n.get('frequency', 0)),
            'signal':  f"{n.get('rssi', '?')} dBm",
            'enc':     True,   # termux-wifi-scaninfo doesn't expose encryption clearly
        })

    print(f"\n  {C.MED}{C.BOLD}{'#':<4} {'SSID':<28} {'CH':<5} {'Signal':<12} Enc{C.RESET}")
    print(f"  {C.BORDER}{'─' * 54}{C.RESET}")
    for i, n in enumerate(networks, 1):
        conn   = f"  {C.LIME}← connected{C.RESET}" if n['ssid'] == current_ssid else ""
        ssid_d = n['ssid'][:26] + '…' if len(n['ssid']) > 27 else n['ssid']
        print(f"  {C.BRIGHT}{i:<4}{C.RESET}"
              f"{C.WHITE}{ssid_d:<28}{C.RESET}"
              f"{C.MED}{n['channel']:<5}{C.RESET}"
              f"{C.DARK}{n['signal']:<12}{C.RESET}"
              f"🔒{conn}")
    return networks

def scan_networks(iface=None):
    if not IS_ROOT:
        return scan_networks_limited()

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
            try:   cur['bssid'] = line.split('Address:')[1].strip()
            except: cur['bssid'] = ''
        if line.startswith('Channel:'):
            try:   cur['channel'] = line.split(':')[1].strip()
            except: pass
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
    print(f"\n  {C.MED}{C.BOLD}{'#':<4} {'SSID':<28} {'CH':<5} {'Signal':<12} Enc{C.RESET}")
    print(f"  {C.BORDER}{'─' * 54}{C.RESET}")
    for i, n in enumerate(unique, 1):
        conn   = f"  {C.LIME}← connected{C.RESET}" if n['ssid'] == current_ssid else ""
        lock   = "🔒" if n.get('enc') else "🔓"
        ch     = n.get('channel', '?')
        ssid_d = n['ssid'][:26] + '…' if len(n['ssid']) > 27 else n['ssid']
        print(f"  {C.BRIGHT}{i:<4}{C.RESET}"
              f"{C.WHITE}{ssid_d:<28}{C.RESET}"
              f"{C.MED}{ch:<5}{C.RESET}"
              f"{C.DARK}{n.get('signal','?'):<12}{C.RESET}"
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
    else:
        # wpa_passphrase includes the plaintext password as a #psk= comment — strip it
        out = "\n".join(
            line for line in out.splitlines()
            if not line.strip().startswith("#psk=")
        ) + "\n"
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
        password = getpass.getpass(f"  {C.BRIGHT}Password (blank for open network): {C.RESET}").strip()

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
            pw = getpass.getpass(f"  {C.BRIGHT}Password for '{n['ssid']}': {C.RESET}").strip()
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
        print()
        _menu_item('c', "Connect to profile", IS_ROOT)
        print(f"  {C.BRIGHT}d{C.RESET}.  Delete profile")
        print(f"  {C.BRIGHT}b{C.RESET}.  Back")
        choice = input(f"\n  {C.BRIGHT}>{C.RESET} ").strip().lower()
        if choice == 'b':
            break
        elif choice == 'c':
            if not IS_ROOT:
                requires_root(); continue
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
    print(f"    Password  : {C.WHITE}{'*' * len(PITAIL_PASS)}{C.RESET}")
    print(f"    Interval  : {C.WHITE}{PITAIL_KEEPALIVE_INT}s{C.RESET}\n")
    print(f"  {C.DARK}Leave blank to keep current value.{C.RESET}\n")
    v = input(f"  {C.BRIGHT}Interface [{PITAIL_IFACE}]: {C.RESET}").strip()
    if v: PITAIL_IFACE = v
    v = input(f"  {C.BRIGHT}Hotspot SSID [{PITAIL_SSID}]: {C.RESET}").strip()
    if v: PITAIL_SSID = v
    v = getpass.getpass(f"  {C.BRIGHT}Hotspot Password (Enter to keep current): {C.RESET}").strip()
    if v: PITAIL_PASS = v
    v = input(f"  {C.BRIGHT}Check interval in seconds [{PITAIL_KEEPALIVE_INT}]: {C.RESET}").strip()
    if v:
        try: PITAIL_KEEPALIVE_INT = int(v)
        except: warn("Invalid interval, keeping current")
    ok("Keepalive config updated")
    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMAND REFERENCE — data
# ═══════════════════════════════════════════════════════════════════════════════
CMD_REFERENCE = [

    {'cat': 'Diagnostics'},
    {'cmd': 'ping -c 4 google.com',
     'desc': 'Check internet connectivity (4 packets to google.com)'},
    {'cmd': 'ifconfig',
     'desc': 'Show all network interfaces, IPs, and packet stats'},
    {'cmd': 'iwconfig',
     'desc': 'Show wireless interface details — mode, SSID, signal, bitrate'},
    {'cmd': 'ip link show',
     'desc': 'Show all interfaces and whether they are UP or DOWN'},
    {'cmd': 'ip addr show {IFACE}; ip addr show {IFACE2}',
     'desc': 'Show IP addresses assigned to both interfaces'},
    {'cmd': 'hostname -I',
     'desc': 'Show all local IP addresses on this machine'},
    {'cmd': 'lsusb',
     'desc': 'List USB devices — WiFi adapters appear here (e.g. Realtek)'},
    {'cmd': 'iwgetid {IFACE}',
     'desc': 'Show which WiFi network {IFACE} is currently connected to'},
    {'cmd': 'arp -a',
     'desc': 'Show ARP table — devices recently seen on the local network'},
    {'cmd': 'curl -s ifconfig.me',
     'desc': 'Get public / external IP address'},
    {'cmd': 'traceroute google.com',
     'desc': 'Trace the network path — shows each hop to destination'},
    {'cmd': 'nslookup google.com',
     'desc': 'DNS lookup — verify domain name resolution is working'},
    {'cmd': 'cat /etc/resolv.conf',
     'desc': 'Show configured DNS servers'},

    {'cat': 'Interface Control'},
    {'cmd': 'sudo ip link set {IFACE} up',
     'desc': 'Bring {IFACE} up'},
    {'cmd': 'sudo ip link set {IFACE} down',
     'desc': 'Bring {IFACE} down'},
    {'cmd': 'sudo ifconfig {IFACE} up',
     'desc': 'Bring {IFACE} up (ifconfig variant)'},
    {'cmd': 'sudo ifconfig {IFACE} down',
     'desc': 'Bring {IFACE} down (ifconfig variant)'},
    {'cmd': 'sudo dhclient {IFACE}',
     'desc': 'Request a new IP address from DHCP for {IFACE}'},
    {'cmd': 'sudo dhclient -r {IFACE}',
     'desc': 'Release the current DHCP lease on {IFACE}'},

    {'cat': 'Scanning'},
    {'cmd': 'sudo iwlist {IFACE} scan',
     'desc': 'Scan for nearby WiFi networks using {IFACE}'},
    {'cmd': 'nmcli device wifi list',
     'desc': 'Scan for nearby WiFi networks (NetworkManager)'},

    {'cat': 'Routing'},
    {'cmd': 'ip route show',
     'desc': 'Show the full routing table'},
    {'cmd': 'ip route | grep default',
     'desc': 'Show only the default gateway routes'},
    {'cmd': 'sudo ip route add default via {GATEWAY} dev {IFACE}',
     'desc': 'Add a default route for {IFACE} through {GATEWAY}'},
    {'cmd': 'sudo ip route del default via {GATEWAY} dev {IFACE}',
     'desc': 'Delete the default route for {IFACE} through {GATEWAY}'},
    {'cmd': 'sudo ip route replace default via {GATEWAY} dev {IFACE}',
     'desc': 'Replace / change the default gateway for {IFACE}'},

    {'cat': 'Gateway'},
    {'cmd': "ip route | grep default | awk '{print $3}'",
     'desc': 'Print the current default gateway IP address'},
    {'cmd': "xdg-open http://$(ip route | grep default | awk '{print $3}')",
     'desc': 'Open the gateway admin page in a browser'},
    {'cmd': 'sudo ip route replace default via {GATEWAY}',
     'desc': 'Change the default gateway to {GATEWAY} (affects all interfaces)'},

    {'cat': 'Static IP'},
    {'cmd': 'sudo ip addr add {IP}/24 dev {IFACE}',
     'desc': 'Assign static IP {IP} to {IFACE}'},
    {'cmd': 'sudo ip addr del {IP}/24 dev {IFACE}',
     'desc': 'Remove static IP {IP} from {IFACE}'},
    {'cmd': 'sudo nmcli connection modify "{SSID}" ipv4.addresses {IP}/24 ipv4.gateway {GATEWAY} ipv4.method manual',
     'desc': 'Set static IP for saved connection via nmcli (replaces DHCP)'},
    {'cmd': 'sudo nmcli connection modify "{SSID}" ipv4.method auto',
     'desc': 'Switch saved connection "{SSID}" back to DHCP'},
    {'cmd': 'sudo nmcli connection modify "{SSID}" ipv4.dns "8.8.8.8 8.8.4.4"',
     'desc': 'Set DNS servers for connection "{SSID}"'},

    {'cat': 'NetworkManager'},
    {'cmd': 'sudo systemctl start NetworkManager',
     'desc': 'Start the NetworkManager service'},
    {'cmd': 'sudo systemctl stop NetworkManager',
     'desc': 'Stop the NetworkManager service'},
    {'cmd': 'sudo systemctl restart NetworkManager',
     'desc': 'Restart NetworkManager (useful after config changes)'},
    {'cmd': 'sudo systemctl enable NetworkManager',
     'desc': 'Enable NetworkManager to start automatically on boot'},
    {'cmd': 'sudo systemctl status NetworkManager',
     'desc': 'Show NetworkManager service status and recent logs'},

    {'cat': 'nmcli — Connections'},
    {'cmd': 'nmcli connection show',
     'desc': 'List all saved WiFi/network connections'},
    {'cmd': 'nmcli -f NAME,AUTOCONNECT-PRIORITY connection show',
     'desc': 'Show saved connections and their auto-connect priorities'},
    {'cmd': 'nmcli connection show --active | grep wifi',
     'desc': 'Show currently active WiFi connection'},
    {'cmd': 'nmcli connection up "{SSID}"',
     'desc': 'Manually connect to saved network "{SSID}"'},
    {'cmd': 'nmcli connection delete "{SSID}"',
     'desc': 'Delete saved connection "{SSID}"'},
    {'cmd': 'nmcli connection modify "{SSID}" connection.autoconnect-priority 100',
     'desc': 'Set auto-connect priority — 100=high, 50=medium, 10=low'},

    {'cat': 'nmcli — Add Network'},
    {'cmd': 'nmcli connection add type wifi ifname {IFACE} con-name "{SSID}" ssid "{SSID}"',
     'desc': 'Step 1 — Create a new WiFi connection profile'},
    {'cmd': 'nmcli connection modify "{SSID}" wifi-sec.key-mgmt wpa-psk',
     'desc': 'Step 2 — Set security type to WPA/WPA2'},
    {'cmd': 'nmcli connection modify "{SSID}" wifi-sec.psk <PASSWORD>',
     'desc': 'Step 3 — Set the WiFi password (replace <PASSWORD>)'},
    {'cmd': 'nmcli connection modify "{SSID}" connection.autoconnect yes',
     'desc': 'Step 4 — Enable auto-connect for this network'},
    {'cmd': 'nmcli connection modify "{SSID}" connection.autoconnect-priority 100',
     'desc': 'Step 5 — Set priority (100=high, 50=medium, 10=low)'},

    {'cat': 'Port Forwarding'},
    {'cmd': 'sudo iptables -t nat -A PREROUTING -i {IFACE} -p tcp --dport {PORT} -j REDIRECT --to-port 80',
     'desc': 'Forward incoming TCP port {PORT} on {IFACE} to local port 80'},
    {'cmd': 'sudo iptables -t nat -A POSTROUTING -o {IFACE} -j MASQUERADE',
     'desc': 'Enable NAT masquerading on {IFACE} — share internet connection'},
    {'cmd': 'sudo iptables -t nat -L -n -v',
     'desc': 'List all NAT rules (port forwarding, masquerading)'},
    {'cmd': 'sudo iptables -L -n -v',
     'desc': 'List all firewall / filter rules'},
    {'cmd': 'sudo iptables -t nat -F',
     'desc': 'WARNING: Flush all NAT rules — removes all port forwarding'},
    {'cmd': 'echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward',
     'desc': 'Enable IP forwarding — required for routing between interfaces'},

    {'cat': 'Troubleshooting'},
    {'cmd': 'dmesg | tail -50',
     'desc': 'Show last 50 kernel messages — first place to look after any hardware issue'},
    {'cmd': 'dmesg -w',
     'desc': 'Watch kernel log live — run this, then plug in the adapter to see what happens'},
    {'cmd': 'dmesg | grep -i usb | tail -30',
     'desc': 'Filter kernel log for USB events only — shows plug/unplug, enumeration'},
    {'cmd': 'dmesg | grep -i "error\\|fail\\|disconnect\\|overcurrent\\|reset" | tail -30',
     'desc': 'Find USB errors — overcurrent means Android tripped protection on the port'},
    {'cmd': 'lsusb',
     'desc': 'List USB devices — adapter should appear here when detected'},
    {'cmd': 'lsusb -v 2>/dev/null | head -100',
     'desc': 'Verbose USB device list — shows VID:PID, class, speed for each device'},
    {'cmd': 'ls /sys/bus/usb/devices/',
     'desc': 'Show USB device tree in sysfs — confirms USB subsystem is alive'},
    {'cmd': 'cat /sys/bus/platform/drivers/musb-hdrc/*/mode',
     'desc': 'Check OTG mode — should show host or peripheral (Android)'},
    {'cmd': 'cat /sys/devices/*/otg_mode 2>/dev/null',
     'desc': 'Alternative OTG mode check for devices without musb-hdrc'},
    {'cmd': 'rmmod r8188eu 2>/dev/null; sleep 1; modprobe r8188eu',
     'desc': 'Reload Realtek RTL8188 driver — replace r8188eu with your adapter module'},
    {'cmd': 'echo 0 | sudo tee /sys/bus/usb/devices/usb1/authorized; sleep 2; echo 1 | sudo tee /sys/bus/usb/devices/usb1/authorized',
     'desc': 'Soft-reset the USB host controller — clears stuck device state without rebooting'},
    {'cmd': 'sudo reboot',
     'desc': 'Full reboot — clears overcurrent protection and all driver state'},

    {'cat': 'Monitor Mode'},
    {'cmd': 'sudo airmon-ng check kill',
     'desc': 'Kill processes that interfere with monitor mode (wpa_supplicant, NetworkManager)'},
    {'cmd': 'sudo airmon-ng start {IFACE}',
     'desc': 'Enable monitor mode on {IFACE} — creates {IFACE_MON} (e.g. wlan1mon)'},
    {'cmd': 'sudo airmon-ng stop {IFACE_MON}',
     'desc': 'Stop monitor mode — restores {IFACE} to managed mode'},
    {'cmd': 'sudo iw dev {IFACE} set monitor none && sudo ip link set {IFACE} up',
     'desc': 'Enable monitor mode without airmon-ng (fallback / manual method)'},
    {'cmd': 'sudo iw dev {IFACE} set type managed && sudo ip link set {IFACE} up',
     'desc': 'Return {IFACE} to managed mode (no airmon-ng needed)'},
    {'cmd': 'iwconfig {IFACE}',
     'desc': 'Confirm adapter mode — look for Mode:Monitor or Mode:Managed in output'},

    {'cat': 'Capture'},
    {'cmd': 'sudo airodump-ng {IFACE_MON}',
     'desc': 'Capture all visible WiFi traffic — shows BSSIDs, channels, clients'},
    {'cmd': 'sudo airodump-ng -c {CHANNEL} --bssid {BSSID} -w capture {IFACE_MON}',
     'desc': 'Targeted capture — channel {CHANNEL}, AP {BSSID} — writes handshake files'},
    {'cmd': 'sudo airodump-ng --wps {IFACE_MON}',
     'desc': 'Show WPS-enabled APs during capture'},
    {'cmd': 'sudo wash -i {IFACE_MON}',
     'desc': 'Scan for WPS-enabled APs and lock status (reaver / wash package)'},

    {'cat': 'Injection / Deauth'},
    {'cmd': 'sudo aireplay-ng --test {IFACE_MON}',
     'desc': 'Test packet injection on {IFACE_MON} — must pass before any attack'},
    {'cmd': 'sudo aireplay-ng -0 10 -a {BSSID} {IFACE_MON}',
     'desc': 'Deauth all clients from AP {BSSID} — sends 10 deauth frames'},
    {'cmd': 'sudo aireplay-ng -0 0 -a {BSSID} {IFACE_MON}',
     'desc': 'Continuous deauth from {BSSID} — use 0 to run until Ctrl+C'},
    {'cmd': 'sudo aireplay-ng -0 10 -a {BSSID} -c <CLIENT_MAC> {IFACE_MON}',
     'desc': 'Targeted deauth — disconnect one specific client from {BSSID}'},
    {'cmd': 'sudo aireplay-ng -1 0 -e "{SSID}" -a {BSSID} {IFACE_MON}',
     'desc': 'Fake auth — associate with AP {BSSID} before other attacks'},

    {'cat': 'Cracking'},
    {'cmd': 'sudo aircrack-ng capture-01.cap -w {WORDLIST}',
     'desc': 'Dictionary attack on WPA handshake from airodump-ng capture file'},
    {'cmd': 'sudo aircrack-ng -b {BSSID} *.cap -w {WORDLIST}',
     'desc': 'Crack using BSSID {BSSID} across all .cap files in current directory'},
    {'cmd': 'sudo hashcat -m 22000 capture.hc22000 {WORDLIST}',
     'desc': 'Crack WPA2 handshake with hashcat (GPU — faster than aircrack-ng)'},
    {'cmd': 'sudo hcxdumptool -i {IFACE_MON} -o capture.pcapng --enable_status=1',
     'desc': 'Capture PMKID / handshakes with hcxdumptool (modern alternative to airodump-ng)'},
    {'cmd': 'sudo hcxpcapngtool -o capture.hc22000 capture.pcapng',
     'desc': 'Convert hcxdumptool capture to hashcat format (hc22000)'},

    {'cat': 'Traffic Capture'},
    {'cmd': 'sudo tcpdump -i {IFACE_MON} -w capture.pcap',
     'desc': 'Capture raw 802.11 frames on {IFACE_MON} and write to file'},
    {'cmd': 'sudo tcpdump -i {IFACE_MON} ether host {BSSID} -w capture.pcap',
     'desc': 'Capture only frames to/from AP {BSSID} on monitor interface'},
    {'cmd': 'sudo tcpdump -i {IFACE} -w capture.pcap port 80 or port 443',
     'desc': 'Capture web traffic on managed interface — useful after ARP-spoof MITM'},
    {'cmd': 'sudo tcpdump -i {IFACE} -A -s 0 port 80',
     'desc': 'Print HTTP traffic as ASCII — quick plaintext sniff, no file saved'},
    {'cmd': 'sudo tcpdump -i {IFACE_MON} type mgt subtype probe-req',
     'desc': 'Show probe requests — reveals SSIDs nearby devices are actively searching for'},
    {'cmd': 'sudo tcpdump -r capture.pcap',
     'desc': 'Read and display a saved capture file'},
    {'cmd': 'sudo tshark -i {IFACE_MON} -w capture.pcapng',
     'desc': 'Capture on {IFACE_MON} to pcapng file (tshark — terminal Wireshark)'},
    {'cmd': 'sudo tshark -i {IFACE_MON} -Y "eapol" -w handshake.pcapng',
     'desc': 'Capture only EAPOL frames (WPA 4-way handshake) — minimal file size'},
    {'cmd': 'sudo tshark -i {IFACE_MON} -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.ssid -e wlan.bssid',
     'desc': 'Live beacon parser — prints SSID and BSSID for every AP seen'},
    {'cmd': 'tshark -r capture.pcapng -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri',
     'desc': 'Extract HTTP GET requests from saved capture — shows victim IPs and URLs'},
    {'cmd': 'tshark -r capture.pcapng -Y "dns" -T fields -e ip.src -e dns.qry.name',
     'desc': 'Extract DNS queries from capture — shows what domains victims are looking up'},

    {'cat': 'Kismet'},
    {'cmd': 'sudo kismet -c {IFACE_MON}',
     'desc': 'Start Kismet on {IFACE_MON} — passive scanner, web UI at http://localhost:2501'},
    {'cmd': 'sudo kismet -c {IFACE_MON} --no-ncurses',
     'desc': 'Headless mode — no terminal UI, control via browser only'},
    {'cmd': 'sudo kismet --daemonize -c {IFACE_MON}',
     'desc': 'Run as background daemon — access web UI at http://localhost:2501'},
    {'cmd': 'sudo kismet -c {IFACE_MON}:hop=true,hoprate=5/sec',
     'desc': 'Enable channel hopping at 5/sec — broader passive scan coverage'},
    {'cmd': 'sudo kismet -c {IFACE_MON}:channel={CHANNEL}',
     'desc': 'Lock Kismet to channel {CHANNEL} — targeted monitoring of one AP'},
    {'cmd': 'sudo kismet -c {IFACE_MON} --log-title capture',
     'desc': 'Custom log prefix "capture" — writes capture.kismet and capture.pcapng'},

    {'cat': 'Bettercap'},
    {'cmd': 'sudo bettercap -iface {IFACE}',
     'desc': 'Start bettercap interactive REPL on {IFACE}'},
    {'cmd': 'sudo bettercap -iface {IFACE} -caplet http-ui',
     'desc': 'Start with web UI caplet — browse to https://localhost (port 80)'},
    {'cmd': 'sudo bettercap -iface {IFACE} -eval "net.probe on; net.show"',
     'desc': 'Probe local network and list all discovered hosts'},
    {'cmd': 'sudo bettercap -iface {IFACE_MON} -eval "wifi.recon on"',
     'desc': 'Passive WiFi recon on {IFACE_MON} — lists APs and associated clients'},
    {'cmd': 'sudo bettercap -iface {IFACE_MON} -eval "wifi.recon on; wifi.deauth {BSSID}"',
     'desc': 'Deauth all clients from AP {BSSID} via bettercap WiFi module'},
    {'cmd': 'sudo bettercap -iface {IFACE_MON} -eval "set wifi.handshakes.file handshake.pcap; wifi.recon on"',
     'desc': 'Passively capture WPA handshakes to handshake.pcap on {IFACE_MON}'},
    {'cmd': 'sudo bettercap -iface {IFACE} -eval "set arp.spoof.targets {IP}; arp.spoof on; net.sniff on"',
     'desc': 'ARP spoof {IP} then sniff all their traffic (MITM)'},

    {'cat': 'WPS Attack'},
    {'cmd': 'sudo wash -i {IFACE_MON} -C',
     'desc': 'Scan for WPS-enabled APs — shows BSSID, channel, RSSI, lock status'},
    {'cmd': 'sudo reaver -i {IFACE_MON} -b {BSSID} -vv',
     'desc': 'WPS PIN brute force against {BSSID} — verbose, tries all ~11000 PINs'},
    {'cmd': 'sudo reaver -i {IFACE_MON} -b {BSSID} -K 1 -vv',
     'desc': 'Pixie Dust attack (-K 1) — offline PIN crack in seconds if AP is vulnerable'},
    {'cmd': 'sudo reaver -i {IFACE_MON} -b {BSSID} -K 1 -vv -c {CHANNEL}',
     'desc': 'Pixie Dust locked to channel {CHANNEL} — avoids channel-hop delays'},
    {'cmd': 'sudo reaver -i {IFACE_MON} -b {BSSID} -vv -S',
     'desc': 'Small DH keys mode (-S) — improves compatibility with some routers'},
    {'cmd': 'sudo reaver -i {IFACE_MON} -b {BSSID} -vv -d 1 -r 3:15',
     'desc': 'Add lock-out avoidance — retry 3 times, wait 15s between bursts'},
    {'cmd': 'sudo reaver -i {IFACE_MON} -b {BSSID} -vv -p <PIN>',
     'desc': 'Test a single PIN — use after pixiewps recovers the PIN offline'},
    {'cmd': 'pixiewps -e <PKR> -r <PKE> -s <E-HASH1> -z <E-HASH2> -a <AUTHKEY> -n <E-NONCE>',
     'desc': 'Standalone pixiewps — use when reaver -v shows WPS exchange hex values'},

    {'cat': 'Wifite'},
    {'cmd': 'sudo wifite',
     'desc': 'Auto-scan networks, present target list, attack selected — fully automated'},
    {'cmd': 'sudo wifite --interface {IFACE}',
     'desc': 'Start wifite on {IFACE} — bypasses auto-detection (useful on NetHunter)'},
    {'cmd': 'sudo wifite -wpa --dict {WORDLIST}',
     'desc': 'Target WPA/WPA2 only — crack captured handshakes using {WORDLIST}'},
    {'cmd': 'sudo wifite --wps --wps-only',
     'desc': 'WPS attacks only — runs Pixie Dust then PIN brute force automatically'},
    {'cmd': 'sudo wifite -c {CHANNEL}',
     'desc': 'Restrict scan to channel {CHANNEL} — faster targeting when AP is known'},
    {'cmd': 'sudo wifite --bssid {BSSID}',
     'desc': 'Attack only {BSSID} — skips interactive target selection'},
    {'cmd': 'sudo wifite --pmkid',
     'desc': 'PMKID attack — no deauth needed, stealthier than 4-way handshake capture'},
    {'cmd': 'sudo wifite --kill',
     'desc': 'Kill NetworkManager and wpa_supplicant before attacking'},
    {'cmd': 'sudo wifite --skip-crack',
     'desc': 'Capture handshakes but skip cracking — saves .cap files for offline processing'},

]

# Jump keys for command reference — press key to jump to that category.
# Numbers for standard categories, letters for attack categories.
CMD_SECTION_KEYS = {
    '1': 'Diagnostics',
    '2': 'Interface Control',
    '3': 'Scanning',
    '4': 'Routing',
    '5': 'Gateway',
    '6': 'Static IP',
    '7': 'NetworkManager',
    '8': 'nmcli — Connections',
    '9': 'nmcli — Add Network',
    '0': 'Port Forwarding',
    't': 'Troubleshooting',
    'm': 'Monitor Mode',
    'u': 'Capture',
    'i': 'Injection / Deauth',
    'w': 'Cracking',
    'p': 'Traffic Capture',    # p = packets / pcap
    'z': 'Kismet',             # z = available, kismet = passive recon
    'n': 'Bettercap',          # n = network MITM
    'x': 'WPS Attack',         # x = pixie / WPS exploit
    'g': 'Wifite',             # g = go / fully automated
}

# Attack-only categories shown in the dedicated attack reference screen
ATTACK_CATS = {
    'Monitor Mode', 'Capture', 'Injection / Deauth', 'Cracking',
    'Traffic Capture', 'Kismet', 'Bettercap', 'WPS Attack', 'Wifite',
}

# ─── Help / Troubleshooting content ──────────────────────────────────────────
# Each entry is a (type, text) tuple.
# Types: 'section', 'text', 'blank', 'step', 'cmd', 'note', 'cause'
HELP_CONTENT = [

    ('section', 'USB Adapter Not Showing in lsusb'),
    ('text',    'Unplugging and replugging the adapter repeatedly (or charging the'),
    ('text',    'phone in between without taking the interface down first) can put the'),
    ('text',    'USB port or driver into a bad state where the adapter disappears.'),
    ('blank',   ''),

    ('step',    'Step 1 — Watch kernel logs  (most important)'),
    ('cmd',     'dmesg | tail -50'),
    ('cmd',     'dmesg | grep -i usb | tail -30'),
    ('note',    'Run this, then plug in the adapter to see what happens in real time:'),
    ('cmd',     'dmesg -w'),
    ('text',    'If nothing appears at all — the kernel is not seeing the hardware.'),
    ('text',    'If errors appear — they will tell you exactly what failed.'),
    ('blank',   ''),

    ('step',    'Step 2 — Check USB subsystem is alive'),
    ('cmd',     'lsusb'),
    ('cmd',     'lsusb -v 2>/dev/null | head -100'),
    ('cmd',     'ls /sys/bus/usb/devices/'),
    ('blank',   ''),

    ('step',    'Step 3 — Look for USB errors in dmesg'),
    ('cmd',     'dmesg | grep -i "error|fail|disconnect|overcurrent|reset" | tail -30'),
    ('note',    'Overcurrent: Android disabled the USB port — reboot usually clears it.'),
    ('text',    'Too many hot-plug cycles can trip overcurrent protection even if the'),
    ('text',    'adapter itself draws normal power.'),
    ('blank',   ''),

    ('step',    'Step 4 — Check OTG is still enabled'),
    ('cmd',     'cat /sys/bus/platform/drivers/musb-hdrc/*/mode'),
    ('cmd',     'cat /sys/devices/*/otg_mode 2>/dev/null'),
    ('blank',   ''),

    ('step',    'Step 5 — Reload the driver module'),
    ('cmd',     'rmmod r8188eu 2>/dev/null; sleep 1; modprobe r8188eu'),
    ('text',    'Replace r8188eu with your adapter module (check Driver Manager).'),
    ('blank',   ''),

    ('step',    'Step 6 — Soft-reset the USB host controller'),
    ('cmd',     'echo 0 | sudo tee /sys/bus/usb/devices/usb1/authorized'),
    ('cmd',     'sleep 2'),
    ('cmd',     'echo 1 | sudo tee /sys/bus/usb/devices/usb1/authorized'),
    ('text',    'This resets the USB bus without rebooting. usb1 is usually the OTG'),
    ('text',    'host controller — check ls /sys/bus/usb/devices/ if unsure.'),
    ('blank',   ''),

    ('step',    'Most likely fix — full reboot'),
    ('note',    'Reboot the phone FIRST before anything else.'),
    ('cmd',     'sudo reboot'),
    ('text',    'Plug the adapter in AFTER boot, before doing anything else.'),
    ('text',    '  - Shows in lsusb after clean boot = software/driver state issue.'),
    ('text',    '  - Still missing after reboot = overcurrent protection or physical.'),
    ('blank',   ''),

    ('section', 'Why This Happens'),
    ('cause',   'Overcurrent protection tripped — too many hot-plugs. Reboot clears it.'),
    ('cause',   'Driver in bad state — module stuck, needs rmmod + modprobe.'),
    ('cause',   'Interface not brought DOWN before unplugging — always use option 2 first.'),
    ('cause',   'Physical wear — OTG cable or port from repeated plugging (less common).'),
    ('cause',   'USB hub/OTG adapter failure — the cable, not the phone.'),
    ('blank',   ''),

    ('section', 'General Tips'),
    ('cause',   'Always bring the interface DOWN (option 2) before unplugging the adapter.'),
    ('cause',   'Run dmesg -w in a second terminal when debugging new hardware.'),
    ('cause',   'Run airmon-ng check kill before enabling monitor mode.'),
    ('cause',   'After plugging in, wait 2-3 seconds before running lsusb.'),
    ('cause',   'Check Driver Manager (d) to identify your adapter and find the right module.'),
    ('cause',   'If adapter is listed in lsusb but not in iwconfig, driver is the issue.'),
    ('blank',   ''),

    ('section', 'Connection / wpa_supplicant Issues'),
    ('cause',   'wpa_supplicant already running — run airmon-ng check kill or killall.'),
    ('cause',   'Wrong password stored — delete the profile and reconnect.'),
    ('cause',   'DHCP not getting IP — run sudo dhclient wlan1 manually after connect.'),
    ('cause',   'Interface in wrong mode — check iwconfig, make sure Mode:Managed.'),
    ('blank',   ''),
]

# ═══════════════════════════════════════════════════════════════════════════════
#  COMMAND REFERENCE — engine
# ═══════════════════════════════════════════════════════════════════════════════
def _apply_vars(cmd):
    """Substitute {VAR} placeholders with current CMD_VARS values."""
    for k, v in CMD_VARS.items():
        cmd = cmd.replace(f'{{{k}}}', v)
    return cmd


def _build_cmd_items(filter_cats=None):
    """Build flat (type, data) list from CMD_REFERENCE, optionally filtered to a set of categories."""
    items = []
    include = True
    for entry in CMD_REFERENCE:
        if 'cat' in entry:
            include = (filter_cats is None or entry['cat'] in filter_cats)
            if include:
                items.append(('header', entry['cat']))
        elif include:
            items.append(('cmd', entry))
    return items

def _getch():
    """Read a single keypress from stdin, including arrow key sequences.

    Phone keyboards (Termux) can be slow sending escape sequences — the bytes
    of an arrow key (ESC [ A) may arrive with gaps > 150ms between them.
    We use a generous 0.6s timeout per byte to handle this safely.
    """
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            # Wait up to 0.6s for the next byte — phones can be slow
            if select.select([sys.stdin], [], [], 0.6)[0]:
                ch2 = sys.stdin.read(1)
                if ch2 == '[' and select.select([sys.stdin], [], [], 0.6)[0]:
                    ch3 = sys.stdin.read(1)
                    if ch3 == 'A': return 'UP'
                    if ch3 == 'B': return 'DOWN'
                    if ch3 == 'C': return 'RIGHT'   # right arrow — don't fall to ESC
                    if ch3 == 'D': return 'LEFT'    # left arrow  — don't fall to ESC
                    if ch3 == '5': sys.stdin.read(1); return 'PGUP'
                    if ch3 == '6': sys.stdin.read(1); return 'PGDN'
                    return 'UNKNOWN'  # some other escape sequence — ignore, don't quit
            return 'ESC'
        elif ch in ('\r', '\n'): return 'ENTER'
        elif ch == '\x03': raise KeyboardInterrupt
        return ch.lower()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _input_prefilled(prompt, prefill=''):
    """Full-featured single-line editor — arrows, Home/End, Delete, Ctrl shortcuts.

    Implemented directly in raw terminal mode (same approach as _getch) rather
    than relying on readline hooks, which are unreliable on Termux:
    - set_pre_input_hook + redisplay() mislaid the cursor at the top of screen
    - set_startup_hook caused a few backspaces to bulk-delete the entire pre-fill
    This version handles every keypress explicitly; backspace deletes one char.

    Keys supported:
      ← →            move cursor left / right one character
      Home / Ctrl+A   move to start of line
      End  / Ctrl+E   move to end of line
      Backspace        delete character before cursor (one at a time)
      Delete           delete character after cursor
      Ctrl+K           kill from cursor to end of line
      Ctrl+U           kill from start of line to cursor
      Ctrl+W           delete word before cursor
      Enter            confirm and return
      Ctrl+C           cancel (raises KeyboardInterrupt)
    """
    buf = list(prefill)
    pos = len(buf)               # cursor starts at end of pre-filled text

    fd      = sys.stdin.fileno()
    old_tty = termios.tcgetattr(fd)

    def redraw():
        """Rewrite the current line and reposition the cursor at pos."""
        move_back = len(buf) - pos
        sys.stdout.write(f'\r{prompt}{"".join(buf)}\033[K')
        if move_back > 0:
            sys.stdout.write(f'\033[{move_back}D')   # ESC[nD  move cursor left n cols
        sys.stdout.flush()

    try:
        tty.setraw(fd)
        redraw()

        while True:
            ch = os.read(fd, 1)

            # ── Enter ────────────────────────────────────────────
            if ch in (b'\r', b'\n'):
                sys.stdout.write('\r\n')
                sys.stdout.flush()
                break

            # ── Ctrl+C ───────────────────────────────────────────
            elif ch == b'\x03':
                sys.stdout.write('\r\n')
                sys.stdout.flush()
                raise KeyboardInterrupt

            # ── Backspace / DEL — one character at a time ────────
            elif ch in (b'\x7f', b'\x08'):
                if pos > 0:
                    del buf[pos - 1]
                    pos -= 1
                    redraw()

            # ── Escape sequences: arrows, Home, End, Delete key ──
            elif ch == b'\x1b':
                nxt = os.read(fd, 1)
                if nxt == b'[':
                    seq = os.read(fd, 1)
                    if   seq == b'D':                       # ← left arrow
                        if pos > 0:
                            pos -= 1; redraw()
                    elif seq == b'C':                       # → right arrow
                        if pos < len(buf):
                            pos += 1; redraw()
                    elif seq in (b'H', b'h'):               # Home
                        pos = 0; redraw()
                    elif seq in (b'F', b'f'):               # End
                        pos = len(buf); redraw()
                    elif seq == b'A':                       # ↑ up → jump to start
                        pos = 0; redraw()
                    elif seq == b'B':                       # ↓ down → jump to end
                        pos = len(buf); redraw()
                    elif seq in (b'1', b'3', b'4', b'7', b'8'):
                        tail = os.read(fd, 1)               # consume trailing ~
                        if seq in (b'1', b'7'):             # Home variants
                            pos = 0; redraw()
                        elif seq in (b'4', b'8'):           # End variants
                            pos = len(buf); redraw()
                        elif seq == b'3' and tail == b'~':  # Delete key
                            if pos < len(buf):
                                del buf[pos]; redraw()
                elif nxt == b'O':                           # SS3 sequences
                    seq = os.read(fd, 1)
                    if   seq == b'H': pos = 0;        redraw()   # Home
                    elif seq == b'F': pos = len(buf); redraw()   # End

            # ── Ctrl shortcuts ────────────────────────────────────
            elif ch == b'\x01':                             # Ctrl+A → Home
                pos = 0; redraw()
            elif ch == b'\x05':                             # Ctrl+E → End
                pos = len(buf); redraw()
            elif ch == b'\x0b':                             # Ctrl+K → kill to end
                del buf[pos:]; redraw()
            elif ch == b'\x15':                             # Ctrl+U → kill to start
                del buf[:pos]; pos = 0; redraw()
            elif ch == b'\x17':                             # Ctrl+W → delete word back
                end = pos
                while pos > 0 and buf[pos - 1] == ' ':    pos -= 1
                while pos > 0 and buf[pos - 1] != ' ':    pos -= 1
                del buf[pos:end]; redraw()

            # ── Printable ASCII ───────────────────────────────────
            elif b'\x20' <= ch <= b'\x7e':
                buf.insert(pos, ch.decode('ascii'))
                pos += 1; redraw()

            # ── Multi-byte UTF-8 (accents, emoji, etc.) ──────────
            elif ch[0] >= 0xC0:
                n_more = 3 if ch[0] >= 0xF0 else 2 if ch[0] >= 0xE0 else 1
                try:
                    rest = os.read(fd, n_more)
                    buf.insert(pos, (ch + rest).decode('utf-8'))
                    pos += 1; redraw()
                except (OSError, UnicodeDecodeError):
                    pass

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_tty)

    return ''.join(buf)

def _cmd_vars_screen():
    """Screen to view and edit CMD_VARS substitution variables."""
    var_names = list(CMD_VARS.keys())
    while True:
        os.system('clear')
        print(LOGO)
        print(f"\n{C.MED}{C.BOLD}  ── Command Variables {'─' * 21}{C.RESET}")
        print(f"  {C.DARK}These are substituted into commands when you select them.{C.RESET}\n")
        for i, k in enumerate(var_names, 1):
            v = CMD_VARS[k] if CMD_VARS[k] else f'{C.DARK}(not set){C.RESET}'
            print(f"  {C.BRIGHT}{i}{C.RESET}.  {C.WHITE}{k:<10}{C.RESET}  {C.BRIGHT}{CMD_VARS[k] or '(not set)'}{C.RESET}")
        print(f"\n  {C.BRIGHT}b{C.RESET}.  Back")
        choice = input(f"\n  {C.BRIGHT}>{C.RESET} ").strip().lower()
        if choice == 'b':
            break
        try:
            k = var_names[int(choice) - 1]
            val = input(f"  {C.BRIGHT}{k} [{CMD_VARS[k]}]: {C.RESET}").strip()
            if val:
                CMD_VARS[k] = val
                ok(f"{k} = {val}")
        except (ValueError, IndexError):
            err("Invalid choice")

def _draw_cmd_ref(items, cursor, scroll, list_h, term_w, title='Muon'):
    """Redraw the command reference screen — single-line header and footer for max list space."""
    os.system('clear')

    # Reverse map for section key tags: category name → jump key
    _cat_rev = {v: k for k, v in CMD_SECTION_KEYS.items()}

    # ── 1-line header: title + vars + hint ──
    mode_tag = f" {C.WARN}[limited]{C.RESET}" if not IS_ROOT else ""
    var_parts = [f"{C.DARK}{k}={C.BRIGHT}{v}{C.RESET}" for k, v in CMD_VARS.items() if v]
    print(f"  {C.LIME}{C.BOLD}≫ {title}{C.RESET}{mode_tag}  {'  '.join(var_parts)}"
          f"  {C.DARK}[?]jump  [v]vars  q=back{C.RESET}")

    # ── Scrollable command list ──
    visible = items[scroll:scroll + list_h]
    for idx, (typ, data) in enumerate(visible):
        abs_idx = scroll + idx
        if typ == 'header':
            label = data
            cat_key = _cat_rev.get(label, '')
            tag_vis = f"[{cat_key}] " if cat_key else ''
            pad = max(0, term_w - len(label) - len(tag_vis) - 8)
            print(f"  {C.MED}{C.BOLD}── {C.BRIGHT}{tag_vis}{C.RESET}"
                  f"{C.MED}{C.BOLD}{label} {'─' * pad}{C.RESET}")
        else:
            selected = (abs_idx == cursor)
            cmd_text = _apply_vars(data['cmd'])
            max_len = term_w - 6
            display = cmd_text if len(cmd_text) <= max_len else cmd_text[:max_len - 1] + '…'
            if selected:
                print(f"  {C.LIME}▶ {C.WHITE}{display}{C.RESET}")
            else:
                print(f"    {C.BRIGHT}{display}{C.RESET}")

    # Pad so footer is always at a fixed position
    for _ in range(list_h - len(visible)):
        print()

    # ── 1-line footer: description of selected command ──
    if items[cursor][0] == 'cmd':
        desc = items[cursor][1]['desc']
        for k, v in CMD_VARS.items():
            if v:
                desc = desc.replace(f'{{{k}}}', f'{C.WHITE}{v}{C.RESET}{C.DARK}')
        print(f"  {C.DARK}▸ {desc}{C.RESET}")
    else:
        print(f"  {C.DARK}↑↓ / j k  PgUp PgDn · Enter=run · [?]jump · q=back{C.RESET}")

# ═══════════════════════════════════════════════════════════════════════════════
#  SETTINGS MENU
# ═══════════════════════════════════════════════════════════════════════════════

def projects_menu():
    """Save and restore named session projects (interface, CMD_VARS, mode, Pi-Tail config)."""
    while True:
        print_header()
        projects = _list_projects()

        print(f"  {C.MED}{C.BOLD}── Projects {'─' * 36}{C.RESET}")
        print(f"  {C.DARK}Save/restore interface, variables, mode and Pi-Tail config.{C.RESET}\n")

        if not projects:
            print(f"  {C.DARK}No saved projects yet.{C.RESET}\n")
        else:
            for i, p in enumerate(projects, 1):
                iface   = p.get('active_iface', '?')
                mode    = p.get('mode') or '—'
                saved   = p.get('saved', '?')[:16].replace('T', '  ')
                bssid   = p.get('cmd_vars', {}).get('BSSID', '')
                tgt     = f"  {C.DARK}→ {bssid}{C.RESET}" if bssid else ''
                print(f"  {C.BRIGHT}{i}{C.RESET}.  {C.WHITE}{p['name']:<22}{C.RESET}"
                      f"  {C.MED}{iface:<8}{C.RESET}"
                      f"  {C.DARK}{mode:<10}{C.RESET}"
                      f"  {C.DARK}{saved}{C.RESET}"
                      f"{tgt}")
            print()

        print(f"  {C.BRIGHT}s{C.RESET}.  Save current state as new project")
        if projects:
            print(f"  {C.BRIGHT}l{C.RESET}.  Load project")
            print(f"  {C.BRIGHT}d{C.RESET}.  Delete project")
        print(f"  {C.BRIGHT}b{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()

        if choice == 's':
            name = input(f"  {C.BRIGHT}Project name: {C.RESET}").strip()
            if name:
                _save_project(name)
                pause()

        elif choice == 'l' and projects:
            num = input(f"  {C.BRIGHT}Project number to load: {C.RESET}").strip()
            try:
                _load_project(projects[int(num) - 1])
                pause()
            except (ValueError, IndexError):
                err("Invalid selection"); pause()

        elif choice == 'd' and projects:
            num = input(f"  {C.BRIGHT}Project number to delete: {C.RESET}").strip()
            try:
                proj = projects[int(num) - 1]
                path = proj.get('_path', '')
                if path and os.path.exists(path):
                    os.remove(path)
                    ok(f"Deleted project: '{proj['name']}'")
                else:
                    warn("Project file not found")
                pause()
            except (ValueError, IndexError):
                err("Invalid selection"); pause()

        elif choice in ('b', 'q', '0', ''):
            break


def settings_menu():
    """Settings and configuration — things that don't belong on the main menu."""
    global WATCHDOG_INTERVAL
    while True:
        print_header()
        wd_lbl = f"{C.LIME}ON{C.RESET}"  if watchdog_running  else f"{C.DARK}OFF{C.RESET}"
        tgt    = f"  {C.LIME}-> {watchdog_target_ssid}{C.RESET}" if watchdog_target_ssid else ""
        kl_lbl = f"{C.LIME}ON{C.RESET}"  if keepalive_running else f"{C.DARK}OFF{C.RESET}"
        mode_lbl = (f"{C.LIME}{MODE_DEFS[CURRENT_MODE]['name']}{C.RESET}"
                    if CURRENT_MODE else f"{C.DARK}None{C.RESET}")

        print(f"  {C.MED}{C.BOLD}── Settings {'─' * 37}{C.RESET}")
        print()
        print(f"  {C.BRIGHT}1{C.RESET}.  Mode             [{mode_lbl}]")
        print(f"  {C.BRIGHT}2{C.RESET}.  Saved profiles")
        _menu_item('3', f"Watchdog          [{wd_lbl}]{tgt}", IS_ROOT)
        _menu_item('4',  "Watchdog target SSID", IS_ROOT)
        _menu_item('5', f"Watchdog interval  {C.DARK}(now: {WATCHDOG_INTERVAL}s){C.RESET}"
                        if IS_ROOT else "Watchdog interval", IS_ROOT)
        _menu_item('6', f"Pi-Tail keepalive [{kl_lbl}]", IS_ROOT)
        _menu_item('7',  "Configure Pi-Tail  (SSID / IP / interval)", IS_ROOT)
        n_proj = len(_list_projects())
        proj_hint = f"{C.DARK}({n_proj} saved){C.RESET}" if n_proj else f"{C.DARK}(none){C.RESET}"
        print(f"  {C.BRIGHT}8{C.RESET}.  Command variables"
              f"  {C.DARK}{' '.join(f'{k}={v}' for k, v in CMD_VARS.items() if v)}{C.RESET}")
        print(f"  {C.BRIGHT}9{C.RESET}.  Projects  {proj_hint}")
        _menu_item('i', f"Interfaces  {C.DARK}(active: {active_iface}){C.RESET}", IS_ROOT)
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip()
        if   choice == '1': mode_menu()
        elif choice == '2': manage_profiles()
        elif choice == '3': toggle_watchdog()        if IS_ROOT else requires_root()
        elif choice == '4': set_watchdog_target()    if IS_ROOT else requires_root()
        elif choice == '5': _set_watchdog_interval() if IS_ROOT else requires_root()
        elif choice == '6': toggle_keepalive()       if IS_ROOT else requires_root()
        elif choice == '7': configure_keepalive()    if IS_ROOT else requires_root()
        elif choice == '8': _cmd_vars_screen()
        elif choice == '9': projects_menu()
        elif choice == 'i': switch_interface()       if IS_ROOT else requires_root()
        elif choice.lower() in ('q', '0', ''):
            break


def _set_watchdog_interval():
    """Change how often the watchdog checks connections."""
    global WATCHDOG_INTERVAL
    print(f"\n  {C.MED}Watchdog check interval{C.RESET} {C.DARK}(current: {WATCHDOG_INTERVAL}s){C.RESET}")
    val = input(f"  {C.BRIGHT}New interval in seconds (blank to cancel): {C.RESET}").strip()
    if val:
        try:
            v = int(val)
            if v < 5:
                err("Minimum is 5 seconds"); pause(); return
            WATCHDOG_INTERVAL = v
            ok(f"Watchdog interval set to {v}s")
        except ValueError:
            err("Enter a whole number")
    pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODES
# ═══════════════════════════════════════════════════════════════════════════════

def mode_menu():
    """Select or deactivate an operating mode."""
    global CURRENT_MODE
    while True:
        print_header()
        print(f"  {C.MED}{C.BOLD}── Mode {'─' * 41}{C.RESET}\n")

        cur_name = MODE_DEFS[CURRENT_MODE]['name'] if CURRENT_MODE else "None"
        cur_col  = C.LIME if CURRENT_MODE else C.DARK
        print(f"  {C.DARK}Active:{C.RESET} {cur_col}{cur_name}{C.RESET}\n")
        print(f"  {C.DARK}Modes configure the app for a specific workflow and add a{C.RESET}")
        print(f"  {C.DARK}dedicated screen with status, quick actions, and setup guides.{C.RESET}\n")

        print(f"  {C.BRIGHT}1{C.RESET}.  Pi-Tail        {C.DARK}Pi Zero as WiFi bridge; keepalive, SSH, reconnect{C.RESET}")
        print(f"  {C.BRIGHT}2{C.RESET}.  NetHunter      {C.DARK}External adapter; monitor mode, injection, driver check{C.RESET}")
        print(f"  {C.BRIGHT}3{C.RESET}.  Raspberry Pi   {C.DARK}Pi as access point or bridge; hostapd/dnsmasq/NAT guides{C.RESET}")
        print(f"  {C.BRIGHT}4{C.RESET}.  Pentest        {C.DARK}Pi-Tail bridge + external adapter; combined workflow{C.RESET}")
        print(f"  {C.BRIGHT}0{C.RESET}.  None           {C.DARK}Clear current mode{C.RESET}")
        if CURRENT_MODE:
            print(f"  {C.BRIGHT}m{C.RESET}.  Open {MODE_DEFS[CURRENT_MODE]['name']} screen")
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()
        if choice == '1':
            CURRENT_MODE = 'pitail'
            _on_mode_activate('pitail')
            _mode_screen_pitail()
        elif choice == '2':
            CURRENT_MODE = 'nethunter'
            _on_mode_activate('nethunter')
            _mode_screen_nethunter()
        elif choice == '3':
            CURRENT_MODE = 'rpi'
            _on_mode_activate('rpi')
            _mode_screen_rpi()
        elif choice == '4':
            CURRENT_MODE = 'pentest'
            _on_mode_activate('pentest')
            _mode_screen_pentest()
        elif choice == '0':
            CURRENT_MODE = None
            ok("Mode cleared")
            pause()
        elif choice == 'm' and CURRENT_MODE:
            _open_mode_screen()
        elif choice in ('q', 'b', ''):
            break


def _on_mode_activate(mode):
    """Apply side-effects when a mode is selected."""
    global active_iface
    if mode == 'nethunter':
        ifaces = get_wireless_ifaces() if IS_ROOT else []
        if 'wlan1' in ifaces and active_iface != 'wlan1':
            active_iface = 'wlan1'
            ok("Active interface set to wlan1")
    elif mode == 'pentest':
        # Pentest = Pi-Tail on wlan0, attack adapter on wlan1
        ifaces = get_wireless_ifaces() if IS_ROOT else []
        if 'wlan1' in ifaces:
            active_iface = 'wlan1'
            ok("Active interface set to wlan1 (attack adapter)")


def _open_mode_screen():
    """Open the screen for the currently active mode."""
    if   CURRENT_MODE == 'pitail':    _mode_screen_pitail()
    elif CURRENT_MODE == 'nethunter': _mode_screen_nethunter()
    elif CURRENT_MODE == 'rpi':       _mode_screen_rpi()
    elif CURRENT_MODE == 'pentest':   _mode_screen_pentest()


# ── Pi-Tail mode ──────────────────────────────────────────────────────────────

def _mode_screen_pitail():
    """Pi-Tail mode screen — status, keepalive, quick actions."""
    while True:
        os.system('clear')
        print(LOGO)
        if CURRENT_MODE:
            print(f"  {C.LIME}[Pi-Tail mode]{C.RESET}")
        print(f"\n  {C.MED}{C.BOLD}── Pi-Tail {'─' * 39}{C.RESET}\n")

        reachable  = check_pitail() if IS_ROOT else False
        reach_str  = f"{C.LIME}reachable{C.RESET}" if reachable else f"{C.ERR}unreachable{C.RESET}"
        cur_ssid   = iface_ssid(PITAIL_IFACE) if IS_ROOT else "—"
        cur_ip     = iface_ip(PITAIL_IFACE)   if IS_ROOT else "—"
        kl_str     = f"{C.LIME}ON{C.RESET}"  if keepalive_running else f"{C.DARK}OFF{C.RESET}"

        print(f"  {C.BRIGHT}Pi-Tail IP : {C.WHITE}{PITAIL_IP}{C.RESET}   [{reach_str}]")
        print(f"  {C.BRIGHT}Interface  : {C.WHITE}{PITAIL_IFACE}{C.RESET}   SSID: {cur_ssid}   IP: {cur_ip}")
        print(f"  {C.BRIGHT}Keepalive  : {C.RESET}[{kl_str}]   target: {PITAIL_SSID}   every {PITAIL_KEEPALIVE_INT}s")
        print()

        print(f"  {C.MED}{C.BOLD}── Actions {'─' * 39}{C.RESET}\n")
        _menu_item('p', f"Ping Pi-Tail            ({PITAIL_IP})", IS_ROOT)
        _menu_item('s', f"SSH to Pi-Tail          (ssh pi@{PITAIL_IP})", IS_ROOT)
        _menu_item('r', f"Reconnect now           ({PITAIL_IFACE} -> '{PITAIL_SSID}')", IS_ROOT)
        _menu_item('k', f"Toggle keepalive        [{kl_str}]", IS_ROOT)
        _menu_item('K', "Configure Pi-Tail       (SSID / IP / interval)", IS_ROOT)
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()
        if   choice == 'p' and IS_ROOT:
            print(); os.system(f"ping -c 4 {PITAIL_IP}"); pause()
        elif choice == 's' and IS_ROOT:
            print(); os.system(f"ssh pi@{PITAIL_IP}")
        elif choice == 'r' and IS_ROOT:
            _connect_pitail_hotspot(); pause()
        elif choice == 'k':
            toggle_keepalive() if IS_ROOT else requires_root()
        elif choice == 'K':
            configure_keepalive() if IS_ROOT else requires_root()
        elif choice in ('p', 's', 'r') and not IS_ROOT:
            requires_root()
        elif choice in ('q', '0', 'b', ''):
            break


# ── NetHunter mode ────────────────────────────────────────────────────────────

def _mode_screen_nethunter():
    """NetHunter mode — external adapter status, monitor mode, injection."""
    while True:
        os.system('clear')
        print(LOGO)
        if CURRENT_MODE:
            print(f"  {C.LIME}[NetHunter mode]{C.RESET}")
        print(f"\n  {C.MED}{C.BOLD}── NetHunter {'─' * 37}{C.RESET}\n")

        iface      = active_iface
        mode_str   = "—"
        in_monitor = False
        mon_iface  = CMD_VARS.get('IFACE_MON', f"{iface}mon")
        all_ifaces = []

        if IS_ROOT:
            m = iface_mode(iface)
            in_monitor = (m == "monitor")
            mode_str   = (f"{C.LIME}monitor{C.RESET}" if in_monitor
                          else f"{C.BRIGHT}managed{C.RESET}")
            all_ifaces = get_wireless_ifaces()

        ip   = iface_ip(iface)   if IS_ROOT else "—"
        ssid = iface_ssid(iface) if IS_ROOT else "—"

        print(f"  {C.BRIGHT}Adapter  : {C.WHITE}{iface}{C.RESET}")
        print(f"  {C.BRIGHT}Mode     : {C.RESET}{mode_str}")
        print(f"  {C.BRIGHT}IP / SSID: {C.RESET}{ip}  /  {ssid}")
        if mon_iface in all_ifaces:
            print(f"  {C.LIME}Monitor interface {mon_iface} is active{C.RESET}")
        print()

        print(f"  {C.MED}{C.BOLD}── Actions {'─' * 39}{C.RESET}\n")
        if in_monitor:
            _menu_item('M', f"Disable monitor mode  (set {iface} back to managed)", IS_ROOT)
        else:
            _menu_item('m', f"Enable monitor mode   (iw dev {iface} set monitor none)", IS_ROOT)
        tgt_iface = mon_iface if mon_iface in all_ifaces else iface
        _menu_item('t', f"Test packet injection (aireplay-ng --test {tgt_iface})", IS_ROOT)
        print(f"  {C.BRIGHT}d{C.RESET}.  Driver manager")
        print(f"  {C.BRIGHT}c{C.RESET}.  Command reference")
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip()
        if   choice == 'm' and IS_ROOT:  _nethunter_monitor_on(iface);  pause()
        elif choice == 'M' and IS_ROOT:  _nethunter_monitor_off(iface); pause()
        elif choice == 't' and IS_ROOT:
            print(); os.system(f"aireplay-ng --test {tgt_iface}"); pause()
        elif choice in ('m', 'M', 't') and not IS_ROOT: requires_root()
        elif choice == 'd': driver_manager()
        elif choice == 'c': command_reference()
        elif choice in ('q', '0', 'b', ''): break


def _detect_monitor_iface(base_iface):
    """Scan iw dev output for a monitor-mode interface and update CMD_VARS['IFACE_MON'].
    Prefers an interface whose name starts with base_iface (e.g. wlan1mon, wlan1mon0)."""
    _, out, _ = run("iw dev 2>/dev/null")
    current = None
    best = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith('Interface '):
            current = s.split()[-1]
        elif s == 'type monitor' and current:
            if best is None or current.startswith(base_iface):
                best = current
    if best:
        CMD_VARS['IFACE_MON'] = best
        if best != f"{base_iface}mon":
            info(f"Monitor interface detected as:  {best}  (IFACE_MON updated)")
    return CMD_VARS['IFACE_MON']


def _nethunter_monitor_on(iface):
    """Enable monitor mode — tries airmon-ng first, falls back to iw.
    Auto-detects the resulting monitor interface name and updates IFACE_MON."""
    info(f"Enabling monitor mode on {iface}…")
    rc, _, _ = run("which airmon-ng")
    if rc == 0:
        os.system("airmon-ng check kill")
        os.system(f"airmon-ng start {iface}")
    else:
        os.system(f"ip link set {iface} down && "
                  f"iw dev {iface} set monitor none && "
                  f"ip link set {iface} up")
    # Detect the actual monitor interface name (may be wlan1mon, wlan1mon0, etc.)
    _detect_monitor_iface(iface)


def _nethunter_monitor_off(iface):
    """Disable monitor mode — tries airmon-ng first, falls back to iw.
    Uses CMD_VARS['IFACE_MON'] as the monitor interface name."""
    info(f"Disabling monitor mode on {iface}…")
    mon_iface = CMD_VARS.get('IFACE_MON', f"{iface}mon")
    rc, _, _  = run("which airmon-ng")
    if rc == 0:
        os.system(f"airmon-ng stop {mon_iface}")
    else:
        os.system(f"ip link set {iface} down && "
                  f"iw dev {iface} set type managed && "
                  f"ip link set {iface} up")
    # Reset IFACE_MON to the default expected name for next time
    CMD_VARS['IFACE_MON'] = f"{iface}mon"


# ── Raspberry Pi AP mode ──────────────────────────────────────────────────────

def _mode_screen_rpi():
    """Raspberry Pi AP/bridge mode — status and setup guides."""
    while True:
        os.system('clear')
        print(LOGO)
        if CURRENT_MODE:
            print(f"  {C.LIME}[Raspberry Pi AP mode]{C.RESET}")
        print(f"\n  {C.MED}{C.BOLD}── Raspberry Pi AP {'─' * 30}{C.RESET}\n")

        wlan0_ip   = iface_ip("wlan0")   if IS_ROOT else "—"
        wlan0_ssid = iface_ssid("wlan0") if IS_ROOT else "—"
        _, hp, _   = run("pgrep -x hostapd")
        _, dm, _   = run("pgrep -x dnsmasq")
        hp_str     = f"{C.LIME}running{C.RESET}" if hp else f"{C.DARK}stopped{C.RESET}"
        dm_str     = f"{C.LIME}running{C.RESET}" if dm else f"{C.DARK}stopped{C.RESET}"

        print(f"  {C.BRIGHT}wlan0   : {C.RESET}IP: {wlan0_ip}   SSID: {wlan0_ssid}")
        print(f"  {C.BRIGHT}hostapd : {C.RESET}[{hp_str}]")
        print(f"  {C.BRIGHT}dnsmasq : {C.RESET}[{dm_str}]")
        print()

        print(f"  {C.MED}{C.BOLD}── Setup Guides {'─' * 34}{C.RESET}\n")
        print(f"  {C.BRIGHT}a{C.RESET}.  Access point    (hostapd + dnsmasq)")
        print(f"  {C.BRIGHT}b{C.RESET}.  Bridge mode     (wlan0 <-> eth0)")
        print(f"  {C.BRIGHT}n{C.RESET}.  NAT / routing   (ip_forward + iptables)")
        print(f"  {C.BRIGHT}c{C.RESET}.  Command reference")
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()
        if   choice == 'a': _rpi_ap_guide()
        elif choice == 'b': _rpi_bridge_guide()
        elif choice == 'n': _rpi_nat_guide()
        elif choice == 'c': command_reference()
        elif choice in ('q', '0', 'b', ''): break


def _rpi_ap_guide():
    """Step-by-step hostapd + dnsmasq access point setup."""
    os.system('clear')
    print(LOGO)
    print(f"  {C.MED}{C.BOLD}── Pi Access Point Setup {'─' * 25}{C.RESET}\n")
    _guide_steps([
        ("1. Install tools",
         ["apt install -y hostapd dnsmasq"]),
        ("2. Configure hostapd  (/etc/hostapd/hostapd.conf)",
         ["interface=wlan0", "ssid=MyPiAP", "hw_mode=g", "channel=7",
          "wpa=2", "wpa_passphrase=MyPassword"]),
        ("3. Set static IP on wlan0",
         ["ip addr add 192.168.4.1/24 dev wlan0",
          "ip link set wlan0 up"]),
        ("4. Configure dnsmasq  (/etc/dnsmasq.conf)",
         ["interface=wlan0",
          "dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h"]),
        ("5. Start services",
         ["systemctl unmask hostapd",
          "systemctl start hostapd",
          "systemctl start dnsmasq"]),
        ("6. Enable on boot",
         ["systemctl enable hostapd dnsmasq"]),
    ])
    input(f"  {C.DARK}[Enter to go back]{C.RESET}")


def _rpi_bridge_guide():
    """wlan0 <-> eth0 bridge setup guide."""
    os.system('clear')
    print(LOGO)
    print(f"  {C.MED}{C.BOLD}── Pi Bridge Mode {'─' * 31}{C.RESET}\n")
    _guide_steps([
        ("1. Install bridge tools",
         ["apt install -y bridge-utils"]),
        ("2. Create bridge and add interfaces",
         ["brctl addbr br0",
          "brctl addif br0 eth0",
          "brctl addif br0 wlan0"]),
        ("3. Bring bridge up and get IP",
         ["ip link set br0 up",
          "dhclient br0"]),
        ("4. Persist via /etc/network/interfaces",
         ["auto br0",
          "iface br0 inet dhcp",
          "  bridge_ports eth0 wlan0"]),
    ])
    input(f"  {C.DARK}[Enter to go back]{C.RESET}")


def _rpi_nat_guide():
    """IP forwarding + iptables NAT/masquerade guide."""
    os.system('clear')
    print(LOGO)
    print(f"  {C.MED}{C.BOLD}── Pi NAT / IP Routing {'─' * 27}{C.RESET}\n")
    print(f"  {C.DARK}Share internet from eth0 out through wlan0 (Pi as router){C.RESET}\n")
    _guide_steps([
        ("1. Enable IP forwarding (runtime)",
         ["echo 1 > /proc/sys/net/ipv4/ip_forward"]),
        ("1b. Make it permanent",
         ["# add to /etc/sysctl.conf:",
          "net.ipv4.ip_forward=1"]),
        ("2. NAT masquerade — wlan0 clients out via eth0",
         ["iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
          "iptables -A FORWARD -i eth0 -o wlan0 -m state "
          "--state RELATED,ESTABLISHED -j ACCEPT",
          "iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT"]),
        ("3. Save iptables rules across reboots",
         ["apt install -y iptables-persistent",
          "netfilter-persistent save"]),
    ])
    input(f"  {C.DARK}[Enter to go back]{C.RESET}")


def _guide_steps(steps):
    """Render a list of (title, [cmd_lines]) guide steps."""
    for title, lines in steps:
        print(f"  {C.BRIGHT}{title}{C.RESET}")
        for line in lines:
            print(f"    {C.LIME}{line}{C.RESET}")
        print()


# ── Pentest mode ──────────────────────────────────────────────────────────────

def _mode_screen_pentest():
    """Pentest mode — Pi-Tail bridge on wlan0, attack adapter on wlan1."""
    while True:
        os.system('clear')
        print(LOGO)
        if CURRENT_MODE:
            print(f"  {C.LIME}[Pentest mode]{C.RESET}")
        print(f"\n  {C.MED}{C.BOLD}── Pentest {'─' * 39}{C.RESET}\n")
        print(f"  {C.DARK}wlan0 -> Pi-Tail hotspot (bridge / internet){C.RESET}")
        print(f"  {C.DARK}wlan1 -> attack adapter  (monitor / injection){C.RESET}\n")

        # wlan0 / Pi-Tail status
        reachable = check_pitail() if IS_ROOT else False
        pt_str    = f"{C.LIME}reachable{C.RESET}" if reachable else f"{C.ERR}unreachable{C.RESET}"
        kl_str    = f"{C.LIME}ON{C.RESET}" if keepalive_running else f"{C.DARK}OFF{C.RESET}"

        # wlan1 / attack adapter status
        atk_iface = 'wlan1'
        atk_mode  = iface_mode(atk_iface) if IS_ROOT else "—"
        in_mon    = (atk_mode == "monitor")
        atk_str   = f"{C.LIME}monitor{C.RESET}" if in_mon else f"{C.BRIGHT}managed{C.RESET}"

        print(f"  {C.BRIGHT}Pi-Tail  : {C.RESET}{PITAIL_IP} [{pt_str}]  keepalive [{kl_str}]")
        print(f"  {C.BRIGHT}wlan1    : {C.RESET}mode [{atk_str}]")
        print()

        print(f"  {C.MED}{C.BOLD}── Actions {'─' * 39}{C.RESET}\n")
        _menu_item('p', f"Ping Pi-Tail ({PITAIL_IP})", IS_ROOT)
        _menu_item('k', f"Toggle Pi-Tail keepalive [{kl_str}]", IS_ROOT)
        if in_mon:
            _menu_item('M', "Disable monitor mode on wlan1", IS_ROOT)
        else:
            _menu_item('m', "Enable monitor mode on wlan1", IS_ROOT)
        print(f"  {C.BRIGHT}d{C.RESET}.  Driver manager")
        print(f"  {C.BRIGHT}c{C.RESET}.  Command reference")
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip()
        if   choice == 'p' and IS_ROOT:  print(); os.system(f"ping -c 4 {PITAIL_IP}"); pause()
        elif choice == 'k':              toggle_keepalive() if IS_ROOT else requires_root()
        elif choice == 'm' and IS_ROOT:  _nethunter_monitor_on(atk_iface);  pause()
        elif choice == 'M' and IS_ROOT:  _nethunter_monitor_off(atk_iface); pause()
        elif choice in ('p','m','M') and not IS_ROOT: requires_root()
        elif choice == 'd': driver_manager()
        elif choice == 'c': command_reference()
        elif choice in ('q', '0', 'b', ''): break


# ═══════════════════════════════════════════════════════════════════════════════
#  DRIVER MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

def driver_manager():
    """Dedicated driver management submenu."""
    while True:
        print_header()
        print(f"  {C.MED}{C.BOLD}── Driver Manager {'─' * 32}{C.RESET}")
        print()
        print(f"  {C.BRIGHT}a{C.RESET}.  Auto-detect plugged adapters")
        print(f"  {C.BRIGHT}m{C.RESET}.  Show loaded WiFi modules")
        print(f"  {C.BRIGHT}D{C.RESET}.  dmesg — USB / WiFi kernel messages")
        print(f"  {C.BRIGHT}b{C.RESET}.  Browse all {len(DRIVER_DB)} supported adapters")
        print(f"  {C.BRIGHT}q{C.RESET}.  Back")
        print()
        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip()
        if   choice == 'a': _driver_detect()
        elif choice == 'm': _driver_modules()
        elif choice == 'D': _driver_dmesg()
        elif choice == 'b': _driver_browse()
        elif choice.lower() in ('q', '0', ''):
            break


def _driver_detect():
    """Auto-detect plugged USB WiFi adapters and offer to install their driver."""
    print_header()
    print(f"  {C.MED}{C.BOLD}── Auto-Detect Adapters {'─' * 26}{C.RESET}\n")
    info("Scanning USB devices…")
    matches = _lsusb_wifi_adapters()

    if not matches:
        rc, raw, _ = run("lsusb")
        if rc != 0:
            err("lsusb not found — install: apt install usbutils")
        else:
            warn("No recognised WiFi adapters found in lsusb output.")
            print(f"  {C.DARK}Tip: unplug / replug the adapter then press r from the main menu{C.RESET}\n")
            if raw:
                print(f"  {C.DARK}Raw lsusb output:{C.RESET}")
                for line in raw.splitlines():
                    print(f"    {C.DARK}{line}{C.RESET}")
        pause()
        return

    for usb_id, usb_line in matches:
        entry   = DRIVER_DB[usb_id]
        mod     = entry.get('module')
        apt_pkg = entry.get('apt')
        git_url = entry.get('git')
        mod_loaded = _module_loaded(mod)

        print(f"\n  {C.LIME}Found:{C.RESET}  {C.DARK}{usb_line}{C.RESET}")
        print(f"    {C.BRIGHT}Chip   : {C.WHITE}{entry['chip']}{C.RESET}")
        print(f"    {C.BRIGHT}Devices: {C.RESET}{entry['adapter']}")
        mon_str = (f"{C.LIME}yes — monitor mode + packet injection{C.RESET}"
                   if entry.get('monitor') else f"{C.DARK}no{C.RESET}")
        print(f"    {C.BRIGHT}Monitor: {C.RESET}{mon_str}")

        if mod:
            if mod_loaded:
                print(f"    {C.BRIGHT}Module : {C.LIME}loaded ({mod}){C.RESET}")
            else:
                print(f"    {C.BRIGHT}Module : {C.WARN}not loaded — need: {mod}{C.RESET}")

        if entry.get('note'):
            print(f"    {C.DARK}Note: {entry['note']}{C.RESET}")

        print()

        if mod_loaded:
            print(f"    {C.LIME}Driver is already loaded — adapter should be working.{C.RESET}")
            if mod:
                print(f"    {C.DARK}If no interface appeared try: ip link  or  iw dev{C.RESET}")
        elif apt_pkg or git_url:
            print(f"  {C.MED}── Install options {'─' * 30}{C.RESET}")
            if apt_pkg:
                print(f"    {C.BRIGHT}a{C.RESET}.  apt install {apt_pkg}")
            if git_url:
                short = git_url.replace("https://github.com/", "github.com/")
                print(f"    {C.BRIGHT}g{C.RESET}.  git clone + make  ({short})")
            print(f"    {C.BRIGHT}s{C.RESET}.  Skip")
            print()
            sub = input(f"  {C.BRIGHT}Choice: {C.RESET}").strip().lower()
            if sub == 'a' and apt_pkg:
                _driver_install_apt(apt_pkg)
            elif sub == 'g' and git_url:
                _driver_install_git(git_url, entry.get('git_build', 'make && make dkms_install'))
        else:
            print(f"    {C.DARK}Kernel built-in — no external driver package needed.{C.RESET}")
            if mod:
                print(f"    {C.DARK}Try: modprobe {mod}{C.RESET}")

        print()

    pause()


def _driver_install_apt(package):
    """Install a driver DKMS package via apt — streams output to terminal."""
    print()
    info(f"Installing {package} via apt…")
    warn("Needs root and an active internet connection.")
    print()
    deps = "git dkms bc build-essential libelf-dev linux-headers-$(uname -r)"
    os.system(f"apt install -y {deps}")
    os.system(f"apt install -y {package}")
    print()
    info("Done. Unplug and replug the adapter if it does not appear automatically.")


def _driver_install_git(git_url, build_cmd="make && make dkms_install"):
    """Clone a driver repo into /tmp, build and install it — streams output."""
    repo_name = git_url.rstrip('/').split('/')[-1]
    print()
    info(f"Cloning {git_url}")
    warn("Needs root, git, build tools, and an active internet connection.")
    print()
    deps = "git dkms bc build-essential libelf-dev linux-headers-$(uname -r)"
    os.system(f"apt install -y {deps}")
    os.system(
        f"cd /tmp && rm -rf {repo_name} && "
        f"git clone --depth=1 {git_url} && "
        f"cd {repo_name} && {build_cmd}"
    )
    print()
    info("Done. Unplug and replug the adapter if it does not appear automatically.")


def _driver_modules():
    """Show loaded WiFi-related kernel modules and active wireless interfaces."""
    print_header()
    print(f"  {C.MED}{C.BOLD}── Loaded WiFi Modules {'─' * 27}{C.RESET}\n")
    rc, lsmod_out, _ = run("lsmod")
    if rc != 0:
        err("lsmod failed"); pause(); return

    wifi_kw = {'wifi','wlan','rtl','ath','mt7','rt28','rt73','carl',
               'mac80211','cfg80211','88','8814','8821','8852','8188',
               '8192','8723','brcm','b43','iwl','p54','zd12'}
    found = []
    for line in lsmod_out.splitlines()[1:]:     # skip header row
        name = line.split()[0].lower() if line.split() else ''
        if any(kw in name for kw in wifi_kw):
            found.append(line)

    if not found:
        warn("No WiFi-related modules found in lsmod output.")
    else:
        print(f"  {C.DARK}{'Module':<22}{'Size':>10}  Used by{C.RESET}")
        print(f"  {C.DARK}{'─'*54}{C.RESET}")
        for line in found:
            parts  = line.split(None, 3)
            name   = parts[0] if len(parts) > 0 else ''
            size   = parts[1] if len(parts) > 1 else ''
            usedby = parts[3].strip() if len(parts) > 3 else ''
            print(f"  {C.LIME}{name:<22}{C.RESET}{C.DARK}{size:>10}{C.RESET}  {C.BRIGHT}{usedby}{C.RESET}")

    print()
    rc2, iw_out, _ = run("iw dev")
    if rc2 == 0 and iw_out:
        print(f"  {C.MED}{C.BOLD}── iw dev ──────────────────────────────────{C.RESET}")
        for line in iw_out.splitlines():
            print(f"  {C.BRIGHT}{line}{C.RESET}")
        print()

    pause()


def _driver_dmesg():
    """Show dmesg filtered for USB and WiFi-related kernel events."""
    print_header()
    print(f"  {C.MED}{C.BOLD}── dmesg — USB / WiFi Messages {'─' * 19}{C.RESET}\n")

    rc, out, _ = run(
        r"dmesg --time-format=reltime 2>/dev/null | "
        r"grep -iE '(usb|wlan|wifi|80211|rtl|ath9|mt76|rt2800|wpa|bssid|associat|auth)' | "
        r"tail -50"
    )
    if rc != 0 or not out:
        # Older kernels may not support --time-format
        rc, out, _ = run(
            r"dmesg | grep -iE '(usb|wlan|wifi|rtl|ath9|mt76|rt2800)' | tail -50"
        )

    if not out:
        warn("No relevant dmesg output (or dmesg not available).")
    else:
        for line in out.splitlines():
            low = line.lower()
            if any(w in low for w in ('error','fail','denied','disconnect','timeout')):
                print(f"  {C.ERR}{line}{C.RESET}")
            elif any(w in low for w in ('registered','connected','associate','new full','rename')):
                print(f"  {C.LIME}{line}{C.RESET}")
            else:
                print(f"  {C.BRIGHT}{line}{C.RESET}")

    print()
    pause()


def _driver_browse():
    """Scrollable browse screen — all adapters in DRIVER_DB grouped by family."""
    # Build flat item list from DRIVER_GROUPS ordering
    items = []     # ('header', label) | ('adapter', uid, entry)
    for label, uid_list in DRIVER_GROUPS:
        items.append(('header', label))
        for uid in uid_list:
            if uid in DRIVER_DB:
                items.append(('adapter', uid, DRIVER_DB[uid]))

    # Start cursor on first adapter entry
    cursor = next((i for i, it in enumerate(items) if it[0] == 'adapter'), 0)
    scroll = 0

    while True:
        try:
            tw = os.get_terminal_size().columns
            th = os.get_terminal_size().lines
        except OSError:
            tw, th = 80, 24

        list_h = max(4, th - 4)    # title(1) + nav(1) + list + footer(1) = 4 overhead

        if cursor < scroll:
            scroll = cursor
        elif cursor >= scroll + list_h:
            scroll = cursor - list_h + 1

        os.system('clear')
        # ── 2-line header ──
        print(f"  {C.LIME}{C.BOLD}>> Adapter DB{C.RESET}  "
              f"{C.DARK}{len(DRIVER_DB)} adapters   {C.LIME}*{C.DARK}=monitor mode{C.RESET}")
        print(f"  {C.DARK}↑↓ / j k  PgUp PgDn  Enter=detail  q=back{C.RESET}")

        # ── Scrollable list ──
        visible = items[scroll: scroll + list_h]
        for idx, item in enumerate(visible):
            abs_idx = scroll + idx
            if item[0] == 'header':
                label = item[1]
                pad = max(0, tw - len(label) - 8)
                print(f"  {C.MED}{C.BOLD}-- {label} {'─' * pad}{C.RESET}")
            else:
                _, uid, entry = item
                selected = (abs_idx == cursor)
                star = f"{C.LIME}*{C.RESET}" if entry.get('monitor') else f"{C.DARK}.{C.RESET}"
                chip = entry['chip']
                adap = entry['adapter']
                max_adap = max(10, tw - 30)
                if len(adap) > max_adap:
                    adap = adap[:max_adap - 1] + '~'
                if selected:
                    print(f"  {C.LIME}>{C.RESET} {star} {C.WHITE}{chip:<14}{C.RESET} {adap}")
                else:
                    print(f"    {star} {C.BRIGHT}{chip:<14}{C.RESET} {C.DARK}{adap}{C.RESET}")

        # Pad remaining rows
        for _ in range(list_h - len(visible)):
            print()

        # ── 1-line footer: detail of selected item ──
        cur = items[cursor]
        if cur[0] == 'adapter':
            _, uid, entry = cur
            apt_str = entry['apt'] or '--'
            git_str = 'yes' if entry.get('git') else '--'
            mod_str = entry.get('module') or '--'
            print(f"  {C.DARK}USB {uid}  module:{mod_str}  apt:{apt_str}  git:{git_str}{C.RESET}")
        else:
            print(f"  {C.DARK}up/down or j/k to navigate  Enter=detail  q back{C.RESET}")

        k = _getch()
        if k in ('UP', 'k'):
            cursor = max(0, cursor - 1)
            while cursor > 0 and items[cursor][0] == 'header':
                cursor -= 1
        elif k == 'PGUP':
            cursor = max(0, cursor - 10)
            while cursor > 0 and items[cursor][0] == 'header':
                cursor -= 1
        elif k in ('DOWN', 'j'):
            cursor = min(len(items) - 1, cursor + 1)
            while cursor < len(items) - 1 and items[cursor][0] == 'header':
                cursor += 1
        elif k == 'PGDN':
            cursor = min(len(items) - 1, cursor + 10)
            while cursor < len(items) - 1 and items[cursor][0] == 'header':
                cursor += 1
        elif k == 'ENTER':
            if items[cursor][0] == 'adapter':
                _, uid, entry = items[cursor]
                _driver_show_detail(uid, entry)
        elif k in ('q', 'b', 'ESC', '0'):
            break


def _driver_show_detail(uid, entry):
    """Full-screen detail + optional install for one adapter."""
    os.system('clear')
    mon_str = (f"{C.LIME}yes — monitor mode + packet injection{C.RESET}"
               if entry.get('monitor') else f"{C.DARK}no{C.RESET}")
    print(f"  {C.LIME}{C.BOLD}>> {entry['chip']}{C.RESET}   monitor: {mon_str}")
    print()
    print(f"  {C.BRIGHT}USB ID : {C.WHITE}{uid}{C.RESET}")
    print(f"  {C.BRIGHT}Chip   : {C.WHITE}{entry['chip']}{C.RESET}")
    print(f"  {C.BRIGHT}Devices: {C.RESET}{entry['adapter']}")
    if entry.get('module'):
        loaded = _module_loaded(entry['module'])
        status = f"{C.LIME}loaded{C.RESET}" if loaded else f"{C.WARN}not loaded{C.RESET}"
        print(f"  {C.BRIGHT}Module : {C.RESET}{entry['module']}  [{status}]")
    print()

    if entry.get('note'):
        print(f"  {C.DARK}{entry['note']}{C.RESET}")
        print()

    if entry.get('apt'):
        print(f"  {C.MED}-- Install via apt -------------------------------------------{C.RESET}")
        print(f"  {C.WHITE}apt install -y {entry['apt']}{C.RESET}")
        print()

    if entry.get('git'):
        rname = entry['git'].rstrip('/').split('/')[-1]
        build = entry.get('git_build', 'make && make dkms_install')
        print(f"  {C.MED}-- Install via git -------------------------------------------{C.RESET}")
        print(f"  {C.BRIGHT}git clone --depth=1 {entry['git']}{C.RESET}")
        print(f"  {C.BRIGHT}cd {rname}{C.RESET}")
        print(f"  {C.BRIGHT}{build}{C.RESET}")
        print()

    if not entry.get('apt') and not entry.get('git'):
        print(f"  {C.DARK}No external driver needed — kernel module auto-loads on plug-in.{C.RESET}")
        if entry.get('module'):
            print(f"  {C.DARK}Manual load: modprobe {entry['module']}{C.RESET}")
        print()

    has_apt = bool(entry.get('apt'))
    has_git = bool(entry.get('git'))
    if IS_ROOT and (has_apt or has_git):
        print(f"  {C.MED}-- Install now? ---------------------------------------------{C.RESET}")
        if has_apt:
            print(f"    {C.BRIGHT}a{C.RESET}.  apt install {entry['apt']}")
        if has_git:
            print(f"    {C.BRIGHT}g{C.RESET}.  git clone + make")
        print(f"    {C.BRIGHT}Enter{C.RESET}.  back")
        sub = input(f"\n  {C.BRIGHT}> {C.RESET}").strip().lower()
        if sub == 'a' and has_apt:
            _driver_install_apt(entry['apt'])
            pause()
        elif sub == 'g' and has_git:
            _driver_install_git(entry['git'], entry.get('git_build', 'make && make dkms_install'))
            pause()
    else:
        input(f"  {C.DARK}[Enter to go back]{C.RESET}")


def _jump_to_section(items, cat_name):
    """Return index of the first command after the named category header, or None."""
    for idx, (typ, data) in enumerate(items):
        if typ == 'header' and data == cat_name:
            # Find the first cmd entry after this header
            for j in range(idx + 1, len(items)):
                if items[j][0] == 'cmd':
                    return j
            return idx   # header exists but no commands follow — land on the header
    return None


def _show_section_map(items):
    """Full-screen section index overlay. Returns a jump target index or None."""
    # Collect categories that actually exist in this item list
    present = {data for typ, data in items if typ == 'header'}
    os.system('clear')
    print(f"\n  {C.LIME}{C.BOLD}≫ Jump to section{C.RESET}  {C.DARK}press key or q to cancel{C.RESET}\n")
    for key, cat in CMD_SECTION_KEYS.items():
        if cat in present:
            print(f"  {C.BRIGHT}[{key}]{C.RESET}  {cat}")
    print()
    k = _getch()
    if k in CMD_SECTION_KEYS and CMD_SECTION_KEYS[k] in present:
        return _jump_to_section(items, CMD_SECTION_KEYS[k])
    return None


def _run_cmd_ref(items, title='Muon'):
    """Shared scrollable engine used by command_reference() and attack_reference()."""
    if not items:
        return

    cursor = next((i for i, (t, _) in enumerate(items) if t == 'cmd'), 0)
    scroll = 0

    while True:
        try:
            tw = os.get_terminal_size().columns
            th = os.get_terminal_size().lines
        except OSError:
            tw, th = 80, 24

        OVERHEAD = 3   # header(1) + footer(1) + 1 spare
        list_h = max(4, th - OVERHEAD)

        if cursor < scroll:
            scroll = cursor
        elif cursor >= scroll + list_h:
            scroll = cursor - list_h + 1

        _draw_cmd_ref(items, cursor, scroll, list_h, tw, title)

        try:
            key = _getch()
        except KeyboardInterrupt:
            break

        if key in ('UP', 'k'):
            new = cursor - 1
            while new >= 0 and items[new][0] == 'header':
                new -= 1
            if new >= 0:
                cursor = new

        elif key in ('DOWN', 'j'):
            new = cursor + 1
            while new < len(items) and items[new][0] == 'header':
                new += 1
            if new < len(items):
                cursor = new

        elif key == 'PGUP':
            new = max(0, cursor - list_h)
            while new > 0 and items[new][0] == 'header':
                new += 1
            cursor = new

        elif key == 'PGDN':
            new = min(len(items) - 1, cursor + list_h)
            while new < len(items) - 1 and items[new][0] == 'header':
                new -= 1
            cursor = new

        elif key == 'ENTER':
            if items[cursor][0] == 'cmd':
                cmd = _apply_vars(items[cursor][1]['cmd'])
                os.system('clear')
                print(f"\n  {C.MED}{C.BOLD}── Run Command {'─' * 27}{C.RESET}")
                print(f"  {C.DARK}Edit if needed, then press Enter to execute. Ctrl+C to cancel.{C.RESET}\n")
                try:
                    final_cmd = _input_prefilled(f"  {C.BRIGHT}$ {C.RESET}", cmd)
                    if final_cmd.strip():
                        print()
                        os.system(final_cmd)
                except KeyboardInterrupt:
                    print()
                    warn("Cancelled")
                pause()

        elif key == 'v':
            _cmd_vars_screen()

        elif key == '?':
            target = _show_section_map(items)
            if target is not None:
                cursor = target

        elif key in CMD_SECTION_KEYS:
            # Direct jump — check that the target category exists in this item list
            cat = CMD_SECTION_KEYS[key]
            target = _jump_to_section(items, cat)
            if target is not None:
                cursor = target

        elif key in ('RIGHT', 'LEFT', 'UNKNOWN'):
            pass  # ignore — don't quit on unrecognised escape sequences

        elif key in ('q', 'b', 'ESC'):
            break


def command_reference():
    """Full-screen scrollable command reference — all categories."""
    _run_cmd_ref(_build_cmd_items(), title='Commands')


def attack_reference():
    """Attack command reference — monitor mode, capture, injection, cracking."""
    _run_cmd_ref(_build_cmd_items(filter_cats=ATTACK_CATS), title='Attack')

# ═══════════════════════════════════════════════════════════════════════════════
#  HELP / TROUBLESHOOTING
# ═══════════════════════════════════════════════════════════════════════════════
def _render_help_lines(term_w):
    """Convert HELP_CONTENT into a list of colored display strings."""
    sep = '─' * max(0, term_w - 6)
    lines = []
    for kind, text in HELP_CONTENT:
        if kind == 'section':
            pad = '─' * max(0, term_w - len(text) - 8)
            lines.append(f"  {C.LIME}{C.BOLD}── {text} {pad}{C.RESET}")
        elif kind == 'step':
            lines.append(f"  {C.BRIGHT}{text}{C.RESET}")
        elif kind == 'text':
            lines.append(f"  {C.DARK}{text}{C.RESET}")
        elif kind == 'cmd':
            lines.append(f"  {C.MED}$  {C.WHITE}{text}{C.RESET}")
        elif kind == 'note':
            lines.append(f"  {C.WARN}▸  {text}{C.RESET}")
        elif kind == 'cause':
            lines.append(f"  {C.DARK}•  {text}{C.RESET}")
        elif kind == 'blank':
            lines.append('')
    return lines


def help_screen():
    """Scrollable help and troubleshooting guide."""
    scroll = 0

    while True:
        try:
            tw = os.get_terminal_size().columns
            th = os.get_terminal_size().lines
        except OSError:
            tw, th = 80, 24

        all_lines = _render_help_lines(tw)
        list_h = max(4, th - 2)   # header(1) + content + footer(1)
        max_scroll = max(0, len(all_lines) - list_h)
        scroll = max(0, min(scroll, max_scroll))

        os.system('clear')
        print(f"  {C.LIME}{C.BOLD}≫ Help & Troubleshooting{C.RESET}"
              f"  {C.DARK}↑↓ / j k  PgUp PgDn  q=back{C.RESET}")

        visible = all_lines[scroll: scroll + list_h]
        for line in visible:
            print(line)
        for _ in range(list_h - len(visible)):
            print()

        total = len(all_lines)
        end   = min(scroll + list_h, total)
        pct   = int(100 * end / max(total, 1))
        print(f"  {C.DARK}lines {scroll + 1}–{end} of {total}  ({pct}%)  q=back{C.RESET}")

        k = _getch()
        if k in ('UP', 'k'):
            scroll = max(0, scroll - 1)
        elif k in ('DOWN', 'j'):
            scroll = min(max_scroll, scroll + 1)
        elif k == 'PGUP':
            scroll = max(0, scroll - list_h)
        elif k == 'PGDN':
            scroll = min(max_scroll, scroll + list_h)
        elif k in ('q', 'b', 'ESC', '0'):
            break


# ═══════════════════════════════════════════════════════════════════════════════
#  MONITOR MODE
# ═══════════════════════════════════════════════════════════════════════════════
def _get_iface_mode(iface):
    """Return 'monitor', 'managed', or 'unknown' for the given interface."""
    _, out, _ = run(f"iw dev {iface} info 2>/dev/null")
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith('type '):
            return stripped.split()[-1].lower()
    return 'unknown'


def monitor_mode_menu():
    """Front-page monitor mode toggle — brings adapter UP then enables monitor if needed."""
    while True:
        print_header()

        # Always re-detect on entry — catches interface name drift between sessions
        _detect_monitor_iface(active_iface)
        mon_iface = CMD_VARS.get('IFACE_MON', f"{active_iface}mon")

        # Check BOTH the original interface AND the monitor interface.
        # airmon-ng creates a NEW interface (wlan1mon) — the original (wlan1) may
        # become unknown/missing, so checking only active_iface misses this case.
        active_mode   = _get_iface_mode(active_iface)
        mon_iface_mode = _get_iface_mode(mon_iface)

        if active_mode == 'monitor':
            # iw fallback: original interface put directly in monitor mode
            mon_active  = True
            test_iface  = active_iface
            mode_str    = f"{C.LIME}{C.BOLD}MONITOR{C.RESET}  {C.DARK}({active_iface}){C.RESET}"
        elif mon_iface_mode == 'monitor':
            # airmon-ng path: separate wlan1mon interface in monitor mode
            mon_active  = True
            test_iface  = mon_iface
            mode_str    = f"{C.LIME}{C.BOLD}MONITOR{C.RESET}  {C.DARK}({mon_iface}){C.RESET}"
        else:
            mon_active  = False
            test_iface  = active_iface
            mode_str    = f"{C.BRIGHT}managed{C.RESET}  {C.DARK}({active_iface}){C.RESET}"

        print(f"{C.MED}{C.BOLD}  ── Monitor Mode — {active_iface} {'─' * 18}{C.RESET}")
        print(f"  Current mode:  {mode_str}")
        print(f"  IFACE_MON:     {C.BRIGHT}{mon_iface}{C.RESET}  {C.DARK}[v · edit if wrong]{C.RESET}\n")

        if mon_active:
            print(f"  {C.BRIGHT}d{C.RESET}.  Disable — back to managed  {C.DARK}(airmon-ng stop {mon_iface}){C.RESET}")
            print(f"  {C.BRIGHT}t{C.RESET}.  Test injection  {C.DARK}(aireplay-ng --test {test_iface}){C.RESET}")
        else:
            print(f"  {C.BRIGHT}e{C.RESET}.  Enable monitor mode  {C.DARK}(brings adapter UP first if needed){C.RESET}")
            print(f"  {C.BRIGHT}t{C.RESET}.  Test injection  {C.DARK}(requires monitor mode — enable first){C.RESET}")

        print(f"  {C.BRIGHT}k{C.RESET}.  Kill interfering processes  {C.DARK}(airmon-ng check kill){C.RESET}")
        print(f"  {C.BRIGHT}v{C.RESET}.  Edit IFACE_MON  {C.DARK}(now: {mon_iface}){C.RESET}")
        print(f"  {C.BRIGHT}0{C.RESET}.  Back")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()

        if choice == 'e' and not mon_active:
            _, link_out, _ = run(f"ip link show {active_iface} 2>/dev/null")
            if 'state DOWN' in link_out or 'state UNKNOWN' in link_out:
                info(f"Bringing {active_iface} UP first…")
                run(f"sudo ip link set {active_iface} up")
            _nethunter_monitor_on(active_iface)
            pause()

        elif choice == 'd' and mon_active:
            # Build the default disable command, then let the user edit it before running.
            # This is the same pattern as attack commands — you can fix the interface name
            # on the fly if auto-detection got it wrong.
            rc_am, _, _ = run("which airmon-ng")
            if rc_am == 0:
                default_cmd = f"airmon-ng stop {mon_iface}"
            else:
                # iw fallback: the original interface is itself in monitor mode
                default_cmd = (f"ip link set {active_iface} down && "
                               f"iw dev {active_iface} set type managed && "
                               f"ip link set {active_iface} up")
            print()
            try:
                cmd = _input_prefilled(f"  {C.BRIGHT}cmd>{C.RESET} ", default_cmd)
            except KeyboardInterrupt:
                cmd = ''
            if cmd.strip():
                print()
                os.system(cmd)
                CMD_VARS['IFACE_MON'] = f"{active_iface}mon"   # reset to default after stop
            pause()

        elif choice == 'v':
            # Manually override IFACE_MON — useful when airmon-ng picks a non-standard name
            print()
            try:
                new_val = _input_prefilled(f"  IFACE_MON > ", mon_iface)
            except KeyboardInterrupt:
                new_val = ''
            if new_val.strip() and new_val.strip() != mon_iface:
                CMD_VARS['IFACE_MON'] = new_val.strip()
                info(f"IFACE_MON set to:  {CMD_VARS['IFACE_MON']}")
                pause()

        elif choice == 't':
            if mon_active:
                print()
                os.system(f"aireplay-ng --test {test_iface}")
                pause()
            else:
                warn("Enable monitor mode first (press e).")
                pause()

        elif choice == 'k':
            print()
            os.system("airmon-ng check kill")
            pause()

        elif choice in ('0', 'q', 'b', ''):
            break


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    global active_iface
    ensure_dirs()
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    if IS_ROOT:
        # Auto-select active interface if the default (wlan1) isn't present.
        # Priority: non-protected non-p2p → wlan0 → any non-p2p.
        # p2p interfaces are never auto-selected.
        ifaces = get_wireless_ifaces()
        if active_iface not in ifaces:
            candidates = [i for i in ifaces
                          if i not in protected_ifaces and not i.startswith('p2p')]
            if not candidates:
                # Fall back to wlan0 if available, even though it's protected
                candidates = [i for i in ifaces if i == 'wlan0']
            if not candidates:
                candidates = [i for i in ifaces if not i.startswith('p2p')]
            if candidates:
                active_iface = candidates[0]

    while True:
        print_header()
        show_status()

        r = IS_ROOT   # shorthand: True = full mode, False = limited mode

        if r:
            print(f"{C.MED}{C.BOLD}  ── Active: {C.WHITE}{active_iface}"
                  f"{C.MED} {'─' * 27}{C.RESET}")
        else:
            print(f"{C.MED}{C.BOLD}  ── Menu {'─' * 34}{C.RESET}")
        print()

        iface_label = active_iface if r else "wlan0"
        _menu_item('1', f"Bring {iface_label} UP",                                           r)
        _menu_item('2', f"Bring {iface_label} DOWN",                                         r)
        _menu_item('3', "Scan networks",                                               True)
        _menu_item('4', f"Connect manually  {C.DARK}(hidden or known SSID){C.RESET}"
                        if r else "Connect manually  (hidden or known SSID)",                  r)
        _menu_item('5', f"Disconnect {iface_label}",                                          r)
        _menu_item('6', f"Monitor mode  {C.DARK}({active_iface}){C.RESET}"
                        if r else "Monitor mode",                                              r)
        _menu_item('i', f"Interfaces  {C.DARK}(active: {active_iface}){C.RESET}"
                        if r else "Interfaces",                                                r)
        if CURRENT_MODE:
            mode_name = MODE_DEFS[CURRENT_MODE]['name']
            print(f"  {C.BRIGHT}m{C.RESET}.  {C.LIME}{mode_name} screen{C.RESET}")
        print(f"  {C.BRIGHT}c{C.RESET}.  Command reference")
        print(f"  {C.BRIGHT}a{C.RESET}.  {C.LIME}Attack commands{C.RESET}  {C.DARK}(monitor · capture · inject · crack){C.RESET}")
        print(f"  {C.BRIGHT}h{C.RESET}.  Help & troubleshooting")
        print(f"  {C.BRIGHT}d{C.RESET}.  Driver manager")
        print(f"  {C.BRIGHT}s{C.RESET}.  Settings")
        print(f"  {C.BRIGHT}r{C.RESET}.  Refresh")
        print(f"  {C.BRIGHT}0{C.RESET}.  Exit")
        print()

        choice = input(f"  {C.BRIGHT}>{C.RESET} ").strip().lower()

        if   choice == '1':   bring_up()              if r else requires_root()
        elif choice == '2':   bring_down()             if r else requires_root()
        elif choice == '3':   scan_and_connect_flow()
        elif choice == '4':   connect_to_network()     if r else requires_root()
        elif choice == '5':   disconnect_iface()       if r else requires_root()
        elif choice == '6':   monitor_mode_menu()      if r else requires_root()
        elif choice == 'i':   switch_interface()       if r else requires_root()
        elif choice == 'm' and CURRENT_MODE: _open_mode_screen()
        elif choice == 'c':   command_reference()
        elif choice == 'a':   attack_reference()
        elif choice == 'h':   help_screen()
        elif choice == 'd':   driver_manager()
        elif choice == 's':   settings_menu()
        elif choice == 'r':   continue
        elif choice == '0':
            info("Goodbye.")
            sys.exit(0)

def _set_target_from_network(n):
    """Copy BSSID, SSID and CHANNEL from a scanned network dict into CMD_VARS.
    Called after the user picks a network from the scan list to use as an attack target."""
    if n.get('bssid'):
        CMD_VARS['BSSID']   = n['bssid']
    if n.get('ssid'):
        CMD_VARS['SSID']    = n['ssid']
    if n.get('channel'):
        CMD_VARS['CHANNEL'] = str(n['channel'])
    print()
    ok("Attack target saved to command variables:")
    print(f"  {C.BORDER}SSID     {C.BRIGHT}{CMD_VARS.get('SSID',    '(none)')}{C.RESET}")
    print(f"  {C.BORDER}BSSID    {C.BRIGHT}{CMD_VARS.get('BSSID',   '(not captured)')}{C.RESET}")
    print(f"  {C.BORDER}CHANNEL  {C.BRIGHT}{CMD_VARS.get('CHANNEL', '?')}{C.RESET}")
    print(f"  {C.DARK}All attack commands now reference this target.{C.RESET}")


def scan_and_connect_flow():
    """Scan networks — works in both rooted and limited (Termux) mode.
    Selecting a network sets BSSID/SSID/CHANNEL in CMD_VARS for use in attack commands.
    Connecting requires root (wpa_supplicant)."""
    print_header()
    networks = scan_networks()
    if not networks:
        return
    print()

    # Step 1 — set attack target (available in both rooted and limited mode)
    tgt = input(
        f"  {C.BRIGHT}Set attack target [1-{len(networks)}, Enter=skip]: {C.RESET}"
    ).strip()
    if tgt:
        try:
            _set_target_from_network(networks[int(tgt) - 1])
        except (ValueError, IndexError):
            warn("Invalid selection")
        print()

    if not IS_ROOT:
        info("Connecting requires root (wpa_supplicant).")
        pause()
        return

    # Step 2 — connect (rooted only)
    choice = input(
        f"  {C.BRIGHT}Connect to network [1-{len(networks)}, Enter=cancel]: {C.RESET}"
    ).strip()
    if not choice:
        return
    try:
        n = networks[int(choice) - 1]
        pw = ""
        if n.get('enc'):
            pw = getpass.getpass(f"  {C.BRIGHT}Password for '{n['ssid']}': {C.RESET}").strip()
        connect_to_network(n['ssid'], pw)
    except (ValueError, IndexError):
        err("Invalid selection"); pause()

# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    main()
