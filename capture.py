from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time, os, json, requests, psutil
from datetime import datetime

# ---------------- CONFIG ----------------
WINDOW = 5
COOLDOWN = 15

WHITELIST = {"192.168.64.6"}
SENSITIVE_PORTS = {21, 22, 23, 3389, 445, 3306, 5432}

BRUTE_WINDOW = 20
BRUTE_THRESHOLD = 6

DOS_WINDOW = 2
DOS_THRESHOLD = 120

SYN_WINDOW = 10
SYN_THRESHOLD = 15

import os
TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = "5403111902"

# ---------------- TRACKERS ----------------
brute_force = defaultdict(lambda: defaultdict(list))
dos_tracker = defaultdict(list)
blocked_ips = set()
syn_ports = defaultdict(lambda: defaultdict(float))
horizontal_scan = defaultdict(lambda: defaultdict(dict))

last_alert = defaultdict(float)
brute_last_alert = defaultdict(float)
scan_tracker = {}

# ---------------- UTIL ----------------
def cooldown_ok(ip):
    if time.time() - last_alert[ip] < COOLDOWN:
        return False
    last_alert[ip] = time.time()
    return True

def block_ip(ip):
    if ip in blocked_ips or ip in WHITELIST:
        return
    print(f"[BLOCKED] {ip}")
    os.system(f"iptables -I INPUT -s {ip} -j DROP")
    os.system(f"ss -K dst {ip}")
    blocked_ips.add(ip)

# ---------------- GEO + THREAT ----------------
def get_location(ip):

    # demo override (your attacker)
    if ip == "192.168.64.1":
        return "India, Pune (Simulated Attack)"

    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
        return "Local Network"

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        return f"{r['country']}, {r['city']}"
    except:
        return "Unknown"
# ---------------- TELEGRAM ----------------
def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        r = requests.post(url, data={"chat_id": CHAT_ID, "text": msg})
        print("Telegram response:", r.text)
    except Exception as e:
        print("Telegram error:", e)
# ---------------- LOGGING ----------------
def threat_check(ip):
    return False
def log_alert(ip, attack_type, severity):
    loc = get_location(ip)
    threat = threat_check(ip)

    alert = {
        "ip": ip,
        "type": attack_type,
        "severity": severity,
        "location": loc,
        "threat": threat,
        "time": datetime.now().strftime("%H:%M:%S")
    }

    try:
        with open("/home/sanc/cep-proj/ids_ui/alerts.json", "r") as f:
            data = json.load(f)
    except:
        data = []

    data.append(alert)
    data = data[-50:]

    with open("/home/sanc/cep-proj/ids_ui/alerts.json", "w") as f:
        json.dump(data, f, indent=4)

    print(f"[ALERT] {ip} ({loc}) → {attack_type}")
    send_telegram(f"{attack_type} from {ip} ({loc})")

# ---------------- DETECTIONS ----------------
def detect_dos(ip):
    now = time.time()
    dos_tracker[ip].append(now)
    dos_tracker[ip] = [t for t in dos_tracker[ip] if now - t <= DOS_WINDOW]

    if len(dos_tracker[ip]) > DOS_THRESHOLD:
        if cooldown_ok(ip):
            log_alert(ip, "DOS", "HIGH")
            block_ip(ip)

def detect_syn_scan(ip, flags):
    now = time.time()

    if ip not in scan_tracker:
        scan_tracker[ip] = {"syn": 0, "ack": 0, "time": now}

    entry = scan_tracker[ip]

    if now - entry["time"] > SYN_WINDOW:
        entry["syn"] = 0
        entry["ack"] = 0
        entry["time"] = now

    if flags == "S":
        entry["syn"] += 1
    elif flags == "A":
        entry["ack"] += 1

    if entry["syn"] > SYN_THRESHOLD and entry["ack"] == 0:
        if cooldown_ok(ip):
            log_alert(ip, "SYN_SCAN", "HIGH")
            block_ip(ip)

# ---------------- PROCESS MONITOR ----------------
def monitor_processes():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ["nmap", "hydra"]:
            print(f"[PROCESS ALERT] {proc.info['name']} running")

# ---------------- MAIN ----------------
def handle(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if src in WHITELIST:
        return

    tcp = pkt[TCP]
    flags = tcp.sprintf("%flags%")
    dport = tcp.dport
    now = time.time()

    detect_dos(src)
    detect_syn_scan(src, flags)

    # -------- BRUTE FORCE --------
    if dport in SENSITIVE_PORTS:
        brute_force[src][dport].append(now)

        brute_force[src][dport] = [
            t for t in brute_force[src][dport]
            if now - t <= BRUTE_WINDOW
        ]

        attempts = len(brute_force[src][dport])

        if attempts >= BRUTE_THRESHOLD and (now - brute_last_alert[src] > COOLDOWN):
            brute_last_alert[src] = now
            log_alert(src, "BRUTE_FORCE", "HIGH")
            block_ip(src)
            brute_force[src][dport].clear()

    if flags != "S":
        return

    # -------- PORT SCAN --------
    syn_ports[src][dport] = now

    for port in list(syn_ports[src]):
        if now - syn_ports[src][port] > WINDOW:
            del syn_ports[src][port]

    port_count = len(syn_ports[src])

    if port_count >= 5 and cooldown_ok(src):
        level = "HIGH" if port_count >= 8 else "LOW"
        log_alert(src, "PORT_SCAN", level)

        if level == "HIGH":
            block_ip(src)

# ---------------- START ----------------
print("[*] Advanced IDS running")

monitor_processes()
sniff(iface="eth0", prn=handle, store=False)
