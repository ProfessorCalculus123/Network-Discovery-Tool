import requests
import time
import socket
import os
import re
import uuid
import threading
import sqlite3
import json
import hashlib
import hmac
import queue
import copy
import random
import logging
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from scapy.all import ARP, Ether, srp, conf
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

# ---------------- CONFIG & SECURITY ----------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("NetGuard-Sensor")

API_URL = os.getenv("NETGUARD_API_URL", "http://localhost:8000/api/v1/ingest")
API_KEY = os.getenv("NETGUARD_API_KEY")
CLIENT_ID = os.getenv("NETGUARD_CLIENT_ID", "clinic_01").strip()
DEBUG_MODE = os.getenv("NETGUARD_DEBUG", "True").lower() in ("true", "1", "yes")

if not API_KEY:
    logger.fatal("[!] FATAL: NETGUARD_API_KEY environment variable is missing.")
    exit(1)

if not API_URL.startswith("https://") and not DEBUG_MODE:
    logger.fatal("[!] FATAL: API_URL must use HTTPS in production. Enable DEBUG_MODE for local testing.")
    exit(1)

MAX_OFFLINE_TTL = 604800  
MAX_DEVICES = 2000        
MAX_MDNS_ENTRIES = 500    

DB_DIR = os.getenv("NETGUARD_DB_DIR", "/var/lib/netguard")
os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, "netguard.db")
FAILED_PAYLOADS_FILE = os.path.join(DB_DIR, "failed_payloads.jsonl")

# ---------------- GLOBAL STATE, LOCKS & THREADS ----------------
mdns_lock = threading.Lock()
mdns_store = {}
mdns_timestamps = {}  

state_lock = threading.Lock() 
devices_state = {}    

sync_lock = threading.Lock()
last_payload_hash = None      
last_db_save = 0 

zc_instance = None 
dns_pool = ThreadPoolExecutor(max_workers=10)

dns_cache = {}
dns_cache_ttl = {}
dns_cache_lock = threading.Lock()

error_lock = threading.Lock()
error_counters = {"DHCP": 0, "mDNS": 0, "DNS": 0, "SCAN": 0, "DB": 0, "API": 0}
metrics = {"dropped_payloads": 0, "scan_duration": 0.0}

sync_queue = queue.Queue(maxsize=100)
db_queue = queue.Queue(maxsize=200)
shutdown_event = threading.Event()

def handle_error(subsystem, error):
    with error_lock:
        error_counters[subsystem] = error_counters.get(subsystem, 0) + 1
    if DEBUG_MODE:
        logger.error(f"[!] {subsystem} Error: {error}")

def clean_legacy_cache():
    for f in ["devices.json", "netguard_state.json", "netguard_state.tmp.json"]:
        if os.path.exists(f):
            try: os.remove(f)
            except: pass

def enqueue_safe(q, item):
    try: q.put_nowait(item)
    except queue.Full:
        try: q.get_nowait()
        except queue.Empty: pass
        try: 
            q.put_nowait(item)
            metrics["dropped_payloads"] += 1
        except queue.Full: pass

# ---------------- INPUT VALIDATION & MAC ----------------
def is_valid_mac(mac):
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return not (ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified)
    except Exception:
        return False

def is_random_mac(mac):
    try: return bool(int(mac.split(':')[0], 16) & 0x02)
    except: return False

# ---------------- DATABASE & HISTORY LAYER (Fully Async) ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, bucket TEXT, 
                  is_known INTEGER, last_seen REAL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS device_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, mac TEXT, 
                  event_type TEXT, old_val TEXT, new_val TEXT, reason TEXT)''')
    
    columns_to_add = [
        ("name_score", "INTEGER DEFAULT 0"),
        ("resolution_source", "TEXT DEFAULT 'Unknown'"),
        ("missed_cycles", "INTEGER DEFAULT 0"),
        ("is_randomized", "INTEGER DEFAULT 0"),
        ("first_seen", "REAL DEFAULT 0"),
        ("version", "INTEGER DEFAULT 1"),
        ("last_changed", "REAL DEFAULT 0")
    ]
    for col, dtype in columns_to_add:
        try: c.execute(f"ALTER TABLE devices ADD COLUMN {col} {dtype}")
        except sqlite3.OperationalError: pass 
            
    conn.commit()
    conn.close()

def log_history(mac, event_type, old_val, new_val, reason=""):
    enqueue_safe(db_queue, {
        "type": "history", 
        "data": (time.time(), mac, event_type, str(old_val), str(new_val), reason)
    })

def load_state():
    global devices_state
    clean_legacy_cache()
    init_db()
    with state_lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            for row in c.execute('SELECT mac, ip, hostname, bucket, is_known, last_seen, name_score, resolution_source, missed_cycles, is_randomized, first_seen, version, last_changed FROM devices'):
                devices_state[row[0]] = {
                    "mac": row[0], "ip": row[1], "hostname": row[2],
                    "bucket": row[3], "is_known": bool(row[4]), "last_seen": row[5],
                    "name_score": row[6] if row[6] is not None else 0,
                    "resolution_source": row[7] if row[7] is not None else 'Unknown',
                    "missed_cycles": row[8] if row[8] is not None else 0,
                    "is_randomized": bool(row[9] if row[9] is not None else False),
                    "first_seen": row[10] if row[10] else row[5],
                    "version": row[11] if row[11] is not None else 1,
                    "last_changed": row[12] if row[12] else row[5]
                }
            conn.close()
            logger.info(f"[*] Loaded {len(devices_state)} devices strictly from SQLite.")
        except Exception as e:
            handle_error("DB", e)

def db_worker():
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    
    while not shutdown_event.is_set():
        try:
            task = db_queue.get(timeout=1)
            tasks = [task]
            
            while not db_queue.empty() and len(tasks) < 50:
                try: tasks.append(db_queue.get_nowait())
                except queue.Empty: break
                
            c = conn.cursor()
            for t in tasks:
                if t["type"] == "state":
                    for mac, data in t["data"].items():
                        c.execute('''INSERT OR REPLACE INTO devices
                                     (mac, ip, hostname, bucket, is_known, last_seen, name_score, resolution_source, missed_cycles, is_randomized, first_seen, version, last_changed)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                  (mac, data['ip'], data['hostname'], data['bucket'], int(data['is_known']), 
                                   data['last_seen'], data['name_score'], data['resolution_source'], data.get('missed_cycles', 0), 
                                   int(data.get('is_randomized', False)), data.get('first_seen', 0), data.get('version', 1), data.get('last_changed', 0)))
                elif t["type"] == "history":
                    c.execute("INSERT INTO device_history (timestamp, mac, event_type, old_val, new_val, reason) VALUES (?, ?, ?, ?, ?, ?)", t["data"])
                
                db_queue.task_done()
                
            conn.commit()
        except queue.Empty: pass
        except Exception as e: handle_error("DB_WORKER", e)
    conn.close()

# ---------------- NETWORK HARDWARE ----------------
def get_my_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    for net, mask, gw, iface, addr, metric in conf.route.routes:
        if addr == ip and mask != 0 and mask != 0xFFFFFFFF:
            try: return str(ipaddress.IPv4Network((net, mask))), ip
            except Exception: continue
    prefix = ".".join(ip.split(".")[:-1])
    return f"{prefix}.0/24", ip

def get_my_mac():
    mac_num = hex(uuid.getnode()).replace('0x', '').zfill(12)
    return ':'.join(mac_num[i: i + 2] for i in range(0, 12, 2)).lower()

def get_gateway_ip():
    try:
        gw = conf.route.route("0.0.0.0")[2]
        if gw != "0.0.0.0": return gw
    except Exception as e: handle_error("SCAN", e)
    return None

# ---------------- RESOLUTION SOURCES & CACHING ----------------
def clean_hostname(name):
    if not name: return None
    name = name.strip().replace("@", "")
    name = re.sub(r"-[0-9a-fA-F]{8,}$", "", name)
    name = re.sub(r"-[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$", "", name)
    if re.fullmatch(r"[A-Z0-9]{8,}", name): return None
    if len(name.strip()) < 3: return None
    return name.strip()

def cached_dns_lookup(ip):
    now = time.time()
    with dns_cache_lock:
        if len(dns_cache) > 1000:
            oldest_ip = next(iter(dns_cache))
            dns_cache.pop(oldest_ip, None)
            dns_cache_ttl.pop(oldest_ip, None)

        if ip in dns_cache and now - dns_cache_ttl.get(ip, 0) < 60:
            return dns_cache[ip]

    try:
        future = dns_pool.submit(socket.gethostbyaddr, ip)
        result = clean_hostname(future.result(timeout=1.0)[0])
        with dns_cache_lock:
            dns_cache[ip] = result
            dns_cache_ttl[ip] = now
        return result
    except:
        return None

def read_dhcp():
    leases = {}
    paths = ["/var/lib/dhcp/dhcpd.leases", "/var/lib/misc/dnsmasq.leases"]
    for path in paths:
        if not os.path.exists(path): continue
        try:
            with open(path, "r", errors="ignore") as f:
                blocks = re.split(r"\nlease\s+", f.read())
            for b in blocks[1:]:
                mac_m = re.search(r"hardware ethernet\s+([0-9a-fA-F:]{17})", b)
                host_m = re.search(r'client-hostname\s+"([^"]+)"', b)
                if mac_m and host_m:
                    mac = mac_m.group(1).lower()
                    if not is_valid_mac(mac): continue 
                    name = clean_hostname(host_m.group(1))
                    if name: leases[mac] = name
        except Exception as e: handle_error("DHCP", e)
    return leases

def vendor(mac):
    try:
        oui = mac.lower().replace(":", "")[:6]
        vendors = {
            "84788b": "Apple", "dca632": "Google", "a4c3f0": "Samsung", 
            "b827eb": "Raspberry Pi", "001a11": "Cisco", "0024e4": "Withings",
            "001788": "Philips Lighting", "f0b5d1": "Ubiquiti", "000c29": "VMware",
            "080027": "VirtualBox"
        }
        return vendors.get(oui)
    except: return None

# ---------------- mDNS ----------------
class MDNSListener(ServiceListener):
    def add_service(self, zc, type_, name): self.handle(zc, type_, name)
    def update_service(self, zc, type_, name): self.handle(zc, type_, name)
    def remove_service(self, zc, type_, name): pass
    def handle(self, zc, type_, name):
        try:
            info = zc.get_service_info(type_, name)
            if not info: return
            clean = clean_hostname(name.split(".")[0])
            if not clean: return
            for ip in info.parsed_addresses():
                if is_valid_ip(ip):
                    with mdns_lock:
                        mdns_store[ip] = clean
                        mdns_timestamps[ip] = time.time()
        except Exception as e: handle_error("mDNS", e)

def start_mdns():
    global zc_instance
    if zc_instance is None:
        zc_instance = Zeroconf()
        services = ["_workstation._tcp.local.", "_http._tcp.local.", "_googlecast._tcp.local.", "_airplay._tcp.local."]
        for s in services: 
            ServiceBrowser(zc_instance, s, MDNSListener())
    return zc_instance

def cleanup_mdns():
    now = time.time()
    with mdns_lock:
        for ip in list(mdns_timestamps.keys()):
            if now - mdns_timestamps[ip] > 1200:
                mdns_store.pop(ip, None)
                mdns_timestamps.pop(ip, None)
        
        if len(mdns_timestamps) > MAX_MDNS_ENTRIES:
            sorted_ips = sorted(mdns_timestamps.items(), key=lambda x: x[1])
            for i in range(len(mdns_timestamps) - MAX_MDNS_ENTRIES):
                ip_to_drop = sorted_ips[i][0]
                mdns_store.pop(ip_to_drop, None)
                mdns_timestamps.pop(ip_to_drop, None)

def mdns_cleanup_worker():
    while not shutdown_event.is_set():
        cleanup_mdns()
        shutdown_event.wait(60)

# ---------------- RESOLUTION ----------------
def resolve_name(mac, ip, dhcp):
    if mac in dhcp: return dhcp[mac], 4, "DHCP"
    with mdns_lock:
        if ip in mdns_store: return mdns_store[ip], 3, "mDNS"
    dns = cached_dns_lookup(ip)
    if dns: return dns, 2, "DNS"
    v = vendor(mac)
    if v: return f"{v} Device", 1, "Vendor OUI"
    return f"Unknown ({ip})", 0, "Unknown"

# ---------------- DETECTION & STATUS RULES ----------------
def detect_devices(network):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=2, retry=1, verbose=False)
    return {r.hwsrc.lower(): r.psrc for _, r in ans if is_valid_mac(r.hwsrc) and is_valid_ip(r.psrc)}

def compute_status(last_seen, now, scan_delay, missed_cycles=0):
    drift = now - last_seen
    if drift <= 90:
        return "active"
    if missed_cycles <= 2 or drift <= 600:
        return "idle"
    return "offline"

# ---------------- STATE & CLASSIFICATION LAYER ----------------
def update_state(detected, dhcp, my_ip, my_mac, gateway_ip, scan_delay):
    global last_payload_hash
    global last_db_save
    
    now = time.time()
    force_db_write = False 

    with state_lock:
        if my_mac not in devices_state:
            devices_state[my_mac] = {
                "mac": my_mac, "ip": my_ip, "hostname": "This PC", 
                "bucket": "system", "is_known": True, "last_seen": now, 
                "name_score": 99, "resolution_source": "System", "missed_cycles": 0, 
                "is_randomized": False, "first_seen": now, "version": 1, "last_changed": now
            }
            force_db_write = True
        else:
            devices_state[my_mac]["last_seen"] = now
            devices_state[my_mac]["missed_cycles"] = 0
            if devices_state[my_mac]["ip"] != my_ip:
                log_history(my_mac, "IP_CHANGE", devices_state[my_mac]["ip"], my_ip)
                devices_state[my_mac]["ip"] = my_ip
                devices_state[my_mac]["version"] = devices_state[my_mac].get("version", 1) + 1
                devices_state[my_mac]["last_changed"] = now
                force_db_write = True

        for mac, data in devices_state.items():
            if mac == my_mac: continue
            if mac in detected:
                data["missed_cycles"] = 0
                data["last_seen"] = now
                if data["ip"] != detected[mac]:
                    log_history(mac, "IP_CHANGE", data["ip"], detected[mac])
                    data["ip"] = detected[mac]
                    data["version"] = data.get("version", 1) + 1
                    data["last_changed"] = now
                    force_db_write = True
            else:
                data["missed_cycles"] += 1

        for mac, ip in detected.items():
            if ip == my_ip: continue
            is_gateway = gateway_ip is not None and ip == gateway_ip
            
            if is_gateway:
                new_name, new_score, new_source = "Network Gateway", 99, "System"
            else:
                new_name, new_score, new_source = resolve_name(mac, ip, dhcp)

            if mac not in devices_state:
                devices_state[mac] = {
                    "mac": mac, "ip": ip, "hostname": new_name,
                    "bucket": "system" if is_gateway else "persistent",
                    "is_known": True if is_gateway else False,
                    "last_seen": now, "name_score": new_score,
                    "resolution_source": new_source, "missed_cycles": 0, 
                    "is_randomized": is_random_mac(mac), "first_seen": now,
                    "version": 1, "last_changed": now
                }
                log_history(mac, "NEW_DEVICE", "None", new_name, f"Source: {new_source}")
                force_db_write = True
            else:
                current_score = devices_state[mac].get("name_score", -1)
                if new_score > current_score:
                    old_name = devices_state[mac]["hostname"]
                    devices_state[mac]["hostname"] = new_name
                    devices_state[mac]["name_score"] = new_score
                    devices_state[mac]["resolution_source"] = new_source
                    devices_state[mac]["version"] = devices_state[mac].get("version", 1) + 1
                    devices_state[mac]["last_changed"] = now
                    
                    if DEBUG_MODE:
                        logger.info(f"[*] [UPGRADE] {mac}: {old_name} -> {new_name} (via {new_source})")
                    log_history(mac, "NAME_UPGRADE", old_name, new_name, f"via {new_source}")
                    force_db_write = True

        payload = []
        logger.info(f"--- NETWORK STATE UPDATE (Tracking {len(devices_state)} entities) ---")
        
        def sort_priority(device):
            if device["hostname"] == "This PC": return 1
            if device["hostname"] == "Network Gateway": return 2
            return 3

        for mac, data in list(devices_state.items()):
            drift = now - data["last_seen"]
            
            if drift > MAX_OFFLINE_TTL:
                if data.get("bucket") != "archived":
                    data["bucket"] = "archived"
                    data["version"] = data.get("version", 1) + 1
                    data["last_changed"] = now
                    force_db_write = True
                
                data["status"] = "offline"
                dynamic_status = "offline"
            else:
                dynamic_status = compute_status(data["last_seen"], now, scan_delay, data.get("missed_cycles", 0))
            
            payload_device = copy.deepcopy(data) 
            payload_device["status"] = dynamic_status
            
            if DEBUG_MODE:
                tag = "[SYSTEM]" if payload_device["is_known"] else "[SCANNED]"
                source_tag = f"[{payload_device['resolution_source']}]"
                logger.debug(f"{tag} {payload_device['ip']:<14} | {mac} ({payload_device['hostname']}) {source_tag} [{dynamic_status.upper()}]")
            
            payload.append(payload_device)

        payload.sort(key=lambda d: (sort_priority(d), d.get("ip", "255.255.255.255")))

        # --- FIX E: Ensure we ONLY enqueue Python native objects ---
        payload_str = json.dumps(payload, sort_keys=True)
        current_hash = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
        
        should_sync = False
        if current_hash != last_payload_hash:
            last_payload_hash = current_hash
            should_sync = True

        state_snapshot = copy.deepcopy(devices_state)

    if should_sync: 
        # ENQUEUE OBJECTS, NOT STRINGS
        enqueue_safe(sync_queue, payload)
    
    if force_db_write or (now - last_db_save > 60):
        enqueue_safe(db_queue, {"type": "state", "data": state_snapshot})
        last_db_save = now

    return payload

# ---------------- DELTA SYNC ENGINE (SECURE API CLIENT) ----------------

# FIX G: Validate minimum required fields per device
def validate_device(d):
    return isinstance(d, dict) and "mac" in d and "ip" in d

# FIX A: Normalization Gauntlet ensures strict list[dict]
def normalize_devices(payload):
    if isinstance(payload, str):
        try: payload = json.loads(payload)
        except Exception: return []

    if isinstance(payload, dict):
        payload = payload.get("devices", [])

    if isinstance(payload, str):
        try: payload = json.loads(payload)
        except Exception: return []

    if not isinstance(payload, list):
        return []

    return [d for d in payload if validate_device(d)]

def sync_worker():
    while not shutdown_event.is_set():
        try:
            # FIX B: Never store or read raw JSON strings in the retry queue
            if os.path.exists(FAILED_PAYLOADS_FILE):
                with open(FAILED_PAYLOADS_FILE, "r") as f:
                    for line in f:
                        try:
                            # Safely load into object before enqueuing
                            enqueue_safe(sync_queue, json.loads(line.strip()))
                        except Exception: pass
                os.remove(FAILED_PAYLOADS_FILE)

            # Pull object from queue
            raw_payload = sync_queue.get(timeout=1)
            
            # Apply normalization gauntlet
            clean_device_list = normalize_devices(raw_payload)
            if not clean_device_list:
                sync_queue.task_done()
                continue
                
            # Construct final payload structure
            payload_dict = {"client_id": CLIENT_ID.strip(), "devices": clean_device_list}
            raw_body = json.dumps(payload_dict, separators=(',', ':'))
            encoded_body = raw_body.encode('utf-8')
            payload_hash = hashlib.sha256(encoded_body).hexdigest()
            
            safe_client = CLIENT_ID.strip()
            safe_key = API_KEY.strip()

            success = False
            for attempt in range(3):
                if shutdown_event.is_set(): break
                
                timestamp = str(int(time.time()))
                nonce = uuid.uuid4().hex
                signature = hmac.new(
                    safe_key.encode('utf-8'), 
                    f"{safe_client}:{timestamp}:{nonce}:{payload_hash}".encode('utf-8'), 
                    hashlib.sha256
                ).hexdigest()

                headers = {
                    "X-Client-ID": safe_client,
                    "X-API-Timestamp": timestamp,
                    "X-API-Nonce": nonce,
                    "X-API-Payload-Hash": payload_hash,
                    "X-API-Signature": signature,
                    "Content-Type": "application/json"
                }
                
                try:
                    time.sleep(0.5) 
                    resp = requests.post(API_URL, data=encoded_body, headers=headers, timeout=5)
                    
                    if resp.status_code == 401:
                        logger.warning(f"Backend Rejection Reason: {resp.text}")
                        
                    resp.raise_for_status()
                    if DEBUG_MODE: logger.info(f"[+] Synced devices to backend. (Sig: {signature[:8]})")
                    success = True
                    break
                except requests.RequestException as e:
                    logger.warning(f"API Sync retry {attempt+1}/3: {e}")
                    shutdown_event.wait(2 ** attempt)
            
            if not success:
                handle_error("API_TRANSPORT", "Failed to sync after 3 retries. Saving to disk buffer.")
                try:
                    with open(FAILED_PAYLOADS_FILE, "a") as f:
                        # Write clean_device_list natively so it loads as a list[dict]
                        f.write(json.dumps(clean_device_list) + "\n")
                except Exception as file_err:
                    handle_error("DISK_WRITE", file_err)

            sync_queue.task_done()
        except queue.Empty: pass
        except Exception as e: handle_error("API_FATAL", e)

# ---------------- DAEMON MAIN ----------------
if __name__ == "__main__":
    if os.getuid() != 0:
        logger.fatal("[!] ERROR: This script requires root privileges to execute raw ARP packets.")
        exit(1)

    logger.info("[*] Initializing NetGuard Sensor (Production RC1.3)")
    threading.Thread(target=sync_worker, daemon=True).start()
    threading.Thread(target=db_worker, daemon=True).start()
    threading.Thread(target=mdns_cleanup_worker, daemon=True).start() 

    load_state()
    start_mdns()
    
    consecutive_scan_failures = 0
    loops = 0
    BASE_SCAN_DELAY = 10 
    
    try:
        network, my_ip = get_my_network()
        my_mac = get_my_mac()
        gateway_ip = get_gateway_ip() 
        logger.info(f"[*] Scanner Online -> IP: {my_ip} | Target: {network}")

        while not shutdown_event.is_set():
            scan_start = time.time()
            try:
                dhcp = read_dhcp()
                detected_macs = detect_devices(network)
                with error_lock: consecutive_scan_failures = 0
                
                devices = update_state(detected_macs, dhcp, my_ip, my_mac, gateway_ip, BASE_SCAN_DELAY)

                metrics["scan_duration"] = round(time.time() - scan_start, 2)
                
                loops += 1
                if loops % 10 == 0:
                    if DEBUG_MODE:
                        with error_lock: 
                            logger.info(f"[*] Health Stats: Errors {error_counters} | Metrics {metrics}")

                actual_delay = BASE_SCAN_DELAY * random.uniform(0.95, 1.05)
                shutdown_event.wait(actual_delay)

            except KeyboardInterrupt:
                logger.info("SIGINT Received. Shutting down...")
                shutdown_event.set()
            except Exception as e:
                handle_error("SCAN_LOOP", e)
                with error_lock:
                    consecutive_scan_failures += 1
                    failures = consecutive_scan_failures
                
                backoff = min(failures * 5, 60)
                if DEBUG_MODE: logger.warning(f"[!] Scan loop failed. Backing off for {backoff} seconds...")
                shutdown_event.wait(backoff)

    finally:
        logger.info("[*] Initiating staged shutdown. Flushing queues...")
        shutdown_event.set()
        
        try: db_queue.join()
        except: pass
        
        if zc_instance: zc_instance.close()
        dns_pool.shutdown(wait=False)
        logger.info("[*] Daemon cleanly exited.")