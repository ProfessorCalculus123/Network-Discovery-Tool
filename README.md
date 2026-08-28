# NetGuard SMB

NetGuard SMB is an automated local network discovery and unkwown/suspicious device scanning tool. I hope you like the generic place holder name 'Net Guard'

---

## Core Features

* **Network Discovery & Asset Tracking**: Discovers hosts via ARP sweeps, resolves hostnames, and looks up MAC vendors offline using `manuf`.


* **Port & Service Inspection**: Performs TCP connect scanning and grabs banners/versions across common administrative and networking ports.


* **DNS Interception Validation**: Dispatches native UDP queries to port 53 to verify whether real resolvers exist or if upstream routers are intercepting DNS traffic.


* **Rule-Based Security Engine**: Evaluates risks for exposed services (Telnet, FTP, SMB, NetBIOS, RDP) and audits missing HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).


* **OS Fingerprinting**: Employs SYN/ICMP TTL and TCP window heuristics to approximate remote operating systems.


* **Scan Diffing & Change Tracking**: Tracks new devices, offline nodes, DHCP IP movements, and newly exposed ports across scans using MAC address baselines.


* **FastAPI Backend & Dashboard**: Provides an authenticated ingestion API, device status tracking (active/idle/offline), approval workflows, and an HTML5/Tailwind dashboard.



---

## Architecture Overview

1. **Scanner Engine (`scanner.py`)**: Runs ARP sweeps, port probes, HTTP header checks, and rule analysis. Writes structured JSON output and triggers downstream processing.


2. **Backend API (`src/main.py`)**: Built on FastAPI and SQLAlchemy, accepting HMAC-authenticated sensor payloads and serving REST endpoints for device management.


3. **Database Layer (`src/db.py`, `src/models.py`)**: SQLite storage with Write-Ahead Logging (WAL) and automatic table schema migrations.


4. **Web UI (`src/index.html`)**: Live monitoring interface displaying active entities, security alerts, and device status with approval triggers.



---

## Project Structure

```text
.
├── scanner.py                 # Network discovery and security analysis engine
├── backend_netguard.db        # Default SQLite database location
├── scan_results/              # Output directory for raw JSON scan reports
└── src/
    ├── config.py              # Application settings and environment variables
    ├── db.py                  # SQLAlchemy engine, session maker, and base model
    ├── index.html             # Dashboard frontend template
    ├── main.py                # FastAPI routes, HMAC auth, and status logic
    ├── models.py              # Device and DeviceEvent ORM models
    ├── schemas.py             # Pydantic validation models
    └── services/
        └── device_service.py  # Ingestion logic and database persistence

```

---

## Prerequisites

* Python 3.9+
* Root or Administrator privileges (required for Scapy ARP broadcasting and raw socket SYN packets)


* Npcap (on Windows) or `libpcap` (on Linux/macOS) for Scapy packet crafting

---

## Installation

1. Install backend and scanner dependencies:

```bash
pip install fastapi uvicorn pydantic pydantic-settings sqlalchemy scapy manuf

```

2. Configure environment variables in a `.env` file at the root level:

```env
PROJECT_NAME="NetGuard SMB"
DATABASE_URL="sqlite:///./backend_netguard.db"
API_KEYS_MAP="clinic_01:sk_live_12345"
TRANSIENT_TTL_MINUTES=1440
PERSISTENCE_THRESHOLD_MINUTES=2

```

---

## Usage

### 1. Running the Backend Server

Start the API and dashboard service with Uvicorn:

```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

```

Access the web interface by navigating to `http://localhost:8000` in your browser. When prompted, provide the configured API key (e.g., `sk_live_12345`).

### 2. Executing a Network Scan

Run the scanner as root/administrator to allow raw packet construction:

```bash
sudo python scanner.py

```

* The scanner automatically detects the local subnet and interface.


* You must confirm interactive authorization by typing `yes` when prompted.


* Results are summarized in the console, diffed against historical scans, and saved to `scan_results/scan_<timestamp>.json`.



---

## API Endpoints

* `GET /`: Serves the primary web dashboard.


* `POST /api/v1/ingest`: Ingests scan payloads (secured via client ID, timestamp, nonce, and HMAC-SHA256 signature headers).


* `GET /api/v1/devices?client_id=<ID>`: Retrieves all tracked devices for a client with current operational states.


* `GET /api/v1/history?client_id=<ID>`: Fetches the last 100 logged device events.


* `PATCH /api/v1/devices/{mac}/approve?client_id=<ID>`: Marks an unknown device as known/approved.



---

## Security Disclaimer

This tool performs active SYN port scans and banner grabs. Only run this scanner against subnets you own or have explicit authorization to assess. Unauthorized network scanning may violate organizational policies and local laws.
