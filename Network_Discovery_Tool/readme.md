# NetGuard Enterprise & SMB Network Security Monitor

**NetGuard** is an end-to-end network asset discovery, security auditing, and live device monitoring platform. It combines an active network discovery & vulnerability rules engine (built on Scapy and multi-threaded socket probes) with a hardened FastAPI backend, SQLite/SQLAlchemy persistent storage, and an interactive real-time dashboard. Now, to answer your question, the reaosn behind the name Netguard is because I wanted to create a dashboard that felt real and not another no-name project; hence why I went with the generic Netguard.

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Running NetGuard](#running-netguard)
  - [1. Starting the API & Web Dashboard](#1-starting-the-api--web-dashboard)
  - [2. Running the Network Scanner](#2-running-the-network-scanner)
- [Security Rules & Findings Engine](#security-rules--findings-engine)
- [API Endpoints & Authentication](#api-endpoints--authentication)
  - [Dashboard Authentication](#dashboard-authentication)
  - [Sensor HMAC Ingestion](#sensor-hmac-ingestion)
- [Scan Diffing & Asset Tracking](#scan-diffing--asset-tracking)
- [Troubleshooting & Best Practices](#troubleshooting--best-practices)
- [License](#license)

---

## Key Features

### Active Network Reconnaissance (`scanner.py`)
- **ARP Subnet Discovery:** Multi-sweep broadcast scans over raw Layer 2 sockets.
- **Multi-threaded Port & Service Identification:** High-speed TCP connect scanning across common administrative and server ports (`21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080`).
- **Banner Grabbing & TLS Probing:** Passive and active protocol probing with automated regex parsing for SSH, HTTP Server headers, FTP, SMTP, and POP3 versions.
- **DNS Interception Validation:** Sends real UDP queries to distinguish true DNS resolvers on port 53 from router-level transparent NAT/parental control interception.
- **OS Heuristic Fingerprinting:** TTL and TCP window size analysis via thread-safe Scapy raw socket SYN probes with automated hop-count estimations.
- **Offline MAC Vendor Resolution:** Local OUI database lookup via `manuf` without external API dependencies.

### Security Rules Engine
- **Heuristic Configuration Auditing:** Flags risky services, legacy protocols, and unencrypted management interfaces (e.g., Telnet, cleartext FTP, exposed SMB/NetBIOS, exposed RDP).
- **HTTP Security Header Audits:** Inspects web services for missing defense-in-depth headers (`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`).
- **Structured Findings:** Generates standardized finding records with unique IDs (`NET-001` through `NET-010`), severity classifications, risk scores (0-10), and actionable remediation steps.

### Backend & Live UI (`FastAPI` + `TailwindCSS`)
- **Cryptographically Secured Ingest:** Replay-resistant HMAC-SHA256 sensor payload verification with nonce tracking and timestamps.
- **Device Lifecycle & Drift Tracking:** Real-time device state classification (`active`, `idle`, `offline`) based on last-seen timestamps and missed scan cycles.
- **SOC-Style Diffing:** MAC-keyed differential analysis between scans to detect new assets, decommissioned hardware, IP/DHCP changes, and newly opened ports.
- **Interactive Web Console:** Real-time responsive dashboard to monitor active entities, inspect security alerts, and acknowledge/approve unknown devices.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------+
|                         Network Scanner / Sensor                      |
|                                                                       |
|  [ARP Discovery]  --->  [Port & Banner Scan]  --->  [OS Fingerprint]  |
|                                 |                                     |
|                                 v                                     |
|                    [Security Rules Engine]                            |
|                                 |                                     |
|                                 v                                     |
|                    [Scan JSON + MAC Diffing]                          |
+-----------------------------------------------------------------------+
                                  |
                   (HMAC-SHA256 Signed Ingest)
                                  v
+-----------------------------------------------------------------------+
|                    NetGuard FastAPI Backend (src/)                    |
|                                                                       |
|   POST /api/v1/ingest           GET /api/v1/devices                   |
|   PATCH /api/v1/devices/{mac}/approve                                 |
|                                 |                                     |
|                                 v                                     |
|                    SQLite Database (WAL Mode)                         |
+-----------------------------------------------------------------------+
                                  |
                        (Live Polling / REST)
                                  v
+-----------------------------------------------------------------------+
|                       Tailwind Web Dashboard                          |
|                                                                       |
|   [Active Entities]    [Security Alerts]    [Device State & Approval] |
+-----------------------------------------------------------------------+
```

---

## Project Structure

```text
.
├── scanner.py                 # Core network discovery, banner grabber & rules engine
├── filter.py                  # Downstream filtering & data preprocessing script
├── agent.py                   # Automated reporting or AI agent processor
├── backend_netguard.db        # SQLite database (generated at runtime)
├── scan_results/              # Timestamped JSON scan outputs and historical baselines
├── src/
│   ├── config.py              # Application settings & environment parsing via Pydantic
│   ├── db.py                  # SQLAlchemy engine configuration, PRAGMA WAL & session factory
│   ├── index.html             # Single-page Tailwind CSS + Lucide Icons dashboard UI
│   ├── main.py                # FastAPI endpoints, HMAC auth, migrations & device lifecycle
│   ├── models.py              # SQLAlchemy ORM models (Device, DeviceEvent)
│   ├── schemas.py             # Pydantic validation schemas (DeviceInput, ScanPayload)
│   └── services/
│       └── device_service.py  # Business logic for device ingestion and state updates
├── .env                       # Environment configuration file
└── requirements.txt           # Python dependencies
```

---

## Installation & Setup

### Prerequisites

* **Python 3.9+**
* **Operating System:** Linux, macOS, or Windows (with `Npcap` installed in WinPcap API-compatible mode for Scapy raw packet operations)
* **Privileges:** Administrator (Windows) or `sudo` / `CAP_NET_RAW` capabilities (Linux) to send ARP and raw TCP SYN probes.

### 1. Clone Repository & Setup Virtual Environment

```bash
git clone https://github.com/your-org/netguard.git
cd netguard

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

#### Example `requirements.txt`

```text
fastapi>=0.100.0
uvicorn[standard]>=0.22.0
scapy>=2.5.0
manuf>=1.1.5
pydantic-settings>=2.0.0
pydantic>=2.0.0
sqlalchemy>=2.0.0
```

---

## Configuration

Create a `.env` file in the project root:

```env
# General Settings
PROJECT_NAME="NetGuard SMB"
DATABASE_URL="sqlite:///./backend_netguard.db"

# API Access Mapping (Format: client_id:api_key,client_id_2:api_key_2)
API_KEYS_MAP="clinic_01:sk_live_12345"

# Lifecycle Thresholds
TRANSIENT_TTL_MINUTES=1440
PERSISTENCE_THRESHOLD_MINUTES=2
```

---

## Running NetGuard

### 1. Starting the API & Web Dashboard

Start the FastAPI application with Uvicorn:

```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

* **Web Dashboard:** Open `http://localhost:8000/` in your browser.
* **API Documentation (Swagger UI):** Open `http://localhost:8000/docs`.
* **API Key Prompt:** When opening the web UI, enter your configured key (e.g. `sk_live_12345`).

---

### 2. Running the Network Scanner

Execute the scanner with elevated permissions:

```bash
# Linux / macOS
sudo python scanner.py

# Windows (Run Command Prompt or PowerShell as Administrator)
python scanner.py
```

#### Scanner Workflow:

1. Detects the primary routing interface, local IP, and subnet CIDR.
2. Prompts for explicit user authorization (`yes`) and logs the audit event to `scan_log.txt`.
3. Performs 3 discovery sweeps via ARP broadcast to catch sleeping or intermittently transmitting hosts.
4. Executes concurrent TCP connect scans and passive banner grabs across target hosts.
5. Performs OS heuristic fingerprinting and DNS UDP verification.
6. Evaluates security rules, generates a terminal summary, and saves results into `scan_results/scan_<timestamp>.json`.
7. Diffs against previous scan baselines to highlight new devices, IP changes (DHCP), or exposed ports.
8. Passes output through `filter.py` and `agent.py` pipelines.

---

## Security Rules & Findings Engine

NetGuard runs deterministic heuristic rules against every host summary:

| Rule ID | Finding Title | Severity | Port | Description & Intent |
| --- | --- | --- | --- | --- |
| **NET-001** | Telnet exposed | `HIGH` | 23 | Transmits credentials and session data in unencrypted cleartext. |
| **NET-002** | FTP exposed | `MEDIUM` | 21 | Unencrypted file transfer protocol; recommend SFTP/FTPS. |
| **NET-003** | SMB exposed | `HIGH` | 445 | Historic attack vector (e.g., EternalBlue); verify patching & isolate. |
| **NET-004** | NetBIOS exposed | `MEDIUM` | 139 | Legacy NetBIOS Session Service; disable if direct SMB is available. |
| **NET-005** | RDP exposed | `HIGH` | 3389 | Common ransomware entry vector; enforce NLA / VPN isolation. |
| **NET-006** | Potential DNS interception | `MEDIUM` | 53 | Port 53 open on TCP but failed UDP DNS response verification. |
| **NET-007** | Missing X-Frame-Options | `LOW` | HTTP/S | Clickjacking protection header missing. |
| **NET-008** | Missing Content-Security-Policy | `LOW` | HTTP/S | Mitigates cross-site scripting (XSS) and injection vulnerabilities. |
| **NET-009** | Missing Strict-Transport-Security | `LOW` | 443 | Enforces HTTPS on modern web browsers (HSTS). |
| **NET-010** | Missing X-Content-Type-Options | `LOW` | HTTP/S | Prevents MIME-type sniffing (`nosniff`). |

---

## API Endpoints & Authentication

### Dashboard Authentication

Dashboard endpoints expect the `x-api-key` header matching the client entry in `API_KEYS_MAP`.

* `GET /` — Serves the single-page HTML/Tailwind console.
* `GET /api/v1/devices?client_id=clinic_01` — Returns all discovered devices, activity statuses, and approval states.
* `GET /api/v1/history?client_id=clinic_01` — Returns recent device discovery and approval events.
* `PATCH /api/v1/devices/{mac}/approve?client_id=clinic_01` — Marks an unknown device as approved (`is_known = true`).

---

### Sensor HMAC Ingestion

The `/api/v1/ingest` endpoint accepts scan results using HMAC-SHA256 authentication to guarantee payload integrity and prevent replay attacks:

#### Required Headers:

* `x-client-id`: Client identifier (e.g. `clinic_01`).
* `x-api-timestamp`: Unix timestamp (requests older than 1800s are rejected).
* `x-api-nonce`: Unique single-use UUID/string.
* `x-api-payload-hash`: SHA256 hex digest of the raw request body.
* `x-api-signature`: HMAC-SHA256 signature calculated over:

```text
signature = HMAC_SHA256(secret_key, "{client_id}:{timestamp}:{nonce}:{payload_hash}")
```

---

## Scan Diffing & Asset Tracking

To prevent false alerts on dynamic networks:

* **MAC-Keyed Device Tracking:** Devices are correlated across scans by their hardware MAC address rather than IP address.
* **DHCP Event Detection:** If an existing MAC address reports a new IP, NetGuard logs a single `IP CHANGED (DHCP event)` rather than reporting a device deletion and new rogue device creation.
* **High-Risk Exposure Alerts:** Automatically isolates changes involving critical ports (`21, 23, 139, 445, 3389`) in the scan differential output.

---

## Troubleshooting & Best Practices

1. **No Devices Found during ARP Sweep:**
   * Verify that the terminal has administrative/root permissions.
   * If using multiple virtual interfaces (e.g. Docker, WSL, VPNs), ensure Scapy binds to the primary physical network adapter.

2. **MAC Vendor Lookup Shows "Unknown":**
   * Ensure the `manuf` package is installed: `pip install manuf`.

3. **Database Locks in SQLite:**
   * NetGuard automatically enables SQLite WAL (Write-Ahead Logging) mode and sets a `busy_timeout` of 5000ms. If running multiple concurrent ingestion processes, ensure connection pools are cleanly closed.

---

