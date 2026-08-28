# NetGuard SMB

NetGuard SMB is an automated local network discovery, asset inventory, and security evaluation platform. It combines raw-packet ARP sweeps, TCP service interrogation, and rule-based risk evaluation with a FastAPI backend, SQLite persistence, and a real-time web dashboard. Also, the name is Netguard because I wanted it to feel more real to the user, so I went with a generic placeholder

---

**Core Components**

* **Network Scanner (`scanner.py`)**: Executes multi-stage ARP discovery sweeps, threaded TCP connect scans, passive banner grabs, HTTP header inspection, and TTL-based OS fingerprinting. It includes a local MAC vendor lookup engine, DNS UDP validation, and a security rules engine evaluating common port exposures.


* **FastAPI Backend Server (`main.py`, `src/`)**: Handles authenticated device ingestion via HMAC signatures, manages device state and history tracking, provides REST endpoints for device management, and serves the web UI.


* **Database & ORM (`db.py`, `models.py`)**: Implements SQLite storage with Write-Ahead Logging (WAL) enabled and provides SQLAlchemy models for device state and audit event tracking.


* **Web Dashboard (`index.html`)**: A Tailwind CSS interface providing live device activity statuses, alert counters, and manual authorization controls.



---

**Security Rules Engine**

The scanner evaluates open services against security checks:

* **NET-001**: Telnet exposed (Port 23) - High severity cleartext risk.


* **NET-002**: FTP exposed (Port 21) - Medium severity cleartext risk.


* **NET-003**: SMB exposed (Port 445) - High severity worm-class vector check.


* **NET-004**: NetBIOS exposed (Port 139) - Medium severity legacy service check.


* **NET-005**: RDP exposed (Port 3389) - High severity remote access risk.


* **NET-006**: Potential DNS Interception (Port 53) - Validates UDP responses against TCP-only interception.


* **NET-007 to NET-010**: Missing HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).



---

**Project Structure**

```text
.
├── backend_netguard.db             # Local SQLite database instance
├── scan_results/                   # Structured JSON scan outputs
├── src/
│   ├── config.py                   # Pydantic environment configuration
│   ├── db.py                       # SQLAlchemy session and engine setup
│   ├── index.html                  # Dashboard user interface
│   ├── models.py                   # Device and DeviceEvent ORM models
│   ├── schemas.py                  # Pydantic request/response schemas
│   └── services/
│       └── device_service.py       # Ingestion and normalization logic
├── scanner.py                      # Network discovery and security engine
└── main.py                         # FastAPI application entrypoint

```

---

**Prerequisites & Dependencies**

* Python 3.10+
* Administrative or root privileges (required by Scapy for raw socket creation and ARP scanning)



Install the required Python packages:

```bash
pip install scapy fastapi uvicorn sqlalchemy pydantic pydantic-settings manuf

```

---

**Configuration**

Settings are configured via environment variables or a `.env` file:

```env
PROJECT_NAME="NetGuard SMB"
DATABASE_URL="sqlite:///./backend_netguard.db"
API_KEYS_MAP="clinic_01:sk_live_12345"
TRANSIENT_TTL_MINUTES=1440
PERSISTENCE_THRESHOLD_MINUTES=2

```

---

**Execution**

**1. Start the API and Dashboard Server**

Run the FastAPI application from the project root:

```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

```

Access the web interface by navigating to `http://localhost:8000` in a browser. When prompted, authenticate using the configured API key (e.g., `sk_live_12345`).

**2. Run the Network Scanner**

Run the scanner with elevated privileges to allow raw packet operations:

```bash
sudo python scanner.py

```

When prompted, confirm network authorization to initiate ARP discovery, deep TCP port scanning, OS fingerprinting, and automated diffing against prior scan baselines.

---

**API Endpoints**

* `GET /`: Serves the monitoring dashboard UI.


* `POST /api/v1/ingest`: Secure ingestion pipeline for scan payloads verified via HMAC signatures (`x-client-id`, `x-api-timestamp`, `x-api-nonce`, `x-api-payload-hash`, `x-api-signature`).


* `GET /api/v1/devices?client_id={id}`: Retrieves all tracked network entities and their computed activity states.


* `GET /api/v1/history?client_id={id}`: Fetches the recent 100 device security and state change events.


* `PATCH /api/v1/devices/{mac}/approve?client_id={id}`: Marks an unknown entity as an approved, known device.
