import json
import time
import secrets
import hmac
import hashlib
from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import event

from src.db import get_db, Base, engine
from src.config import settings
from src.services.device_service import DeviceService
from src.models import DeviceEvent, Device

# ---------------- INIT DB ----------------
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()

Base.metadata.create_all(bind=engine)
# ---------------- DATABASE MIGRATION LOGIC (Add missing columns) ----------------
def run_migrations():
    """Manually injects missing columns into existing SQLite tables without data loss."""
    columns_to_add = [
        ("missed_cycles", "INTEGER DEFAULT 0"),
        ("is_randomized", "INTEGER DEFAULT 0"),
        ("name_score", "INTEGER DEFAULT 0"),
        ("resolution_source", "TEXT DEFAULT 'Unknown'")
    ]
    
    with engine.connect() as conn:
        # Check existing columns in the 'devices' table
        existing_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(devices)"))]
        
        for col_name, col_type in columns_to_add:
            if col_name not in existing_cols:
                print(f"[*] Migrating: Adding column {col_name} to table 'devices'...")
                conn.execute(text(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}"))
                conn.commit()

# Ensure you import 'text' from sqlalchemy
from sqlalchemy import text

# Run the fix
run_migrations()

app = FastAPI(title="NetGuard Enterprise")

# ---------------- STATUS COMPUTATION (Rules 1, 2, 3, 7) ----------------

def compute_status(last_seen: float, now: float, missed_cycles: int = 0) -> str:
    drift = now - last_seen
    if drift < 60 or missed_cycles < 2:
        return "active"
    elif drift < 720:
        return "idle"
    return "offline"

def serialize_device(device: Device, now: float) -> dict:
    missed = getattr(device, 'missed_cycles', 0)
    is_random = getattr(device, 'is_randomized', False)
    return {
        "id": device.id,
        "client_id": device.client_id,
        "mac": device.mac,
        "ip": device.ip,
        "hostname": device.name,
        "name": device.name,
        "confidence": device.confidence,
        "is_known": device.is_known,
        "bucket": device.bucket,
        "last_seen": device.last_seen,
        "missed_cycles": missed,
        "is_randomized": is_random,
        "status": compute_status(device.last_seen or 0, now, missed),
    }

# ---------------- AUTH HELPER (Hardened) ----------------
seen_nonces = {}

def get_keys():
    return {k.split(":")[0].strip(): k.split(":")[1].strip() for k in settings.API_KEYS_MAP.split(",") if ":" in k}

def verify_dashboard_auth(client_id: str, api_key: str):
    keys = get_keys()
    if not client_id or not secrets.compare_digest(keys.get(client_id, ""), api_key or ""):
        raise HTTPException(status_code=401, detail="Auth Failed")

def verify_sensor_hmac(client_id: str, timestamp: str, nonce: str, payload_hash: str, signature: str):
    c_id = str(client_id).strip() if client_id else ""
    if not all([c_id, timestamp, nonce, payload_hash, signature]):
        raise HTTPException(status_code=401, detail="Missing Auth Headers")
        
    now = time.time()
    if abs(now - int(timestamp)) > 1800:
        raise HTTPException(status_code=401, detail="Payload Expired")
        
    if nonce in seen_nonces:
        raise HTTPException(status_code=401, detail="Replay Attack Detected")
    seen_nonces[nonce] = now
    
    for k in list(seen_nonces.keys()):
        if now - seen_nonces[k] > 1800: del seen_nonces[k]
        
    secret_key = get_keys().get(c_id, "")
    if not secret_key:
        raise HTTPException(status_code=401, detail=f"Unknown Client ID: {c_id}")
        
    expected_sig = hmac.new(
        secret_key.encode('utf-8'), 
        f"{c_id}:{timestamp}:{nonce}:{payload_hash}".encode('utf-8'), 
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected_sig, signature):
        raise HTTPException(status_code=401, detail="Signature Verification Failed")

# ---------------- ROOT UI ----------------
@app.get("/")
async def read_index():
    return FileResponse("src/index.html")

# ---------------- INGEST (CORE PIPELINE) ----------------

@app.post("/api/v1/ingest")
async def ingest(
    request: Request,
    x_client_id: str = Header(None), 
    x_api_timestamp: str = Header(None), 
    x_api_nonce: str = Header(None),
    x_api_payload_hash: str = Header(None),
    x_api_signature: str = Header(None),
    db: Session = Depends(get_db)
):
    try:
        raw_body = await request.body()
        
        # Verify the hash of the raw body hasn't been tampered with
        actual_hash = hashlib.sha256(raw_body).hexdigest()
        if actual_hash != x_api_payload_hash:
            raise HTTPException(status_code=401, detail="Payload Tampered")
            
        # FIX: Pass all 5 required arguments to match the updated security function
        verify_sensor_hmac(x_client_id, x_api_timestamp, x_api_nonce, x_api_payload_hash, x_api_signature)

        payload = json.loads(raw_body)
        client_id = payload.get("client_id") or x_client_id

        devices = payload.get("devices", [])
        DeviceService.ingest_devices(db, client_id, devices)

        # History writing
        history_data = payload.get("history", {})
        known_events = history_data.get("known", [])
        unknown_events = history_data.get("unknown", [])

        for ev in known_events + unknown_events:
            event = DeviceEvent(
                client_id=client_id,
                mac=ev.get("mac"),
                ip=ev.get("ip"),
                name=ev.get("name"),
                confidence=ev.get("confidence", 0),
                bucket="known" if ev in known_events else "unknown",
                timestamp=ev.get("time", time.time())
            )
            db.add(event)

        db.commit()
        return {"status": "success", "devices_received": len(devices)}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Backend Crash: {str(e)}")

# ---------------- DEVICE LIST ----------------

@app.get("/api/v1/devices")
async def get_devices(
    client_id: str,
    x_api_key: str = Header(None),
    db: Session = Depends(get_db)
):
    verify_dashboard_auth(client_id, x_api_key)
    devices = db.query(Device).filter(Device.client_id == client_id).all()
    now = time.time()
    return [serialize_device(d, now) for d in devices]

# ---------------- HISTORY FETCH ----------------

@app.get("/api/v1/history")
async def get_history(
    client_id: str,
    x_api_key: str = Header(None),
    db: Session = Depends(get_db)
):
    verify_dashboard_auth(client_id, x_api_key)
    events = db.query(DeviceEvent).filter(DeviceEvent.client_id == client_id).order_by(DeviceEvent.timestamp.desc()).limit(100).all()
    return events

# ---------------- APPROVE DEVICE ----------------

@app.patch("/api/v1/devices/{mac}/approve")
async def approve_device(
    mac: str,
    client_id: str,
    x_api_key: str = Header(None),
    db: Session = Depends(get_db)
):
    verify_dashboard_auth(client_id, x_api_key)
    device = db.query(Device).filter(Device.client_id == client_id, Device.mac == mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.is_known = True
    device.bucket = "known"

    approval_event = DeviceEvent(
        client_id=client_id, mac=mac, ip=device.ip, name=device.name,
        confidence=device.confidence, bucket="manual_approval", timestamp=time.time()
    )
    db.add(approval_event)
    db.commit()
    db.refresh(device)

    now = time.time()
    missed = getattr(device, 'missed_cycles', 0)
    return {
        "status": "success",
        "mac": mac,
        "state": "known",
        "activity_status": compute_status(device.last_seen or 0, now, missed),
    }