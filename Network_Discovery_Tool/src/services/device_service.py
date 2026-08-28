import time
import json
from src.models import Device

class DeviceService:
    @staticmethod
    def ingest_devices(db, client_id, devices):
        
        # FIX C & F: Strict schema enforcement at the API boundary
        if isinstance(devices, str):
            try:
                devices = json.loads(devices)
            except Exception:
                return

        if isinstance(devices, dict):
            devices = devices.get("devices", [devices])

        if not isinstance(devices, list):
            return

        for d in devices:
            # Final safety check: skip malformed entries
            if not isinstance(d, dict):
                continue
                
            db_data = {k: v for k, v in d.items() if k != 'status'}
            
            mac_address = db_data.get("mac")
            if not mac_address:
                continue

            device = db.query(Device).filter_by(client_id=client_id, mac=mac_address).first()
            
            if device:
                # Update existing
                device.ip = db_data.get("ip", device.ip)
                device.name = db_data.get("hostname", device.name)
                device.last_seen = db_data.get("last_seen", time.time())
                device.missed_cycles = db_data.get("missed_cycles", 0)
                device.name_score = db_data.get("name_score", device.name_score)
                device.resolution_source = db_data.get("resolution_source", device.resolution_source)
                
                if not device.is_known:
                    device.is_known = db_data.get("is_known", False)
                    device.bucket = db_data.get("bucket", device.bucket)
            else:
                # Create new
                new_device = Device(
                    client_id=client_id,
                    mac=mac_address,
                    ip=db_data.get("ip", "Unknown"),
                    name=db_data.get("hostname", "Unknown"),
                    confidence=db_data.get("confidence", 0),
                    is_known=db_data.get("is_known", False),
                    bucket=db_data.get("bucket", "unknown"),
                    last_seen=db_data.get("last_seen", time.time()),
                    missed_cycles=db_data.get("missed_cycles", 0),
                    is_randomized=db_data.get("is_randomized", False),
                    name_score=db_data.get("name_score", 0),
                    resolution_source=db_data.get("resolution_source", "Unknown")
                )
                db.add(new_device)