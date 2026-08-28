from pydantic import BaseModel
from typing import List, Optional

class DeviceInput(BaseModel):
    mac: str
    ip: Optional[str] = "Unknown"
    hostname: Optional[str] = "Unknown"
    is_known: Optional[bool] = False
    bucket: Optional[str] = "Persistent"
    last_seen: Optional[float] = 0.0
    name_score: Optional[int] = 0
    resolution_source: Optional[str] = "Unknown"
    missed_cycles: Optional[int] = 0
    is_randomized: Optional[bool] = False
    status: Optional[str] = "active"

class ScanPayload(BaseModel):
    client_id: str
    devices: List[DeviceInput]