from sqlalchemy import Column, Integer, String, Float, Boolean
from src.db import Base

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, index=True)
    mac = Column(String, index=True)
    ip = Column(String)
    name = Column(String)
    confidence = Column(Integer)
    is_known = Column(Boolean, default=False)
    bucket = Column(String)
    last_seen = Column(Float, default=0.0)
    # FIX: Add these to match the hardened scanner data
    name_score = Column(Integer, default=0)
    resolution_source = Column(String, default="Unknown")
    missed_cycles = Column(Integer, default=0)
    is_randomized = Column(Boolean, default=False)

class DeviceEvent(Base):
    __tablename__ = "device_events"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, index=True)
    mac = Column(String, index=True)
    ip = Column(String)
    name = Column(String)
    confidence = Column(Integer)
    bucket = Column(String)
    timestamp = Column(Float, index=True)