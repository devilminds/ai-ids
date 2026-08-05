"""SQLAlchemy ORM models: User, TrafficLog, Alert."""
import uuid
from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from .database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)  # user, analyst, admin
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class TrafficLog(Base):
    """A single network flow record, either captured or predicted on."""

    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(String(36), unique=True, default=gen_uuid, index=True)

    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, default=0)
    dest_port = Column(Integer, default=0)
    protocol = Column(String(10), default="TCP", index=True)

    packet_count = Column(Integer, default=0)
    total_bytes = Column(Float, default=0.0)
    duration = Column(Float, default=0.0)

    predicted_label = Column(String(30), default="normal", index=True)
    confidence_score = Column(Float, default=0.0)
    inference_time_ms = Column(Float, default=0.0)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class Alert(Base):
    """A security alert, usually generated from a suspicious TrafficLog."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(36), unique=True, default=gen_uuid, index=True)

    threat_level = Column(String(20), default="low", index=True)  # low, medium, high, critical
    attack_type = Column(String(50), nullable=True)

    source_ip = Column(String(45), nullable=True, index=True)
    dest_ip = Column(String(45), nullable=True)

    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)

    is_resolved = Column(Boolean, default=False, index=True)
    confidence_score = Column(Float, default=0.0)

    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
