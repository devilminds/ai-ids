"""Pydantic schemas for request/response validation."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------- Auth ----------

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str
    password: str = Field(min_length=6, max_length=128)


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    is_active: bool


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


# ---------- Traffic ----------

class TrafficLogCreate(BaseModel):
    source_ip: str
    dest_ip: str
    source_port: int = 0
    dest_port: int = 0
    protocol: str = "TCP"
    packet_count: int = 0
    total_bytes: float = 0.0
    duration: float = 0.0


class TrafficLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    flow_id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_count: int
    total_bytes: float
    duration: float
    predicted_label: str
    confidence_score: float
    inference_time_ms: float
    created_at: datetime


# ---------- Alerts ----------

class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    threat_level: str
    attack_type: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    title: str
    message: str
    is_resolved: bool
    confidence_score: float
    detected_at: datetime


# ---------- Prediction ----------

class PredictRequest(BaseModel):
    source_ip: str
    dest_ip: str
    source_port: int = 0
    dest_port: int = 0
    protocol: str = "TCP"
    packet_count: int
    total_bytes: float
    duration: float


class PredictResponse(BaseModel):
    predicted_label: str
    confidence_score: float
    is_malicious: bool
    traffic_log_id: int
    alert_id: Optional[str] = None
    inference_time_ms: float


# ---------- Stats ----------

class DashboardStats(BaseModel):
    total_flows: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    by_label: dict
    by_protocol: dict
    avg_inference_ms: float
