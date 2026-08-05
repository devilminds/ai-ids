"""Prediction endpoint: scores a flow with the trained model, logs it, and
raises an Alert automatically if the flow looks malicious. Every prediction
is timed (model inference only, not DB/network overhead) and broadcast to
any connected WebSocket dashboards in real time.

Also includes:
- /simulate: one-shot burst of N synthetic flows through the pipeline
- /live/start, /live/stop, /live/status: a continuous background generator
  that pushes a new flow through the pipeline every couple of seconds,
  broadcasting each one live — this is what gives the dashboard "live data"
  without needing real packet capture.
"""
import asyncio
import random
import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .database import get_db, SessionLocal
from .models import TrafficLog, Alert, User
from .schemas import PredictRequest, PredictResponse
from .security import get_current_user
from .ml.predict import predict_flow
from .ws_manager import manager

router = APIRouter(prefix="/api", tags=["Detection"])

MALICIOUS_LABELS = {"dos", "ddos", "port_scan", "brute_force"}
THREAT_LEVEL_BY_LABEL = {
    "dos": "high",
    "ddos": "critical",
    "port_scan": "medium",
    "brute_force": "high",
}

# In-memory state for the background live-traffic generator. A single shared
# instance is enough for a "friends/testers share one deployment" setup —
# if this ever becomes multi-tenant, this needs to move to per-user state.
_live_state = {"enabled": False, "task": None, "interval_seconds": 2.0}


def _score_and_store(db: Session, flow: dict) -> tuple[TrafficLog, Alert | None, float]:
    """Runs the flow through the model, timing ONLY the inference call, then
    persists the result. Returns (log, alert_or_none, inference_time_ms)."""
    start = time.perf_counter()
    label, confidence = predict_flow(flow)
    inference_ms = (time.perf_counter() - start) * 1000

    log = TrafficLog(
        source_ip=flow["source_ip"],
        dest_ip=flow["dest_ip"],
        source_port=flow.get("source_port", 0),
        dest_port=flow.get("dest_port", 0),
        protocol=flow.get("protocol", "TCP"),
        packet_count=flow["packet_count"],
        total_bytes=flow["total_bytes"],
        duration=flow["duration"],
        predicted_label=label,
        confidence_score=confidence,
        inference_time_ms=inference_ms,
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    alert = None
    if label in MALICIOUS_LABELS:
        alert = Alert(
            threat_level=THREAT_LEVEL_BY_LABEL.get(label, "medium"),
            attack_type=label,
            source_ip=flow["source_ip"],
            dest_ip=flow["dest_ip"],
            title=f"{label.replace('_', ' ').title()} detected from {flow['source_ip']}",
            message=(
                f"Flow {log.flow_id} from {flow['source_ip']}:{flow.get('source_port', 0)} "
                f"to {flow['dest_ip']}:{flow.get('dest_port', 0)} classified as "
                f"'{label}' with {confidence:.1%} confidence."
            ),
            confidence_score=confidence,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

    return log, alert, inference_ms


def _flow_to_ws_message(log: TrafficLog, alert: Alert | None) -> dict:
    return {
        "type": "flow",
        "flow": {
            "id": log.id,
            "flow_id": log.flow_id,
            "source_ip": log.source_ip,
            "dest_ip": log.dest_ip,
            "source_port": log.source_port,
            "dest_port": log.dest_port,
            "protocol": log.protocol,
            "total_bytes": log.total_bytes,
            "predicted_label": log.predicted_label,
            "confidence_score": log.confidence_score,
            "inference_time_ms": round(log.inference_time_ms, 3),
            "created_at": log.created_at.isoformat(),
        },
        "alert": (
            {
                "alert_id": alert.alert_id,
                "threat_level": alert.threat_level,
                "attack_type": alert.attack_type,
                "source_ip": alert.source_ip,
                "title": alert.title,
                "message": alert.message,
                "detected_at": alert.detected_at.isoformat(),
            }
            if alert
            else None
        ),
    }


@router.post("/predict", response_model=PredictResponse)
async def predict(
    data: PredictRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    log, alert, inference_ms = _score_and_store(db, data.model_dump())
    await manager.broadcast(_flow_to_ws_message(log, alert))
    return PredictResponse(
        predicted_label=log.predicted_label,
        confidence_score=log.confidence_score,
        is_malicious=log.predicted_label in MALICIOUS_LABELS,
        traffic_log_id=log.id,
        alert_id=alert.alert_id if alert else None,
        inference_time_ms=round(inference_ms, 3),
    )


def _random_flow() -> dict:
    """Build one plausible flow, weighted mostly toward normal traffic."""
    kind = random.choices(
        ["normal", "dos", "ddos", "port_scan", "brute_force"],
        weights=[70, 8, 5, 10, 7],
    )[0]

    src = f"192.168.1.{random.randint(2, 254)}"
    dst = f"10.0.0.{random.randint(2, 254)}"

    if kind == "normal":
        return dict(source_ip=src, dest_ip=dst, source_port=random.randint(1024, 65535),
                    dest_port=random.choice([80, 443, 22, 53]), protocol=random.choice(["TCP", "UDP"]),
                    packet_count=random.randint(5, 60), total_bytes=random.uniform(3000, 14000),
                    duration=random.uniform(0.5, 4.0))
    if kind == "dos":
        return dict(source_ip=src, dest_ip=dst, source_port=random.randint(1024, 65535),
                    dest_port=random.choice([80, 443]), protocol="TCP",
                    packet_count=random.randint(500, 5000), total_bytes=random.uniform(40000, 90000),
                    duration=random.uniform(0.2, 0.8))
    if kind == "ddos":
        return dict(source_ip=src, dest_ip=dst, source_port=random.randint(1, 65535),
                    dest_port=random.choice([80, 443, 53]), protocol=random.choice(["TCP", "UDP"]),
                    packet_count=random.randint(2000, 20000), total_bytes=random.uniform(200000, 400000),
                    duration=random.uniform(0.05, 0.3))
    if kind == "port_scan":
        return dict(source_ip=src, dest_ip=dst, source_port=random.randint(1024, 65535),
                    dest_port=random.randint(1, 1024), protocol="TCP",
                    packet_count=random.randint(1, 4), total_bytes=random.uniform(40, 200),
                    duration=random.uniform(0.01, 0.08))
    return dict(source_ip=src, dest_ip=dst, source_port=random.randint(1024, 65535),
                dest_port=random.choice([22, 21, 3389, 445]), protocol="TCP",
                packet_count=random.randint(50, 400), total_bytes=random.uniform(10000, 20000),
                duration=random.uniform(2.0, 8.0))


@router.post("/simulate")
def simulate(
    count: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate `count` synthetic flows through the live prediction pipeline
    in one burst (no WebSocket broadcast per-flow, for speed — use /live/start
    for a real-time trickle instead)."""
    count = max(1, min(count, 200))
    created_alerts = 0
    for _ in range(count):
        _, alert, _ = _score_and_store(db, _random_flow())
        if alert:
            created_alerts += 1
    return {"flows_created": count, "alerts_created": created_alerts}


async def _live_loop():
    while _live_state["enabled"]:
        db = SessionLocal()
        try:
            log, alert, _ = _score_and_store(db, _random_flow())
            await manager.broadcast(_flow_to_ws_message(log, alert))
        finally:
            db.close()
        await asyncio.sleep(_live_state["interval_seconds"])


@router.post("/live/start")
async def live_start(
    interval_seconds: float = 2.0,
    current_user: User = Depends(get_current_user),
):
    """Start the background live-traffic generator: one new (real-time-scored)
    flow every `interval_seconds`, pushed to all connected dashboards over
    WebSocket as it happens."""
    interval_seconds = max(0.5, min(interval_seconds, 30))
    _live_state["interval_seconds"] = interval_seconds
    if not _live_state["enabled"]:
        _live_state["enabled"] = True
        _live_state["task"] = asyncio.create_task(_live_loop())
    return {"live": True, "interval_seconds": interval_seconds}


@router.post("/live/stop")
async def live_stop(current_user: User = Depends(get_current_user)):
    _live_state["enabled"] = False
    if _live_state["task"]:
        _live_state["task"].cancel()
        _live_state["task"] = None
    return {"live": False}


@router.get("/live/status")
async def live_status(current_user: User = Depends(get_current_user)):
    return {"live": _live_state["enabled"], "interval_seconds": _live_state["interval_seconds"]}
