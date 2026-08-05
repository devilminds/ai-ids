"""Traffic flow listing and statistics endpoints."""
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from .database import get_db
from .models import TrafficLog, Alert, User
from .schemas import TrafficLogResponse, DashboardStats
from .security import get_current_user

router = APIRouter(prefix="/api/traffic", tags=["Traffic"])


@router.get("/", response_model=list[TrafficLogResponse])
def list_traffic(
    limit: int = Query(50, le=500),
    offset: int = 0,
    protocol: Optional[str] = None,
    label: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(TrafficLog).order_by(TrafficLog.created_at.desc())
    if protocol:
        q = q.filter(TrafficLog.protocol == protocol.upper())
    if label:
        q = q.filter(TrafficLog.predicted_label == label.lower())
    if search:
        like = f"%{search}%"
        q = q.filter((TrafficLog.source_ip.like(like)) | (TrafficLog.dest_ip.like(like)))
    return q.offset(offset).limit(limit).all()


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total_flows = db.query(TrafficLog).count()
    total_alerts = db.query(Alert).count()
    open_alerts = db.query(Alert).filter(Alert.is_resolved.is_(False)).count()
    critical_alerts = db.query(Alert).filter(Alert.threat_level == "critical").count()

    by_label_rows = (
        db.query(TrafficLog.predicted_label, func.count(TrafficLog.id))
        .group_by(TrafficLog.predicted_label)
        .all()
    )
    by_protocol_rows = (
        db.query(TrafficLog.protocol, func.count(TrafficLog.id))
        .group_by(TrafficLog.protocol)
        .all()
    )

    avg_inference_ms = db.query(func.avg(TrafficLog.inference_time_ms)).scalar() or 0.0

    return DashboardStats(
        total_flows=total_flows,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        by_label={label: count for label, count in by_label_rows},
        by_protocol={proto: count for proto, count in by_protocol_rows},
        avg_inference_ms=round(float(avg_inference_ms), 3),
    )


@router.get("/top-attackers")
def top_attackers(
    limit: int = Query(5, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Source IPs with the most alerts against them, worst first."""
    rows = (
        db.query(Alert.source_ip, func.count(Alert.id).label("alert_count"))
        .filter(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )
    return [{"source_ip": ip, "alert_count": count} for ip, count in rows]


@router.get("/timeline")
def traffic_timeline(
    minutes: int = Query(15, le=180),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Flow counts bucketed per minute for the last N minutes, split by
    normal vs malicious, for the activity-over-time chart."""
    since = datetime.utcnow() - timedelta(minutes=minutes)
    rows = (
        db.query(TrafficLog.created_at, TrafficLog.predicted_label)
        .filter(TrafficLog.created_at >= since)
        .all()
    )

    buckets: dict[str, dict[str, int]] = {}
    for created_at, label in rows:
        bucket_key = created_at.strftime("%H:%M")
        buckets.setdefault(bucket_key, {"normal": 0, "malicious": 0})
        if label == "normal":
            buckets[bucket_key]["normal"] += 1
        else:
            buckets[bucket_key]["malicious"] += 1

    ordered_keys = sorted(buckets.keys())
    return {
        "labels": ordered_keys,
        "normal": [buckets[k]["normal"] for k in ordered_keys],
        "malicious": [buckets[k]["malicious"] for k in ordered_keys],
    }

