"""Alert listing and resolution endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .database import get_db
from .models import Alert, User
from .schemas import AlertResponse
from .security import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    limit: int = Query(50, le=500),
    threat_level: Optional[str] = None,
    resolved: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(Alert).order_by(Alert.detected_at.desc())
    if threat_level:
        q = q.filter(Alert.threat_level == threat_level.lower())
    if resolved is not None:
        q = q.filter(Alert.is_resolved == resolved)
    return q.limit(limit).all()


@router.post("/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    db.commit()
    db.refresh(alert)
    return alert
