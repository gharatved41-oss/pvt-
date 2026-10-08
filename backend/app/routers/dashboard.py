from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List
from pydantic import BaseModel
from datetime import datetime

from backend.app.database import get_db
from backend.app.models.database import Analysis, SystemEvent

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

class AnalysisModel(BaseModel):
    id: int
    analysis_id: str
    submitted_url: str
    verdict: str
    risk_score: int
    created_at: datetime

    class Config:
        from_attributes = True

class SystemEventModel(BaseModel):
    id: int
    event_type: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True

class DashboardTelemetry(BaseModel):
    analyses: List[AnalysisModel]
    system_events: List[SystemEventModel]

@router.get("/", response_model=DashboardTelemetry)
def get_dashboard_telemetry(db: Session = Depends(get_db)):
    analyses_qs = db.query(Analysis).order_by(desc(Analysis.created_at)).limit(10).all()
    events_qs = db.query(SystemEvent).order_by(desc(SystemEvent.created_at)).limit(10).all()

    return DashboardTelemetry(
        analyses=analyses_qs if analyses_qs else [],
        system_events=events_qs if events_qs else []
    )
