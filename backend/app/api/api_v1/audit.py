from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from ...core.database import get_db
from ...models.models import AuditEvent, User
from ...schemas.schemas import AuditEventResponse
from ..deps import get_current_user

router = APIRouter(prefix="/audit", tags=["Audit Logs"])

@router.get("", response_model=List[AuditEventResponse])
def get_audit_logs(
    event_type: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    return query.order_by(AuditEvent.created_at.desc()).limit(limit).all()
