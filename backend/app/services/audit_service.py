from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from ..models.models import AuditEvent

class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        event_type: str,  # auth, assessment, validation, remediation, twin, security
        action: str,
        user_id: Optional[str] = None,
        user_email: str = "system",
        ip_address: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            action=action,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            details=details or {}
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

audit_service = AuditService()
