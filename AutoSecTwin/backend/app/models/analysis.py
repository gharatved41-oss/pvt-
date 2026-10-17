"""SQLAlchemy ORM model for security analysis records with lifecycle management."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, Set

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.evidence import SecurityEvidenceRecord


class AnalysisStatus(str, Enum):
    """Lifecycle states for target analysis execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# Valid state machine transitions
VALID_STATUS_TRANSITIONS: Dict[str, Set[str]] = {
    AnalysisStatus.PENDING.value: {AnalysisStatus.RUNNING.value, AnalysisStatus.FAILED.value},
    AnalysisStatus.RUNNING.value: {AnalysisStatus.COMPLETED.value, AnalysisStatus.FAILED.value},
    AnalysisStatus.COMPLETED.value: set(),
    AnalysisStatus.FAILED.value: set(),
}


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class AnalysisRecord(Base):
    """Database entity representing an individual target analysis request."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique UUID primary key for the analysis record",
    )

    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Canonical submitted target URL",
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AnalysisStatus.PENDING.value,
        index=True,
        doc="Current state of analysis ('pending', 'running', 'completed', 'failed')",
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Error or failure message if the analysis failed",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
        doc="UTC timestamp when the submission was recorded",
    )

    # Relationship to SecurityEvidenceRecord
    evidence_items: Mapped[List["SecurityEvidenceRecord"]] = relationship(
        "SecurityEvidenceRecord",
        back_populates="analysis",
        cascade="all, delete-orphan",
        order_by="SecurityEvidenceRecord.observation_timestamp",
    )

    def can_transition_to(self, new_status: str) -> bool:
        """Check whether transition from current status to new_status is valid."""
        allowed = VALID_STATUS_TRANSITIONS.get(self.status, set())
        return new_status in allowed

    def __repr__(self) -> str:
        return f"<AnalysisRecord(id={self.id}, url={self.url!r}, status={self.status!r})>"
