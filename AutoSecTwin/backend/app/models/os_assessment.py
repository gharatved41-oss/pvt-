"""SQLAlchemy ORM model for operating system security assessment sessions and lifecycle."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, Set

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.os_asset import OSAssetRecord
    from app.models.os_evidence import OSEvidenceRecord
    from app.models.os_finding import OSFindingRecord


class OSAssessmentStatus(str, Enum):
    """Lifecycle states for operating system assessment execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# Valid state machine transitions
VALID_OS_STATUS_TRANSITIONS: Dict[str, Set[str]] = {
    OSAssessmentStatus.PENDING.value: {
        OSAssessmentStatus.RUNNING.value,
        OSAssessmentStatus.FAILED.value,
    },
    OSAssessmentStatus.RUNNING.value: {
        OSAssessmentStatus.COMPLETED.value,
        OSAssessmentStatus.FAILED.value,
    },
    OSAssessmentStatus.COMPLETED.value: set(),
    OSAssessmentStatus.FAILED.value: set(),
}


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class OSAssessmentRecord(Base):
    """Database entity representing an operating system security assessment run."""

    __tablename__ = "os_assessments"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique UUID primary key for the assessment session",
    )

    asset_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("os_assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Foreign key referencing the target asset (nullable if asset profile pruned)",
    )

    assessment_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="local_read_only",
        doc="Assessment execution mode ('local_read_only')",
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=OSAssessmentStatus.PENDING.value,
        index=True,
        doc="Lifecycle state ('pending', 'running', 'completed', 'failed')",
    )

    risk_policy_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="policy_v1.0",
        doc="Version identifier of the scoring policy applied",
    )

    risk_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Transparent composite risk score (0 to 100), or None if incomplete",
    )

    risk_level: Mapped[Optional[str]] = mapped_column(
        String(30),
        nullable=True,
        doc="Risk rating category: 'low', 'medium', 'high', 'critical'",
    )

    confidence_level: Mapped[Optional[str]] = mapped_column(
        String(30),
        nullable=True,
        default="low",
        doc="Overall assessment confidence: 'low', 'medium', 'high'",
    )

    exploitability_state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="unknown",
        doc="Overall exploitability state (strictly 'unknown' for static read-only audits)",
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Diagnostic error details if assessment execution failed",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
        doc="UTC timestamp when the assessment was created",
    )

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="UTC timestamp when the assessment reached a terminal state",
    )

    owner_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        default=None,
        doc="Subject or user identifier who created and owns this assessment session",
    )

    # Relationships
    asset: Mapped[Optional["OSAssetRecord"]] = relationship(
        "OSAssetRecord",
        back_populates="assessments",
    )

    evidence_items: Mapped[List["OSEvidenceRecord"]] = relationship(
        "OSEvidenceRecord",
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="OSEvidenceRecord.observation_timestamp",
    )

    findings: Mapped[List["OSFindingRecord"]] = relationship(
        "OSFindingRecord",
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="OSFindingRecord.created_at",
    )

    def can_transition_to(self, new_status: str) -> bool:
        """Validate whether transition from current status to new_status is allowed."""
        allowed = VALID_OS_STATUS_TRANSITIONS.get(self.status, set())
        return new_status in allowed

    def __repr__(self) -> str:
        return (
            f"<OSAssessmentRecord(id={self.id}, status={self.status!r}, "
            f"score={self.risk_score}, exploitability={self.exploitability_state!r})>"
        )
