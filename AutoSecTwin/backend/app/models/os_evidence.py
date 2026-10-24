"""SQLAlchemy ORM model for operating system security evidence records."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.os_assessment import OSAssessmentRecord
    from app.models.os_finding import OSFindingRecord


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class OSEvidenceStatus(str, Enum):
    """Observation outcome for an operating system evidence signal."""

    OBSERVED = "observed"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    NOT_CHECKED = "not_checked"


class OSPermissionState(str, Enum):
    """Privilege and access state during evidence collection."""

    GRANTED = "granted"
    LIMITED = "limited"
    DENIED = "denied"


class OSEvidenceRecord(Base):
    """Database entity representing an observed OS security signal, package, port, or configuration."""

    __tablename__ = "os_evidence"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique UUID primary key for the OS evidence item",
    )

    assessment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("os_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Foreign key referencing the parent OS assessment record",
    )

    collector_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        doc="Module or collector that gathered this evidence item (e.g. 'linux_dpkg_collector')",
    )

    check_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        doc="Specific check identifier (e.g. 'dpkg_package_inventory', 'listening_sockets')",
    )

    signal_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        doc="Standardized signal classification (e.g. 'installed_package', 'open_port', 'aslr_state')",
    )

    observed_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Human-readable textual representation or summary of the observed telemetry",
    )

    structured_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Structured dictionary containing detailed telemetry (e.g. package versions, socket addresses)",
    )

    collection_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=OSEvidenceStatus.OBSERVED.value,
        index=True,
        doc="Outcome: 'observed', 'absent', 'unavailable', 'error', 'not_checked'",
    )

    permission_state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=OSPermissionState.GRANTED.value,
        doc="Permission state: 'granted', 'limited', 'denied'",
    )

    explanatory_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Contextual remarks clarifying the observation or explaining why permissions were denied",
    )

    observation_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
        doc="UTC timestamp when the observation occurred",
    )

    # Relationships
    assessment: Mapped["OSAssessmentRecord"] = relationship(
        "OSAssessmentRecord",
        back_populates="evidence_items",
    )

    findings: Mapped[List["OSFindingRecord"]] = relationship(
        "OSFindingRecord",
        back_populates="evidence",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"<OSEvidenceRecord(id={self.id}, check={self.check_id!r}, "
            f"signal={self.signal_name!r}, status={self.collection_status!r})>"
        )
