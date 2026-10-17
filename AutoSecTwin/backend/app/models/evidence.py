"""SQLAlchemy ORM model for security evidence records."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class SecurityEvidenceRecord(Base):
    """Database entity representing an observed security signal or evidence item."""

    __tablename__ = "security_evidence"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique UUID primary key for the evidence record",
    )

    analysis_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analyses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Foreign key referencing the parent analysis record",
    )

    signal_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        doc="Standardized signal identifier (e.g., 'url_scheme', 'hostname_type')",
    )

    observed_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Observed textual representation or summary of the signal",
    )

    structured_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Structured dictionary containing detailed telemetry or raw observations",
    )

    evidence_source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="passive_syntax_analyzer",
        doc="Module or provider that gathered this evidence item",
    )

    observation_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
        doc="UTC timestamp when the observation occurred",
    )

    collection_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="observed",
        doc="Observation outcome: 'observed', 'absent', or 'error'",
    )

    explanatory_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Contextual remarks clarifying the observation without asserting unverified security conclusions",
    )

    # Relationship back to AnalysisRecord
    analysis: Mapped["AnalysisRecord"] = relationship(  # noqa: F821
        "AnalysisRecord",
        back_populates="evidence_items",
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityEvidenceRecord(id={self.id}, signal={self.signal_name!r}, "
            f"status={self.collection_status!r})>"
        )
