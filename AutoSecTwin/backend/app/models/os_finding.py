"""SQLAlchemy ORM model for operating system vulnerability and security findings."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.os_assessment import OSAssessmentRecord
    from app.models.os_evidence import OSEvidenceRecord


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class OSSeverity(str, Enum):
    """Authoritative severity rating from vendor advisory or CVSS mapping."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRATED = "unrated"


class OSConfidence(str, Enum):
    """Degree of certainty in the finding based on evidence breadth."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OSExploitability(str, Enum):
    """Empirical verification state of exploitability. Strictly UNKNOWN by default."""

    UNKNOWN = "unknown"
    THEORETICAL = "theoretical"
    VERIFIED = "verified"


class OSFindingType(str, Enum):
    """Classification of the security finding."""

    CVE_VULNERABILITY = "cve_vulnerability"
    MISCONFIGURATION = "misconfiguration"
    MISSING_PATCH = "missing_patch"


class OSFindingRecord(Base):
    """Database entity representing an identified vulnerability or security misconfiguration."""

    __tablename__ = "os_findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique UUID primary key for the finding",
    )

    assessment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("os_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Foreign key referencing the parent OS assessment record",
    )

    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("os_evidence.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Foreign key referencing the primary supporting evidence item",
    )

    finding_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=OSFindingType.CVE_VULNERABILITY.value,
        index=True,
        doc="Type of issue: 'cve_vulnerability', 'misconfiguration', 'missing_patch'",
    )

    advisory_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        doc="Vendor advisory or public vulnerability ID (e.g. 'CVE-2023-4911', 'USN-6409-1')",
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Short descriptive summary of the finding",
    )

    component_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True,
        doc="Affected software component or package (e.g. 'glibc', 'openssl')",
    )

    installed_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        doc="Installed component version observed on the system",
    )

    fixed_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        doc="Minimum patched version specified in the vendor advisory",
    )

    cvss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        doc="Authoritative CVSS base score (0.0 to 10.0), or None if unrated",
    )

    cvss_version: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
        default="3.1",
        doc="CVSS specification version (e.g. '3.1')",
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=OSSeverity.UNRATED.value,
        index=True,
        doc="Authoritative severity: 'critical', 'high', 'medium', 'low', 'unrated'",
    )

    confidence: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=OSConfidence.LOW.value,
        doc="Confidence level: 'high', 'medium', 'low'",
    )

    exploitability: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=OSExploitability.UNKNOWN.value,
        doc="Exploitability verification state (strictly 'unknown' by default)",
    )

    advisory_source: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        doc="Origin of the advisory (e.g. 'canonical_usn', 'debian_tracker', 'microsoft_msrc')",
    )

    match_basis: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        doc="Criteria used to establish the match (e.g. 'exact_package_version', 'os_build_delta')",
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Detailed description of the vulnerability and security implications",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
        doc="UTC timestamp when the finding was generated",
    )

    # Relationships
    assessment: Mapped["OSAssessmentRecord"] = relationship(
        "OSAssessmentRecord",
        back_populates="findings",
    )

    evidence: Mapped[Optional["OSEvidenceRecord"]] = relationship(
        "OSEvidenceRecord",
        back_populates="findings",
    )

    def __repr__(self) -> str:
        return (
            f"<OSFindingRecord(id={self.id}, advisory={self.advisory_id!r}, "
            f"component={self.component_name!r}, severity={self.severity!r}, "
            f"exploitability={self.exploitability!r})>"
        )
