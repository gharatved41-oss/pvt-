"""SQLAlchemy ORM model for assessed operating system assets."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.os_assessment import OSAssessmentRecord


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class OSAssetRecord(Base):
    """Database entity representing an assessed computer or operating system environment."""

    __tablename__ = "os_assets"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique UUID primary key for the assessed asset",
    )

    host_identifier: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Anonymized SHA-256 identifier representing the physical or virtual host",
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Local system hostname as observed during assessment",
    )

    os_family: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        doc="High-level operating system family ('windows', 'linux')",
    )

    os_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="Full human-readable OS distribution name (e.g. 'Ubuntu 22.04 LTS', 'Windows 11 Pro')",
    )

    os_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        doc="OS version release identifier (e.g. '22.04', '23H2')",
    )

    os_build: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        doc="Detailed kernel release or build revision (e.g. '6.5.0-28-generic', '22631.3447')",
    )

    architecture: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="x86_64",
        doc="Hardware architecture (e.g. 'x86_64', 'aarch64')",
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
        doc="UTC timestamp when the asset profile was recorded",
    )

    owner_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        default=None,
        doc="Subject or user identifier who owns and registered this asset profile",
    )

    # Relationships
    assessments: Mapped[List["OSAssessmentRecord"]] = relationship(
        "OSAssessmentRecord",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="OSAssessmentRecord.created_at.desc()",
    )

    def __repr__(self) -> str:
        return (
            f"<OSAssetRecord(id={self.id}, hostname={self.hostname!r}, "
            f"os_family={self.os_family!r}, os_name={self.os_name!r})>"
        )
