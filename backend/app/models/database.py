"""Database models for AutoSecTwin.
Maps exact entities specified in Section 10 & SafePath feature.
"""
from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship

from backend.app.db.session import Base


def utcnow():
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), unique=True, index=True, nullable=False, default=lambda: f"AST-{uuid.uuid4().hex[:8].upper()}")
    indicator_type = Column(String(32), default="URL", index=True)  # URL, DOMAIN, HASH
    submitted_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), index=True, nullable=True)
    hostname = Column(String(255), nullable=True)
    scheme = Column(String(16), nullable=True)
    path = Column(Text, nullable=True)
    query_present = Column(Boolean, default=False)
    
    # Risk and Verdict
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(32), index=True, nullable=False)  # LOW, GUARDED, SUSPICIOUS, HIGH
    confidence = Column(Float, nullable=False, default=0.5)
    exploitability_level = Column(String(32), default="UNKNOWN")  # LOW, MEDIUM, HIGH, UNKNOWN
    verdict = Column(String(32), index=True, nullable=False)  # SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN
    
    # State & Metadata
    status = Column(String(32), default="COMPLETED")  # QUEUED, COMPLETED, PARTIAL, FAILED
    summary = Column(Text, nullable=True)
    duration_ms = Column(Integer, default=0)
    is_demo = Column(Boolean, default=False, index=True)
    
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    indicators = relationship("Indicator", back_populates="analysis", cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="analysis", cascade="all, delete-orphan")
    provider_results = relationship("ProviderResult", back_populates="analysis", cascade="all, delete-orphan")
    recommendations = relationship("Recommendation", back_populates="analysis", cascade="all, delete-orphan")
    safepath = relationship("SafePathRecommendation", back_populates="analysis", uselist=False, cascade="all, delete-orphan")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(32), nullable=False)  # DOMAIN, URL, IP, HASH
    indicator_value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    analysis = relationship("Analysis", back_populates="indicators")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(64), nullable=False)  # url_signals, domain_signals, reputation, threat_intel, history
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(128), nullable=False)
    severity = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    impact_score = Column(Integer, default=0)
    observed_at = Column(DateTime(timezone=True), default=utcnow)
    metadata_json = Column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="evidence_items")


class ProviderResult(Base):
    __tablename__ = "provider_results"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False)  # AVAILABLE, UNAVAILABLE, RATE_LIMITED, ERROR
    classification = Column(String(64), nullable=False)  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    confidence = Column(Float, default=0.5)
    raw_reference = Column(Text, nullable=True)
    observed_at = Column(DateTime(timezone=True), default=utcnow)

    analysis = relationship("Analysis", back_populates="provider_results")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    priority = Column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    effort = Column(String(32), default="LOW")  # LOW, MEDIUM, HIGH
    coverage = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    analysis = relationship("Analysis", back_populates="recommendations")


class AnalysisComparison(Base):
    __tablename__ = "analysis_comparisons"

    id = Column(Integer, primary_key=True, index=True)
    current_analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    previous_analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    risk_delta = Column(Integer, default=0)
    confidence_delta = Column(Float, default=0.0)
    verdict_changed = Column(Boolean, default=False)
    previous_verdict = Column(String(32), nullable=True)
    current_verdict = Column(String(32), nullable=True)
    previous_risk_score = Column(Integer, default=0)
    current_risk_score = Column(Integer, default=0)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class SafePathRecommendation(Base):
    __tablename__ = "safepath_recommendations"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    software_name = Column(String(128), nullable=False)
    original_url = Column(Text, nullable=False)
    original_risk = Column(Integer, default=0)
    recommended_name = Column(String(128), nullable=False)
    recommended_url = Column(Text, nullable=False)
    recommended_domain = Column(String(255), nullable=False)
    recommended_risk = Column(Integer, default=0)
    trust_level = Column(String(32), default="HIGH")  # HIGH, VERIFIED
    comparison_reason = Column(Text, nullable=False)
    disclaimer = Column(Text, default="Lower risk based on available evidence. No download can be guaranteed 100% safe.")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    analysis = relationship("Analysis", back_populates="safepath")


class SystemEvent(Base):
    __tablename__ = "system_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(64), index=True, nullable=False)
    message = Column(Text, nullable=False)
    indicator = Column(String(255), nullable=True)
    analysis_id = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class UserDailyQuota(Base):
    __tablename__ = "user_daily_quotas"

    id = Column(Integer, primary_key=True, index=True)
    user_identifier = Column(String(128), index=True, nullable=False)
    user_role = Column(String(32), nullable=False)  # 'developer' or 'user'
    date_str = Column(String(10), index=True, nullable=False)  # YYYY-MM-DD UTC
    scan_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# Explicit composite indexes for high-performance memory searches
Index("ix_analyses_normurl_created", Analysis.normalized_url, Analysis.created_at)
Index("ix_analyses_domain_created", Analysis.domain, Analysis.created_at)
Index("ix_user_daily_quota_lookup", UserDailyQuota.user_identifier, UserDailyQuota.date_str)

