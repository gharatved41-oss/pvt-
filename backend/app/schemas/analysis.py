"""Pydantic schemas for AutoSecTwin API contracts.
Ensures rigorous input validation and serializes rich security intelligence.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The suspicious URL to analyze safely", min_length=3, max_length=2048)
    force_refresh: bool = Field(default=False, description="Bypass cache and force fresh analysis")


class HashAnalysisRequest(BaseModel):
    hash: str = Field(..., description="Cryptographic hash (MD5, SHA-1, SHA-256)", min_length=32, max_length=64)


class EvidenceItem(BaseModel):
    id: Optional[int] = None
    category: str
    title: str
    description: str
    source: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    impact_score: int
    observed_at: datetime
    metadata: Optional[Dict[str, Any]] = None


class RiskFactor(BaseModel):
    name: str
    impact: int
    severity: str
    evidence: str


class ExploitabilityAssessment(BaseModel):
    level: str  # LOW, MEDIUM, HIGH, UNKNOWN
    reason: str
    confidence: float
    factors: List[str] = []


class RecommendationItem(BaseModel):
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    reason: str
    action: str
    effort: str = "LOW"
    coverage: Optional[str] = None


class SafePathAlternative(BaseModel):
    software_name: str
    original_url: str
    original_risk: int
    recommended_name: str
    recommended_url: str
    recommended_domain: str
    recommended_risk: int
    trust_level: str
    comparison_reason: str
    disclaimer: str = "Lower risk based on available evidence. No download can be guaranteed 100% safe."


class HistoricalComparison(BaseModel):
    has_history: bool = False
    previous_analysis_id: Optional[str] = None
    previous_analyzed_at: Optional[datetime] = None
    previous_verdict: Optional[str] = None
    previous_risk_score: Optional[int] = None
    current_risk_score: int
    score_delta: int = 0
    verdict_changed: bool = False
    status_summary: str = "First time this indicator has been analyzed."
    times_analyzed: int = 1


class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    indicator_type: str
    submitted_url: str
    normalized_url: str
    domain: Optional[str] = None
    hostname: Optional[str] = None
    
    # Core Verdicts
    verdict: str  # SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN
    risk_score: int
    risk_level: str  # LOW, GUARDED, SUSPICIOUS, HIGH
    confidence: float
    freshness: str  # FRESH, RECENT, STALE
    
    exploitability: ExploitabilityAssessment
    attack_path: Optional[Dict[str, Any]] = None
    summary: str
    key_findings: List[str] = []
    risk_factors: List[RiskFactor] = []
    evidence: List[EvidenceItem] = []
    recommendations: List[RecommendationItem] = []
    safepath: Optional[SafePathAlternative] = None
    historical: HistoricalComparison
    limitations: List[str] = []
    quota: Optional[Dict[str, Any]] = None
    
    created_at: datetime
    duration_ms: int
    is_demo: bool = False

