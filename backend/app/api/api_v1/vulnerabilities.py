from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from ...core.database import get_db
from ...models.models import VulnerabilityFinding, EvidenceRecord, User
from ...schemas.schemas import VulnerabilityFindingResponse, EvidenceRecordResponse
from ..deps import get_current_user

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

@router.get("", response_model=List[VulnerabilityFindingResponse])
def list_vulnerabilities(
    asset_id: Optional[str] = None,
    assessment_id: Optional[str] = None,
    severity: Optional[str] = None,
    detection_status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(VulnerabilityFinding)
    if asset_id:
        query = query.filter(VulnerabilityFinding.asset_id == asset_id)
    if assessment_id:
        query = query.filter(VulnerabilityFinding.assessment_id == assessment_id)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity.lower())
    if detection_status:
        query = query.filter(VulnerabilityFinding.detection_status == detection_status)
    if search:
        query = query.filter(
            (VulnerabilityFinding.cve_id.ilike(f"%{search}%")) |
            (VulnerabilityFinding.title.ilike(f"%{search}%")) |
            (VulnerabilityFinding.affected_component.ilike(f"%{search}%"))
        )

    # Order by risk score descending
    return query.order_by(VulnerabilityFinding.risk_score.desc()).all()

@router.get("/{finding_id}", response_model=VulnerabilityFindingResponse)
def get_vulnerability(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.get("/{finding_id}/evidence", response_model=List[EvidenceRecordResponse])
def get_finding_evidence(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding_id).all()
