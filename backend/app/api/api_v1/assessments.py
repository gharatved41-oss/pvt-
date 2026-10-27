from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import (
    Asset, Assessment, InventorySnapshot, VulnerabilityFinding,
    EvidenceRecord, RemediationRecommendation, User
)
from ...schemas.schemas import AssessmentCreate, AssessmentResponse
from ...services.cve_service import cve_service
from ...services.ml_risk_engine import ml_risk_engine
from ...services.audit_service import audit_service
from ..deps import get_current_user, require_admin

router = APIRouter(prefix="/assessments", tags=["Assessments"])

@router.get("", response_model=List[AssessmentResponse])
def list_assessments(
    asset_id: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Assessment)
    if asset_id:
        query = query.filter(Assessment.asset_id == asset_id)
    return query.order_by(Assessment.started_at.desc()).all()

@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
def run_assessment(
    assess_in: AssessmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = db.query(Asset).filter(Asset.id == assess_in.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Target asset not found")

    # Get latest inventory snapshot
    snapshot = db.query(InventorySnapshot).filter(
        InventorySnapshot.asset_id == asset.id
    ).order_by(InventorySnapshot.created_at.desc()).first()

    if not snapshot:
        raise HTTPException(
            status_code=400,
            detail="No inventory snapshot found for this asset. Please import an inventory first."
        )

    # Create assessment record
    assessment = Assessment(
        asset_id=asset.id,
        title=assess_in.title or f"Vulnerability & Risk Audit - {asset.name}",
        status="running",
        started_at=datetime.now(timezone.utc),
        notes=assess_in.notes or ""
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # 1. Match vulnerabilities using CVE service
    detected_vulns = cve_service.find_vulnerabilities(
        os_type=asset.os_type,
        packages=snapshot.parsed_packages or [],
        configuration_metadata=snapshot.configuration_metadata or {}
    )

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    total_risk = 0.0

    # 2. Evaluate risk with ML engine & persist records
    for v in detected_vulns:
        risk_result = ml_risk_engine.evaluate_risk(
            cvss_score=v["cvss_v3_score"],
            asset_criticality=asset.criticality,
            asset_environment=asset.environment,
            exploit_maturity=v.get("exploit_maturity", "functional"),
            patch_available=True,
            evidence_depth="manifest",
            detection_status="detected"
        )

        finding = VulnerabilityFinding(
            assessment_id=assessment.id,
            asset_id=asset.id,
            cve_id=v["cve_id"],
            title=v["title"],
            affected_component=v["affected_component"],
            installed_version=v["installed_version"],
            fixed_version=v.get("fixed_version", "Vendor Patched"),
            cvss_v3_score=v["cvss_v3_score"],
            cvss_v3_vector=v.get("cvss_v3_vector", ""),
            severity=v["severity"],
            detection_status="detected",
            risk_score=risk_result["risk_score"],
            risk_category=risk_result["risk_category"],
            confidence_score=risk_result["confidence_score"],
            contributing_factors=risk_result["contributing_factors"],
            recommended_priority=risk_result["recommended_priority"],
            risk_explanation=risk_result["risk_explanation"],
            description=v["description"],
            references=v.get("references", []),
            remediation_summary=v.get("remediation", {}).get("title", "Upgrade package to patched version")
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        # 3. Create Evidence Record
        ev_data = v.get("evidence", {})
        evidence = EvidenceRecord(
            finding_id=finding.id,
            evidence_type=ev_data.get("evidence_type", "package_manifest"),
            title=ev_data.get("title", f"Package {v['affected_component']} version {v['installed_version']}"),
            raw_evidence=ev_data.get("raw_evidence", f"Version manifest: {v['installed_version']}"),
            metadata_info={"cve_id": v["cve_id"], "assessment_id": assessment.id}
        )
        db.add(evidence)

        # 4. Create Remediation Recommendation
        rem_data = v.get("remediation", {})
        if rem_data:
            rec = RemediationRecommendation(
                finding_id=finding.id,
                action_type=rem_data.get("action_type", "package_update"),
                title=rem_data.get("title", f"Apply security update for {v['affected_component']}"),
                description=rem_data.get("description", "Vendor patch fixes vulnerability."),
                vendor_advisory_url=rem_data.get("vendor_advisory_url", ""),
                prerequisites=rem_data.get("prerequisites", []),
                command_preview=rem_data.get("command_preview", "sudo apt-get update && sudo apt-get upgrade"),
                rollback_instructions=rem_data.get("rollback_instructions", ""),
                expected_outcome=rem_data.get("expected_outcome", "Vulnerability mitigated in target twin."),
                status="recommended"
            )
            db.add(rec)

        # Track counters
        sev = v["severity"].lower()
        if sev == "critical":
            critical_count += 1
        elif sev == "high":
            high_count += 1
        elif sev == "medium":
            medium_count += 1
        else:
            low_count += 1

        total_risk += risk_result["risk_score"]

    total_findings = len(detected_vulns)
    avg_risk = round(total_risk / total_findings, 1) if total_findings > 0 else 0.0

    # Finalize assessment
    assessment.status = "completed"
    assessment.completed_at = datetime.now(timezone.utc)
    assessment.findings_count = total_findings
    assessment.critical_count = critical_count
    assessment.high_count = high_count
    assessment.medium_count = medium_count
    assessment.low_count = low_count
    assessment.average_risk_score = avg_risk

    db.commit()
    db.refresh(assessment)

    audit_service.log_event(
        db=db,
        event_type="assessment",
        action="assessment_completed",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "assessment_id": assessment.id,
            "asset_id": asset.id,
            "findings_count": total_findings,
            "avg_risk": avg_risk
        }
    )

    return assessment

@router.get("/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

@router.delete("/{assessment_id}")
def delete_assessment(
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete an assessment run and related findings (admin only)."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    title = assessment.title
    asset_id = assessment.asset_id
    db.delete(assessment)
    db.commit()

    audit_service.log_event(
        db=db,
        event_type="assessment",
        action="assessment_deleted",
        user_id=current_user.id,
        user_email=current_user.email,
        details={"assessment_id": assessment_id, "title": title, "asset_id": asset_id}
    )
    return {"message": "Assessment deleted successfully"}

@router.get("/{assessment_id}/compare/{previous_id}")
def compare_assessments(
    assessment_id: str,
    previous_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Compare two assessment runs for an asset to evaluate historical remediation progress."""
    curr = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    prev = db.query(Assessment).filter(Assessment.id == previous_id).first()

    if not curr:
        raise HTTPException(status_code=404, detail="Current assessment not found")
    if not prev:
        raise HTTPException(status_code=404, detail="Comparison assessment not found")

    curr_findings = {f.cve_id: f for f in curr.findings}
    prev_findings = {f.cve_id: f for f in prev.findings}

    new_cves = set(curr_findings.keys()) - set(prev_findings.keys())
    resolved_cves = set(prev_findings.keys()) - set(curr_findings.keys())
    persistent_cves = set(curr_findings.keys()) & set(prev_findings.keys())

    return {
        "asset_id": curr.asset_id,
        "asset_name": curr.asset.name if curr.asset else "Unknown",
        "current_assessment": {
            "id": curr.id,
            "title": curr.title,
            "started_at": curr.started_at.isoformat() if curr.started_at else None,
            "findings_count": curr.findings_count,
            "average_risk_score": curr.average_risk_score,
            "critical_count": curr.critical_count,
            "high_count": curr.high_count
        },
        "previous_assessment": {
            "id": prev.id,
            "title": prev.title,
            "started_at": prev.started_at.isoformat() if prev.started_at else None,
            "findings_count": prev.findings_count,
            "average_risk_score": prev.average_risk_score,
            "critical_count": prev.critical_count,
            "high_count": prev.high_count
        },
        "new_findings": [
            {
                "cve_id": cve,
                "title": curr_findings[cve].title,
                "severity": curr_findings[cve].severity,
                "risk_score": curr_findings[cve].risk_score
            }
            for cve in new_cves
        ],
        "resolved_findings": [
            {
                "cve_id": cve,
                "title": prev_findings[cve].title,
                "severity": prev_findings[cve].severity,
                "risk_score": prev_findings[cve].risk_score
            }
            for cve in resolved_cves
        ],
        "persistent_findings": [
            {
                "cve_id": cve,
                "title": curr_findings[cve].title,
                "severity": curr_findings[cve].severity,
                "risk_score": curr_findings[cve].risk_score
            }
            for cve in persistent_cves
        ],
        "risk_score_delta": round(curr.average_risk_score - prev.average_risk_score, 1),
        "findings_count_delta": curr.findings_count - prev.findings_count
    }
