from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...models.models import Assessment, VulnerabilityFinding, Asset, RetestResult, User
from ...services.report_generator import report_generator
from ..deps import get_current_user

router = APIRouter(prefix="/reports", tags=["Reporting"])

@router.get("/assessments/{assessment_id}/pdf")
def download_pdf_report(
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.assessment_id == assessment.id).all()
    
    # Retrieve any retest results
    retests = db.query(RetestResult).join(
        VulnerabilityFinding, RetestResult.finding_id == VulnerabilityFinding.id
    ).filter(VulnerabilityFinding.assessment_id == assessment.id).all()

    pdf_bytes = report_generator.generate_pdf(
        assessment=assessment,
        findings=findings,
        asset=asset,
        retest_results=retests
    )

    filename = f"VulnTwin-Report-{assessment.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/assessments/{assessment_id}/csv")
def download_csv_report(
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.assessment_id == assessment.id).all()

    csv_data = report_generator.generate_csv(
        assessment=assessment,
        findings=findings,
        asset=asset
    )

    filename = f"VulnTwin-Report-{assessment.id[:8]}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
