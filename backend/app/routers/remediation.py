from fastapi import APIRouter
from pydantic import BaseModel
from backend.app.services.ai_remediation import generate_remediation_patch

router = APIRouter(prefix="/api/v1/remediation", tags=["Remediation"])

class RemediationRequest(BaseModel):
    vulnerability: str
    context: str

class RemediationResponse(BaseModel):
    patch: str
    source: str

@router.post("/generate", response_model=RemediationResponse)
async def generate_remediation(request: RemediationRequest):
    result = await generate_remediation_patch(request.vulnerability, request.context)
    return RemediationResponse(
        patch=result["patch"],
        source=result["source"]
    )
