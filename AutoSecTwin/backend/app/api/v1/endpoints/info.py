"""Root information endpoint for API v1."""

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.core.config import settings

router = APIRouter()


class ApiInfoResponse(BaseModel):
    """Response model for API v1 root information."""

    app_name: str = Field(..., description="Name of the application", examples=["VulnTwin AI"])
    api_version: str = Field(..., description="API version identifier", examples=["v1"])
    description: str = Field(..., description="High-level description of the API")
    docs_url: str = Field(..., description="Relative URL to the interactive OpenAPI documentation")
    health_url: str = Field(..., description="Relative URL to the health check endpoint")
    status: str = Field(..., description="Current operational status", examples=["operational"])


@router.get(
    "/",
    response_model=ApiInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="API v1 Information",
    description="Returns high-level metadata, documentation links, and operational status for API v1.",
    tags=["System"],
)
async def get_api_info() -> ApiInfoResponse:
    """Return basic metadata about the VulnTwin AI v1 API."""
    return ApiInfoResponse(
        app_name=settings.APP_NAME,
        api_version=settings.API_VERSION,
        description="VulnTwin AI Cybersecurity Platform API - Milestone 1 Foundation",
        docs_url="/docs",
        health_url=f"{settings.API_V1_STR}/health",
        status="operational",
    )
