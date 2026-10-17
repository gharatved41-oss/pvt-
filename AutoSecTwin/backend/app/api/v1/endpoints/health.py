"""Health check endpoint for VulnTwin AI API."""

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.core.config import settings

router = APIRouter()


class HealthResponse(BaseModel):
    """Response model for the health check endpoint."""

    app_name: str = Field(..., description="Name of the application", examples=["VulnTwin AI"])
    status: str = Field(..., description="Operational status of the service", examples=["healthy"])
    api_version: str = Field(..., description="API version identifier", examples=["v1"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Service Health Check",
    description="Returns the health status, application name, and active API version.",
    tags=["System"],
)
async def get_health() -> HealthResponse:
    """Return application name, operational status, and API version."""
    return HealthResponse(
        app_name=settings.APP_NAME,
        status="healthy",
        api_version=settings.API_VERSION,
    )
