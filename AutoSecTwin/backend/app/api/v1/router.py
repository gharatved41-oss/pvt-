"""Central router aggregation for API version 1."""

from fastapi import APIRouter

from app.api.v1.endpoints import analyses, health, info, os_assessments

api_v1_router = APIRouter()

# Include endpoint routers
api_v1_router.include_router(info.router, tags=["System"])
api_v1_router.include_router(health.router, tags=["System"])
api_v1_router.include_router(analyses.router, prefix="/analyses", tags=["Analyses"])
api_v1_router.include_router(os_assessments.router, prefix="/os", tags=["OS Assessments"])

