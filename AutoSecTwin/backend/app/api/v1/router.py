"""Central router aggregation for API version 1."""

from fastapi import APIRouter

from app.api.v1.endpoints import analyses, health, info

api_v1_router = APIRouter()

# Include endpoint routers
api_v1_router.include_router(info.router, tags=["System"])
api_v1_router.include_router(health.router, tags=["System"])
api_v1_router.include_router(analyses.router, prefix="/analyses", tags=["Analyses"])

