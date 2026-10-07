"""AutoSecTwin Backend Application Entrypoint.
"Test the Threat. Not the System."
An explainable cybersecurity digital-twin and security intelligence platform.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.config import settings
from backend.app.core.logging import logger
from backend.app.db.init_db import init_database
from backend.app.api.routes import (
    analysis, history, dashboard, indicators, health, safepath, twin, auth
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB schema safely
    logger.info("Initializing VulnTwin AI backend server...")
    init_database()
    logger.info("VulnTwin AI backend ready to receive safe security queries.")
    yield
    logger.info("VulnTwin AI backend shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Explainable Cybersecurity Digital Twin & Security Memory Platform. Analyzes indicators without executing untrusted content.",
    version=settings.VERSION,
    lifespan=lifespan
)

# Enable CORS for local dev React SPA
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers under /api/v1
app.include_router(auth.router, prefix=settings.API_V1_STR, tags=["Authentication"])
app.include_router(analysis.router, prefix=settings.API_V1_STR, tags=["Analysis"])
app.include_router(history.router, prefix=settings.API_V1_STR, tags=["History & Memory"])
app.include_router(indicators.router, prefix=settings.API_V1_STR, tags=["Indicators & Timeline"])
app.include_router(dashboard.router, prefix=settings.API_V1_STR, tags=["Dashboard"])
app.include_router(safepath.router, prefix=settings.API_V1_STR, tags=["SafePath"])
app.include_router(twin.router, prefix=settings.API_V1_STR, tags=["Digital Twin"])
app.include_router(health.router, prefix=settings.API_V1_STR, tags=["System Health"])


@app.get("/")
def read_root():
    return {
        "project": settings.PROJECT_NAME,
        "tagline": settings.TAGLINE,
        "version": settings.VERSION,
        "docs_url": "/docs",
        "api_v1_base": settings.API_V1_STR
    }


@app.get("/health")
def read_root_health():
    return {"status": "operational", "project": settings.PROJECT_NAME, "version": settings.VERSION}
