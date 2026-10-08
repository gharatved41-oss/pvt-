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
    analysis, history, indicators, health, safepath, twin, auth
)
from backend.app.routers import dashboard, scanner, remediation


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

import os

frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
allow_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    frontend_url
]
if frontend_url == "*":
    allow_origins = ["*"]

# Enable CORS for local dev React SPA and Vercel Prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers under /api/v1
app.include_router(auth.router, prefix=settings.API_V1_STR, tags=["Authentication"])
app.include_router(analysis.router, prefix=settings.API_V1_STR, tags=["Analysis"])
app.include_router(history.router, prefix=settings.API_V1_STR, tags=["History & Memory"])
app.include_router(indicators.router, prefix=settings.API_V1_STR, tags=["Indicators & Timeline"])
app.include_router(safepath.router, prefix=settings.API_V1_STR, tags=["SafePath"])
app.include_router(twin.router, prefix=settings.API_V1_STR, tags=["Digital Twin"])
app.include_router(health.router, prefix=settings.API_V1_STR, tags=["System Health"])

# New Directives Routers
app.include_router(dashboard.router)
app.include_router(scanner.router)
app.include_router(remediation.router)


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
    return {"status": "online", "database": "connected"}
