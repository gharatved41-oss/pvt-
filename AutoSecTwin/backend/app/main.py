"""FastAPI application entry point for VulnTwin AI backend."""

import logging
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from contextlib import asynccontextmanager
from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.db.session import init_db

# Configure logging
logger = logging.getLogger("vulntwin_ai")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for startup and shutdown."""
    logger.info("Initializing database tables...")
    init_db()
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title=f"{settings.APP_NAME} API",
        version="0.1.0",
        description=(
            "VulnTwin AI Backend: AI-assisted cybersecurity platform that analyzes "
            "security indicators, collects evidence, computes explainable risk scores, "
            "and supports digital twin verification workflows."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ---------------------------------------------------------
    # Input-independent & structured error handling
    # ---------------------------------------------------------
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Handle standard HTTP exceptions with consistent JSON envelope."""
        logger.warning(
            "HTTP %d error on %s %s: %s",
            exc.status_code,
            request.method,
            request.url.path,
            exc.detail,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status_code": exc.status_code,
                "error": "HTTP Error",
                "message": exc.detail,
                "path": request.url.path,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle request schema validation errors cleanly."""
        errors_summary = [
            {
                "loc": [str(loc_item) for loc_item in err.get("loc", [])],
                "msg": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in exc.errors()
        ]
        logger.warning(
            "Validation error on %s %s: %s",
            request.method,
            request.url.path,
            errors_summary,
        )
        return JSONResponse(
            status_code=422,
            content={
                "status_code": 422,
                "error": "Validation Error",
                "message": "The request payload or parameters failed validation.",
                "details": errors_summary,
                "path": request.url.path,
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unhandled internal errors safely without leaking internal details."""
        logger.error(
            "Unhandled exception on %s %s: %s",
            request.method,
            request.url.path,
            str(exc),
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "error": "Internal Server Error",
                "message": "An unexpected server error occurred. Please contact the administrator.",
                "path": request.url.path,
            },
        )

    # ---------------------------------------------------------
    # Root endpoint for navigation
    # ---------------------------------------------------------
    @app.get(
        "/",
        tags=["System"],
        summary="Service Root",
        description="Root entry point directing clients to API documentation and versioned endpoints.",
    )
    async def root() -> Dict[str, Any]:
        """Root endpoint redirecting clients to documentation and API v1."""
        return {
            "app_name": settings.APP_NAME,
            "api_version": settings.API_VERSION,
            "docs_url": "/docs",
            "api_v1_url": settings.API_V1_STR,
            "health_url": f"{settings.API_V1_STR}/health",
        }

    # ---------------------------------------------------------
    # Mount API Routers
    # ---------------------------------------------------------
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
