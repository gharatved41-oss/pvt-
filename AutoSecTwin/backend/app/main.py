from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.db.session import init_db

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

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
    # Cross-Origin Resource Sharing (CORS) Middleware
    # ---------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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
            headers=getattr(exc, "headers", None),
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
            "dashboard_url": "/dashboard",
        }

    # ---------------------------------------------------------
    # Frontend Dashboard UI Routes
    # ---------------------------------------------------------
    @app.get(
        "/dashboard",
        response_class=HTMLResponse,
        tags=["Dashboard"],
        summary="Analysis & Evidence Dashboard UI",
    )
    async def dashboard_page() -> HTMLResponse:
        """Serve the single-page application dashboard HTML."""
        index_file = FRONTEND_DIR / "index.html"
        if not index_file.is_file():
            return HTMLResponse("<h1>Dashboard Not Found</h1>", status_code=404)
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))

    @app.get("/dashboard/style.css", include_in_schema=False)
    async def dashboard_css() -> Response:
        """Serve dashboard stylesheet."""
        css_file = FRONTEND_DIR / "style.css"
        if not css_file.is_file():
            return Response("/* Not Found */", status_code=404, media_type="text/css")
        return Response(content=css_file.read_text(encoding="utf-8"), media_type="text/css")

    @app.get("/dashboard/app.js", include_in_schema=False)
    async def dashboard_js() -> Response:
        """Serve dashboard JavaScript logic."""
        js_file = FRONTEND_DIR / "app.js"
        if not js_file.is_file():
            return Response("// Not Found", status_code=404, media_type="application/javascript")
        return Response(content=js_file.read_text(encoding="utf-8"), media_type="application/javascript")

    # ---------------------------------------------------------
    # Mount API Routers
    # ---------------------------------------------------------
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
