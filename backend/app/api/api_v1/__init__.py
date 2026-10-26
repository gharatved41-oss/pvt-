from fastapi import APIRouter
from .auth import router as auth_router
from .assets import router as assets_router
from .assessments import router as assessments_router
from .vulnerabilities import router as vulnerabilities_router
from .risk import router as risk_router
from .twins import router as twins_router
from .validation import router as validation_router
from .remediation import router as remediation_router
from .retesting import router as retesting_router
from .reports import router as reports_router
from .audit import router as audit_router
from .settings import router as settings_router
from .health import router as health_router
from .dashboard import router as dashboard_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(assets_router)
api_router.include_router(assessments_router)
api_router.include_router(vulnerabilities_router)
api_router.include_router(risk_router)
api_router.include_router(twins_router)
api_router.include_router(validation_router)
api_router.include_router(remediation_router)
api_router.include_router(retesting_router)
api_router.include_router(reports_router)
api_router.include_router(audit_router)
api_router.include_router(settings_router)
api_router.include_router(health_router)
api_router.include_router(dashboard_router)
