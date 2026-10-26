from fastapi import APIRouter, Depends
from typing import Dict, Any

from ...core.config import settings
from ...models.models import User
from ..deps import get_current_user

router = APIRouter(prefix="/settings", tags=["Application Settings"])

@router.get("")
def get_system_settings(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    return {
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database_backend": "SQLite (with Foreign Key Pragma & Transactions)",
        "twin_provider": settings.TWIN_PROVIDER,
        "twin_isolation_network": settings.TWIN_ISOLATION_NETWORK,
        "nvd_api_connected": bool(settings.NVD_API_KEY),
        "nvd_api_key_configured": bool(settings.NVD_API_KEY),
        "nvd_timeout_seconds": settings.NVD_API_TIMEOUT,
        "max_validation_timeout": settings.MAX_VALIDATION_TIMEOUT_SECONDS,
        "ml_model_status": "GradientBoostingRegressor (Active & Calibrated)",
        "offline_cve_catalog": "Enabled (Air-Gapped Deterministic Fixtures Available)",
        "supported_os_types": ["Linux (Debian/Ubuntu/RHEL)", "Windows Server (2019/2022/10/11)"]
    }
