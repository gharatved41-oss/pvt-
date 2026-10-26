from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime, timezone
from typing import Dict, Any

from ...core.database import get_db
from ...core.config import settings
from ...services.cve_service import cve_service
from ...services.ml_risk_engine import ml_risk_engine

router = APIRouter(prefix="/health", tags=["Application Health"])

@router.get("")
def check_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # Check DB
    db_connected = False
    try:
        db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    return {
        "status": "healthy" if db_connected else "degraded",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database_connected": db_connected,
        "twin_provider": settings.TWIN_PROVIDER,
        "ml_model_loaded": ml_risk_engine.model is not None,
        "offline_cve_catalog_size": cve_service.get_catalog_size(),
        "nvd_api_configured": bool(settings.NVD_API_KEY)
    }
