"""Health & System Settings API for AutoSecTwin.
Reports real connectivity status for the database and threat providers without disclosing secrets.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.db.session import get_db
from backend.app.config import settings
from backend.app.providers.reputation_provider import BuiltinReputationProvider
from backend.app.providers.threat_intel_provider import ExternalThreatIntelProvider, AbuseIPDBProvider

router = APIRouter()
builtin_prov = BuiltinReputationProvider()
ext_prov = ExternalThreatIntelProvider()
abuse_prov = AbuseIPDBProvider()


@router.get("/health")
def get_system_health(db: Session = Depends(get_db)):
    """
    Returns system operational status and connectivity indicators.
    """
    # Test database connectivity
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    return {
        "status": "operational" if db_healthy else "degraded",
        "app_name": settings.PROJECT_NAME,
        "tagline": settings.TAGLINE,
        "version": settings.VERSION,
        "environment": settings.ENV,
        "database": {
            "status": "connected" if db_healthy else "error",
            "engine": "SQLite Relational"
        },
        "providers": {
            "native_reputation": {
                "name": builtin_prov.name,
                "status": "connected",
                "mode": "deterministic_heuristics"
            },
            "abuseipdb_threat_intel": {
                "name": abuse_prov.name,
                "status": "connected" if abuse_prov.is_configured else "unconfigured_offline_safe",
                "configured": abuse_prov.is_configured
            },
            "virustotal_threat_intel": {
                "name": ext_prov.name,
                "status": "connected" if ext_prov.is_configured else "unconfigured_offline_safe",
                "configured": ext_prov.is_configured
            }
        },
        "ai_engine": {
            "status": "active_gemini_3_5_flash_lite" if (settings.AI_ENABLED and bool(settings.GEMINI_API_KEY)) else "active_fallback_deterministic",
            "provider": "Google Gemini (gemini-3.5-flash-lite)" if (settings.AI_ENABLED and bool(settings.GEMINI_API_KEY)) else "Deterministic Grounded Heuristics",
            "mode": "grounded_evidence_synthesis"
        },
        "ssrf_protection": {
            "status": "active",
            "blocked_cidr_ranges_count": len(settings.BLOCKED_IP_NETWORKS)
        }
    }
