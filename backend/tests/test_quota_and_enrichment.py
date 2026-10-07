"""Tests for Quota Service, Signal Enrichment, Attack Path Modeling, and SafePath."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException

from backend.app.db.session import Base
from backend.app.models.database import UserDailyQuota
from backend.app.services.quota_service import QuotaService
from backend.app.services.enrichment_service import enrichment_service
from backend.app.services.attack_path_engine import attack_path_engine
from backend.app.services.safepath import safepath_engine


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    yield session
    session.close()


def test_developer_unlimited_quota(db_session):
    service = QuotaService()
    dev_user = "mayank.patil"
    
    # Developers can make 10 scans without 429
    for i in range(10):
        res = service.check_and_consume_quota(db_session, user_identifier=dev_user, user_role="developer")
        assert res["unlimited"] is True
        assert res["role"] == "developer"
        assert res["can_analyze"] is True


def test_user_three_scans_limit_enforced(db_session):
    service = QuotaService()
    standard_user = "alex.rivera@corp-security.com"

    # Scan 1
    q1 = service.check_and_consume_quota(db_session, user_identifier=standard_user, user_role="user")
    assert q1["used_today"] == 1
    assert q1["remaining"] == 2
    assert q1["can_analyze"] is True

    # Scan 2
    q2 = service.check_and_consume_quota(db_session, user_identifier=standard_user, user_role="user")
    assert q2["used_today"] == 2
    assert q2["remaining"] == 1

    # Scan 3 (last allowed scan)
    q3 = service.check_and_consume_quota(db_session, user_identifier=standard_user, user_role="user")
    assert q3["used_today"] == 3
    assert q3["remaining"] == 0

    # Scan 4 MUST raise HTTP 429
    with pytest.raises(HTTPException) as exc:
        service.check_and_consume_quota(db_session, user_identifier=standard_user, user_role="user")
    assert exc.value.status_code == 429
    assert "Daily analysis limit reached" in exc.value.detail


def test_enrichment_entropy_and_brand_spoofing():
    # Brand spoofing test on non-official domain
    indicators = {
        "hostname": "login-microsoft-secure-account.xyz",
        "domain": "login-microsoft-secure-account.xyz",
        "scheme": "http",
        "path": "/login.php",
        "query": "redirect=victim.com"
    }
    result = enrichment_service.evaluate_enrichment_signals(indicators)
    assert result["detected_brand"] == "microsoft"
    assert result["has_tls"] is False
    assert result["has_redirect_lure"] is True
    assert result["extra_risk"] >= 40


def test_attack_path_modeling():
    indicators = {
        "hostname": "vlc-fast-updater.xyz",
        "domain": "vlc-fast-updater.xyz",
        "scheme": "http",
        "file_extension": "exe",
        "is_suspicious_extension": True,
        "is_suspicious_tld": True
    }
    attack_model = attack_path_engine.model_attack_path(
        target="http://vlc-fast-updater.xyz/vlc_setup.exe",
        verdict="MALICIOUS",
        risk_score=85,
        parsed_indicators=indicators
    )
    assert attack_model["overall_feasibility_percent"] > 70
    assert len(attack_model["attack_stages"]) >= 3
    assert attack_model["blast_radius"] == "LOCAL_WORKSTATION_AND_NETWORK_PIVOT"


def test_safepath_catalog_extensions():
    # Test WinRAR alternative
    indicators = {
        "hostname": "winrar-crack-2026.net",
        "domain": "winrar-crack-2026.net",
        "path": "winrar_key.exe",
        "has_executable": True
    }
    alt = safepath_engine.find_alternative("http://winrar-crack-2026.net/winrar_key.exe", indicators, 75)
    assert alt is not None
    assert alt.recommended_domain == "rarlab.com"
    assert "Official WinRAR Compression Utility" in alt.recommended_name
