"""Unit tests for AutoSecTwin SafePath Trusted Alternative Recommendation.
"""
from backend.app.services.safepath import SafePathEngine
from backend.app.utils.url_normalizer import normalize_url


def test_safepath_recommends_official_vlc_for_suspicious_dropper():
    engine = SafePathEngine()
    url = "http://vlc-update-fast.xyz/vlc_setup.exe"
    indicators = normalize_url(url)
    
    alt = engine.find_alternative(url, indicators, risk_score=85)
    assert alt is not None
    assert alt.software_name == "VLC media player"
    assert alt.recommended_domain == "videolan.org"
    assert alt.recommended_risk == 5
    assert alt.trust_level == "VERIFIED_OFFICIAL"
    assert "videolan.org" in alt.recommended_url
    assert "Lower risk based on available evidence" in alt.disclaimer


def test_safepath_recommends_7zip_for_third_party_archive():
    engine = SafePathEngine()
    url = "https://freeware-downloads-portal.net/7zip_v23.exe"
    indicators = normalize_url(url)

    alt = engine.find_alternative(url, indicators, risk_score=78)
    assert alt is not None
    assert alt.software_name == "7-Zip File Archiver"
    assert alt.recommended_domain == "7-zip.org"
    assert alt.recommended_risk == 4


def test_safepath_does_not_flag_official_vendor_itself():
    engine = SafePathEngine()
    url = "https://www.videolan.org/vlc/download-windows.html"
    indicators = normalize_url(url)

    alt = engine.find_alternative(url, indicators, risk_score=5)
    # The official vendor itself should not have an alternative recommended
    assert alt is None
