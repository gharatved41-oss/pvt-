"""Unit tests for URL normalization and indicator extraction.
"""
import pytest
from backend.app.utils.url_normalizer import normalize_url, URLValidationError, calculate_entropy


def test_normalize_valid_urls():
    res = normalize_url("https://Example.COM:443/test/path?q=1")
    assert res["normalized_url"] == "https://example.com/test/path?q=1"
    assert res["hostname"] == "example.com"
    assert res["domain"] == "example.com"
    assert res["scheme"] == "https"
    assert res["query_present"] is True


def test_normalize_strips_default_http_port():
    res = normalize_url("http://example.org:80/download")
    assert res["normalized_url"] == "http://example.org/download"
    assert res["port"] is None


def test_reject_unsupported_schemes():
    with pytest.raises(URLValidationError, match="Unsupported URL scheme"):
        normalize_url("file:///etc/passwd")

    with pytest.raises(URLValidationError, match="Unsupported URL scheme"):
        normalize_url("ftp://malicious.com/exploit.bin")

    with pytest.raises(URLValidationError, match="Unsupported URL scheme"):
        normalize_url("javascript:alert(1)")


def test_detect_executable_extensions():
    res = normalize_url("https://suspicious-files.xyz/dropper.exe")
    assert res["has_executable"] is True
    assert ".exe" in res["detected_extensions"]


def test_detect_brand_spoofing():
    res = normalize_url("http://vlc-update-portal.xyz/download")
    assert "vlc" in res["matched_brands"]
    assert res["suspicious_tld"] is True


def test_shannon_entropy():
    # Low entropy (repetitive)
    low_e = calculate_entropy("aaaaaaa")
    # High entropy (random DGA)
    high_e = calculate_entropy("xq9z8b1vlk7m2p")
    assert high_e > low_e
    assert high_e > 3.0
