"""Unit tests for SSRF Guard defense mechanisms.
"""
from backend.app.utils.ssrf_guard import validate_ssrf_safety, is_ip_blocked


def test_blocks_localhost_and_loopback():
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("127.0.0.254") is True
    is_safe, _ = validate_ssrf_safety("localhost")
    assert is_safe is False
    is_safe_ip, _ = validate_ssrf_safety("127.0.0.1")
    assert is_safe_ip is False


def test_blocks_private_rfc1918_ips():
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("192.168.1.1") is True
    assert is_ip_blocked("172.16.5.20") is True


def test_blocks_cloud_metadata():
    assert is_ip_blocked("169.254.169.254") is True
    is_safe, _ = validate_ssrf_safety("metadata.google.internal")
    assert is_safe is False


def test_allows_public_hosts():
    is_safe, _ = validate_ssrf_safety("example.com")
    assert is_safe is True
