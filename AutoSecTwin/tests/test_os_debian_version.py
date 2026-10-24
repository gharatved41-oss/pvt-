"""Automated unit tests for Debian Policy Manual §5.6.12 version comparison semantics."""

import pytest
from app.services.os_matcher.debian_version import (
    compare_debian_versions,
    is_debian_version_less,
    parse_debian_version,
)


def test_parse_debian_version_components() -> None:
    """Verify parsing epochs, upstream versions, and revisions."""
    epoch, upstream, rev = parse_debian_version("1:2.35-0ubuntu3.4")
    assert epoch == 1
    assert upstream == "2.35"
    assert rev == "0ubuntu3.4"

    # Default epoch is 0
    epoch2, upstream2, rev2 = parse_debian_version("3.0.2-0ubuntu1.10")
    assert epoch2 == 0
    assert upstream2 == "3.0.2"
    assert rev2 == "0ubuntu1.10"

    # Missing revision
    epoch3, upstream3, rev3 = parse_debian_version("1.2.3")
    assert epoch3 == 0
    assert upstream3 == "1.2.3"
    assert rev3 == ""


@pytest.mark.parametrize(
    "v1, v2, expected",
    [
        # 1. Basic numerical comparisons
        ("1.0", "2.0", -1),
        ("2.0", "1.0", 1),
        ("1.0", "1.0", 0),
        ("1.2", "1.10", -1),  # 2 < 10 numerically (unlike ASCII sort where '10' < '2')
        ("1.10", "1.2", 1),
        ("0.9.8", "0.9.8a", -1),

        # 2. Epoch comparisons (epoch strictly takes precedence)
        ("1:1.0", "2.0", 1),        # epoch 1 > epoch 0
        ("2.0", "1:1.0", -1),
        ("0:1.0", "1.0", 0),        # 0:1.0 is equal to 1.0
        ("2:0.0.1", "1:99.9.9", 1), # epoch 2 > epoch 1

        # 3. Debian revisions
        ("1.0-1", "1.0-2", -1),
        ("1.0-2", "1.0-1", 1),
        ("1.0-1", "1.0-1", 0),
        ("1.0-0ubuntu1", "1.0-0ubuntu2", -1),
        ("1.0-0ubuntu9", "1.0-0ubuntu10", -1),

        # 4. Tilde (~) ordering: tilde sorts BEFORE anything, even empty string!
        ("1.0~beta1", "1.0", -1),
        ("1.0", "1.0~beta1", 1),
        ("1.0~rc1", "1.0~rc2", -1),
        ("2.0~alpha", "2.0~beta", -1),
        ("1.0~", "1.0", -1),
        ("1.0~22.04.1", "1.0", -1),

        # 5. Ubuntu and Debian backport releases
        ("1.0-0ubuntu1~22.04.1", "1.0-0ubuntu1", -1),  # Backport sorts lower than base release
        ("1.0-0ubuntu1~22.04.1", "1.0-0ubuntu1~22.04.2", -1),
        ("1.0-0ubuntu1~20.04.1", "1.0-0ubuntu1~22.04.1", -1),

        # 6. Real-world Ubuntu Security Notices CVE fixed versions
        ("2.35-0ubuntu3.1", "2.35-0ubuntu3.4", -1),      # glibc CVE-2023-4911
        ("2.35-0ubuntu3.4", "2.35-0ubuntu3.4", 0),
        ("2.35-0ubuntu3.5", "2.35-0ubuntu3.4", 1),
        ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12", -1),  # OpenSSL
        ("7.81.0-1ubuntu1.14", "7.81.0-1ubuntu1.15", -1),# curl
        ("1:9.0p1-1ubuntu7.4", "1:9.0p1-1ubuntu8", -1),  # OpenSSH

        # 7. Official dpkg verrevcmp edge cases and non-digit length differences
        ("a1", "ab1", -1),              # Non-digit prefix length difference ('a' < 'ab')
        ("ab1", "a1", 1),
        ("01", "1", 0),                 # Leading zeros in numerical chunk
        ("1", "01", 0),
        ("1.0", "1.0+b1", -1),          # '+' sorts after end of non-digit
        ("1.0+b1", "1.0", 1),
        ("1.0~rc1", "1.0+b1", -1),      # '~' sorts before '+'
        ("1.0+b1", "1.0~rc1", 1),
        ("+1", "1", 1),                 # '+' sorts after empty non-digit
        ("1", "+1", -1),
        ("1.0-1", "1.0-01", 0),         # Leading zeros in revision
        ("1.0-test-1", "1.0-test-2", -1), # Multiple hyphens in upstream version
    ],
)

def test_compare_debian_versions(v1: str, v2: str, expected: int) -> None:
    """Verify Debian Policy §5.6.12 version comparison rules across standard test vectors."""
    result = compare_debian_versions(v1, v2)
    assert result == expected

    if expected == -1:
        assert is_debian_version_less(v1, v2) is True
    elif expected in (0, 1):
        assert is_debian_version_less(v1, v2) is False
