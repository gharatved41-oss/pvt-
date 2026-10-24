"""Pure-Python implementation of Debian Policy Manual §5.6.12 version comparison.

Accurately handles epochs, upstream versions, Debian revisions, and tilde (~) ordering.
Does not use Python PEP 440 (packaging.version), which is incompatible with Debian packages.
"""

import re
from typing import Optional, Tuple



def parse_debian_version(version_str: str) -> Tuple[int, str, str]:
    """Parse a Debian version string into (epoch, upstream_version, debian_revision).

    Syntax: [epoch:]upstream_version[-debian_revision]

    Args:
        version_str: Raw version string (e.g., '1:2.35-0ubuntu3.4', '3.0.2-0ubuntu1.10', '2.0~rc1').

    Returns:
        Tuple of (epoch as int, upstream_version as str, debian_revision as str).
    """
    clean_ver = str(version_str).strip()
    if not clean_ver:
        return 0, "", ""

    # 1. Parse epoch (optional digits followed by colon)
    epoch = 0
    if ":" in clean_ver:
        epoch_str, remainder = clean_ver.split(":", 1)
        try:
            epoch = int(epoch_str)
        except ValueError:
            epoch = 0
        clean_ver = remainder

    # 2. Parse debian_revision (optional part following the LAST hyphen)
    debian_revision = ""
    if "-" in clean_ver:
        upstream_version, debian_revision = clean_ver.rsplit("-", 1)
    else:
        upstream_version = clean_ver

    return epoch, upstream_version, debian_revision


def _order_char(char: Optional[str]) -> int:
    """Return sorting weight for a single character in non-digit phase per dpkg verrevcmp.

    - Tilde '~' sorts before anything else (even empty string). Weight: -1
    - End-of-string or digit returns 0 (terminates non-digit phase).
    - Letters sort in alphabetical order (a-z, A-Z). Weight: ord(char)
    - Other non-digit characters sort after letters. Weight: ord(char) + 256
    """
    if not char or char.isdigit():
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def compare_debian_part(val: str, ref: str) -> int:
    """Compare two version parts (upstream_version or debian_revision) per Debian Policy §5.6.12.

    Faithful pure-Python implementation of dpkg's verrevcmp algorithm.
    Alternates between non-digit lexical comparison (with tilde sorting before everything)
    and mathematical digit comparison (stripping leading zeros).
    """
    val = val or ""
    ref = ref or ""
    i, j = 0, 0
    len_v, len_r = len(val), len(ref)

    while i < len_v or j < len_r:
        # Step A: Compare non-digit chunks
        while (i < len_v and not val[i].isdigit()) or (j < len_r and not ref[j].isdigit()):
            c_v = val[i] if i < len_v else ""
            c_r = ref[j] if j < len_r else ""
            vc = _order_char(c_v)
            rc = _order_char(c_r)
            if vc != rc:
                return -1 if vc < rc else 1
            i += 1
            j += 1

        # Step B: Strip leading zeros from numerical chunks
        while i < len_v and val[i] == "0":
            i += 1
        while j < len_r and ref[j] == "0":
            j += 1

        # Step C: Compare digits by mathematical magnitude
        first_diff = 0
        while i < len_v and val[i].isdigit() and j < len_r and ref[j].isdigit():
            if not first_diff:
                diff = ord(val[i]) - ord(ref[j])
                if diff != 0:
                    first_diff = diff
            i += 1
            j += 1

        # If one sequence has more remaining digits, it is numerically larger
        if i < len_v and val[i].isdigit():
            return 1
        if j < len_r and ref[j].isdigit():
            return -1
        if first_diff != 0:
            return -1 if first_diff < 0 else 1

    return 0



def compare_debian_versions(v1: str, v2: str) -> int:
    """Compare two complete Debian version strings.

    Returns:
        -1 if v1 < v2 (v1 is older)
         0 if v1 == v2 (equal)
         1 if v1 > v2 (v1 is newer)
    """
    epoch1, upstream1, rev1 = parse_debian_version(v1)
    epoch2, upstream2, rev2 = parse_debian_version(v2)

    # 1. Compare epochs numerically
    if epoch1 < epoch2:
        return -1
    if epoch1 > epoch2:
        return 1

    # 2. Compare upstream versions
    res_upstream = compare_debian_part(upstream1, upstream2)
    if res_upstream != 0:
        return res_upstream

    # 3. Compare Debian revisions
    return compare_debian_part(rev1, rev2)


def is_debian_version_less(installed: str, target: str) -> bool:
    """Convenience helper returning True if installed < target."""
    return compare_debian_versions(installed, target) < 0
