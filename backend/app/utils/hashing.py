"""Cryptographic hash validation and identification utilities.
Supports MD5, SHA-1, and SHA-256 formatting checks without executing untrusted binaries.
"""
import re
from typing import Tuple


def identify_hash_type(hash_str: str) -> Tuple[bool, str, str]:
    """
    Validates cryptographic hash string format.
    Returns (is_valid: bool, hash_type: str, cleaned_hash: str).
    """
    if not hash_str or not isinstance(hash_str, str):
        return False, "UNKNOWN", ""

    cleaned = hash_str.strip().lower()

    if not re.match(r"^[a-f0-9]+$", cleaned):
        return False, "INVALID_CHARS", cleaned

    length = len(cleaned)
    if length == 32:
        return True, "MD5", cleaned
    elif length == 40:
        return True, "SHA-1", cleaned
    elif length == 64:
        return True, "SHA-256", cleaned
    else:
        return False, "INVALID_LENGTH", cleaned
