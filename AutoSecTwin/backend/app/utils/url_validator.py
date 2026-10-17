"""URL validation and canonicalization utility for target submissions."""

import re
from urllib.parse import urlsplit, urlunsplit


# Regex for valid hostname characters according to RFC 1035 / RFC 1123
HOSTNAME_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
ALLOWED_SCHEMES = {"http", "https"}


def validate_and_normalize_url(raw_url: str) -> str:
    """Validate target URL syntax according to defensive security rules.

    Permits only HTTP and HTTPS schemes.
    Rejects malformed URLs, missing hostnames, embedded credentials,
    and unsupported schemes.

    Args:
        raw_url: Raw input string provided by user/client.

    Returns:
        Canonical normalized URL string.

    Raises:
        ValueError: If validation rules are violated.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string.")

    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("URL must not be empty or whitespace only.")

    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        raise ValueError(f"Malformed URL structure: {exc}") from exc

    # 1. Scheme validation (strictly http or https)
    if not parsed.scheme:
        raise ValueError("URL is missing a protocol scheme. Only HTTP and HTTPS are supported.")

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    # 2. Embedded credentials check
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "URLs containing embedded user credentials (user:pass@) are rejected for security reasons."
        )

    # 3. Hostname validation
    try:
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError(f"Invalid host or port specification: {exc}") from exc

    if not hostname:
        raise ValueError("URL must contain a valid hostname or IP address.")

    hostname_lower = hostname.lower()

    if len(hostname_lower) > 253:
        raise ValueError("Hostname exceeds maximum allowable length of 253 characters.")

    # Check for empty labels or malformed dots (e.g. "example..com", ".example.com")
    if hostname_lower.startswith(".") or hostname_lower.endswith("."):
        raise ValueError("Hostname must not start or end with a dot.")

    if ".." in hostname_lower:
        raise ValueError("Hostname contains invalid consecutive dots.")

    # 4. Port validation if present
    try:
        port = parsed.port
        if port is not None and (port <= 0 or port > 65535):
            raise ValueError(f"Port {port} is out of allowable range (1-65535).")
    except ValueError as exc:
        if "out of range" in str(exc) or "Port" in str(exc):
            raise
        raise ValueError(f"Invalid port specification: {exc}") from exc

    # 5. Reconstruct canonical netloc
    if port is not None:
        # Include port only if non-standard
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = hostname_lower
        else:
            netloc = f"{hostname_lower}:{port}"
    else:
        netloc = hostname_lower

    path = parsed.path if parsed.path else ""

    # Reconstruct normalized URL
    return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
