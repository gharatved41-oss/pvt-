"""URL Normalization and Indicator Extraction.
Follows strict RFC 3986 guidelines, strips port defaults, canonicalizes paths,
and extracts lexical threat indicators without executing or fetching untrusted payloads.
"""
import re
import math
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlunparse, parse_qs, unquote


# Known suspicious TLDs often abused in automated phishing/malware delivery campaigns
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "buzz", "club", "cam", "icu", "work", 
    "kim", "surf", "gq", "cf", "tk", "ml", "ga", "fit", "rest", "bar"
}

# High-risk executable and script extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", 
    ".msi", ".jar", ".iso", ".img", ".apk", ".dll", ".pif", ".cpl"
}

# Brands frequently targeted by phishing attacks
COMMON_TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon", 
    "chase", "wellsfargo", "bankofamerica", "steam", "discord", 
    "instagram", "facebook", "whatsapp", "telegram", "coinbase", "binance",
    "metamask", "vlc", "zoom", "chrome", "7zip"
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect randomized/DGA domains."""
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in prob_dict.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class URLValidationError(ValueError):
    """Raised when URL fails syntactic or security validation."""
    pass


def normalize_url(raw_url: str) -> Dict[str, Any]:
    """
    Validates, normalizes, and extracts comprehensive indicators from a URL.
    Does NOT connect to the internet or fetch untrusted content.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise URLValidationError("URL string must not be empty.")
    
    cleaned_url = raw_url.strip()
    if len(cleaned_url) > 2048:
        raise URLValidationError("URL length exceeds maximum safe threshold (2048 characters).")

    # If user provided scheme like javascript: or data: without //
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", cleaned_url) and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url):
        scheme_prefix = cleaned_url.split(":", 1)[0].lower()
        if scheme_prefix not in ("http", "https"):
            raise URLValidationError(f"Unsupported URL scheme '{scheme_prefix}'. Only HTTP and HTTPS are permitted.")

    # If user provided domain without scheme, prefix http for parsing inspection
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url):
        cleaned_url = "http://" + cleaned_url

    parsed = urlparse(cleaned_url)

    # Scheme verification
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise URLValidationError(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    # Host validation
    try:
        host = parsed.hostname
    except ValueError:
        raise URLValidationError("Malformed host or port specification in URL.")

    if not host:
        raise URLValidationError("URL does not contain a valid hostname.")
    
    host = host.lower()
    
    # Check for punycode / IDN homograph representation
    has_punycode = host.startswith("xn--") or ".xn--" in host
    try:
        decoded_host = host.encode("idna").decode("idna")
    except Exception:
        decoded_host = host

    # Normalize default ports
    try:
        port = parsed.port
    except ValueError:
        raise URLValidationError("Invalid or non-numeric port in URL.")
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = host
    if port:
        netloc = f"{host}:{port}"

    # Path normalization: collapse multiple slashes, clean traversal
    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)

    # Reconstruct canonical URL
    normalized_url = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # Exclude fragment for network security reputation
    ))

    # Indicator decomposition
    host_parts = host.split(".")
    is_ip = False
    
    # Check if host is IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        is_ip = True
        tld = "ip_address"
        domain = host
        subdomain = ""
    elif len(host_parts) >= 2:
        tld = host_parts[-1]
        domain = ".".join(host_parts[-2:])
        subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
    else:
        tld = ""
        domain = host
        subdomain = ""

    # Lexical features
    path_lower = path.lower()
    has_executable = any(path_lower.endswith(ext) or ext + "?" in path_lower for ext in EXECUTABLE_EXTENSIONS)
    detected_extensions = [ext for ext in EXECUTABLE_EXTENSIONS if ext in path_lower]

    # Brand impersonation detection
    matched_brands = []
    for brand in COMMON_TARGETED_BRANDS:
        if brand in host and not host.endswith(f"{brand}.com") and not host.endswith(f"{brand}.org"):
            matched_brands.append(brand)

    entropy = calculate_entropy(host_parts[0] if host_parts else host)
    suspicious_tld = tld in SUSPICIOUS_TLDS

    # Check for excessive special characters
    special_char_count = len(re.findall(r"[-_@!~*'%]", host))

    return {
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "hostname": host,
        "decoded_hostname": decoded_host,
        "domain": domain,
        "subdomain": subdomain,
        "tld": tld,
        "port": port,
        "path": path,
        "query": parsed.query,
        "query_present": bool(parsed.query),
        "is_ip": is_ip,
        "has_punycode": has_punycode,
        "has_executable": has_executable,
        "detected_extensions": detected_extensions,
        "matched_brands": matched_brands,
        "hostname_entropy": entropy,
        "suspicious_tld": suspicious_tld,
        "hostname_length": len(host),
        "url_length": len(normalized_url),
        "special_char_count": special_char_count,
    }
