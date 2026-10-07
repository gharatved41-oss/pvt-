"""Server-Side Request Forgery (SSRF) Protection Guard.
Validates hostnames and IP addresses against restricted loopback,
private, and cloud metadata subnets before any external network inquiry.
"""
import ipaddress
import socket
from typing import Tuple
from backend.app.config import settings
from backend.app.core.logging import logger


class SSRFSecurityException(Exception):
    """Raised when an indicator attempts to target an internal or forbidden network."""
    pass


def is_ip_blocked(ip_str: str) -> bool:
    """Verifies whether an IP address belongs to blocked RFC1918, loopback, or metadata networks."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for cidr in settings.BLOCKED_IP_NETWORKS:
            network = ipaddress.ip_network(cidr)
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return True  # Invalid IP address syntax is treated as blocked for safety


def validate_ssrf_safety(hostname: str) -> Tuple[bool, str]:
    """
    Checks if a hostname resolves to any blocked private or loopback IP address.
    Returns (is_safe: bool, reason: str).
    """
    if not hostname:
        return False, "Empty hostname provided."

    # Immediate string checks for obvious internal targets
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
        return False, f"Target '{hostname}' references a forbidden local or internal resource."

    # Check if host is direct IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_blocked(str(ip_obj)):
            return False, f"Direct IP '{hostname}' belongs to a restricted internal subnet."
        return True, "IP is public and safe for reputation lookup."
    except ValueError:
        pass  # It's a domain name, proceed to DNS resolution check

    # Perform DNS resolution
    try:
        resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for item in resolved_ips:
            ip_candidate = item[4][0]
            if is_ip_blocked(ip_candidate):
                return False, f"Domain '{hostname}' resolves to restricted internal IP {ip_candidate} (SSRF prevention)."
        return True, "Domain resolved safely to external addresses."
    except socket.gaierror:
        # If domain does not resolve, it may be a parked or sinkholed domain
        # In threat intelligence, unregistered/dead domains are analyzed statically, not considered SSRF
        return True, "Domain does not resolve to local hosts."
    except Exception as e:
        logger.warning(f"Error during SSRF check for {hostname}: {str(e)}")
        return False, f"SSRF resolution check failed: {str(e)}"
