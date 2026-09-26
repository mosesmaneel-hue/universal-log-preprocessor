"""
SSRF Protection utility for user-supplied AI provider endpoints.
Validates URL scheme, format, hostname, and verifies destination IP is not internal/private/loopback.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Check if an IP address string is private, loopback, link-local, multicast, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True


def validate_user_endpoint(url: str, allow_http: bool = False) -> Tuple[bool, str]:
    """
    Validates a user-supplied API endpoint against SSRF risks.
    
    Returns (is_valid: bool, error_message: str).
    """
    if not url or not isinstance(url, str):
        return False, "Endpoint URL is required."

    url = url.strip()

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL format."

    # 1. Scheme check: only HTTPS allowed for user external providers (HTTP allowed only if flag set)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https", "http"):
        return False, f"Unsupported URL scheme '{scheme}'. Only HTTP/HTTPS is permitted."

    if scheme != "https" and not allow_http:
        return False, "External user-supplied AI endpoints must use HTTPS for credential security."

    # 2. Hostname check
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a valid hostname."

    # Reject credentials in URL
    if parsed.username or parsed.password:
        return False, "URL must not contain embedded user credentials."

    # Reject localhost literal names
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "localhost.localdomain"):
        return False, "Requests to localhost or loopback are not allowed for external AI endpoints."

    # 3. IP Resolution check
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            if is_private_or_loopback_ip(ip_str):
                return False, "Target host resolves to a private, loopback, or reserved network address."
    except socket.gaierror:
        return False, f"Could not resolve hostname '{hostname}'."
    except Exception as e:
        return False, f"Address resolution validation failed: {str(e)}"

    return True, ""
