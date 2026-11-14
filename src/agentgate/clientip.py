"""Client IP resolution that cannot be spoofed via X-Forwarded-For.

Only the right-most ``trusted_proxy_hops`` entries of X-Forwarded-For are
written by proxies you control; anything to their left is client-supplied.
With ``trusted_proxy_hops: 0`` the header is ignored entirely.
"""

from __future__ import annotations

import ipaddress
from typing import Optional


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def resolve_client_ip(peer: Optional[str], xff_values: list[str], trusted_proxy_hops: int) -> str:
    peer_ip = _valid_ip(peer) if peer else None
    if trusted_proxy_hops > 0 and xff_values:
        chain = [p.strip() for v in xff_values for p in v.split(",") if p.strip()]
        if len(chain) >= trusted_proxy_hops:
            candidate = _valid_ip(chain[-trusted_proxy_hops])
            if candidate:
                return candidate
    return peer_ip or "unknown"


def network_prefix(ip: str) -> str:
    """Coarse network bucket: /24 for IPv4, /48 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    bits = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))
