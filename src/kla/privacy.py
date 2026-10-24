"""Keep personal data out of the database: the public IP and API keys."""

from __future__ import annotations

import ipaddress
from typing import Any

MASK = "<redacted>"


def is_private(ip: str) -> bool:
    """True for addresses that only make sense inside a home or ISP network.

    Covers RFC 1918 (192.168.x, 10.x, 172.16-31.x), carrier-grade NAT
    (100.64.0.0/10), link-local, loopback and IPv6 unique-local addresses.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def ip_variants(ip: str) -> list[str]:
    """Forms in which an IPv4 address shows up inside router hostnames.

    ISPs often name customer-facing hops like `41-90-12-34.isp.co.ke` or
    `34.12.90.41.in-addr...`, so masking only the dotted form is not enough.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return [ip]
    rev = list(reversed(parts))
    return [ip, "-".join(parts), ".".join(rev), "-".join(rev), "_".join(parts)]


def scrub_text(text: str, secrets: list[str]) -> str:
    out = text
    for secret in secrets:
        if not secret:
            continue
        variants = ip_variants(secret) if _looks_like_ipv4(secret) else [secret]
        for v in variants:
            out = out.replace(v, MASK)
    return out


def scrub(value: Any, secrets: list[str]) -> Any:
    """Recursively replace secrets in strings inside dicts/lists."""
    if isinstance(value, str):
        return scrub_text(value, secrets)
    if isinstance(value, dict):
        return {k: scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    return value


def _looks_like_ipv4(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
    except ValueError:
        return False
