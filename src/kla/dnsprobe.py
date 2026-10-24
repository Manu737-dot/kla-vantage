"""DNS timing, measured two ways.

Ubuntu's systemd-resolved keeps a cache on the laptop, so asking "the system"
for a name we looked up 15 minutes ago is often instant and says nothing about
the network. We therefore measure:

1. direct: a query sent straight to the upstream resolver (normally the home
   router), skipping the laptop's cache. The router may still have the answer
   cached (from our last run or another device), which is also what real apps
   experience. Measured FIRST, so step 2 cannot warm the router's cache for it.
2. system: the normal `getaddrinfo()` path every app uses, which goes through
   systemd-resolved and its cache.

The IP from the direct lookup is then pinned into curl, so the TCP/TLS/TTFB
timings that follow do not include DNS at all.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

RESOLVED_UPSTREAM = Path("/run/systemd/resolve/resolv.conf")

# Indirection so tests can swap these out (no real DNS traffic in tests).
_udp_query = dns.query.udp
_tcp_query = dns.query.tcp
_getaddrinfo = socket.getaddrinfo


@dataclass
class DnsResult:
    ms: float | None = None
    ips: list[str] = field(default_factory=list)
    ttl: int | None = None
    server: str | None = None
    error: str | None = None


def upstream_servers(
    setting: str | list[str] = "auto", path: Path = RESOLVED_UPSTREAM
) -> list[str]:
    """The resolvers systemd-resolved forwards to (skipping its 127.0.0.53 stub)."""
    if isinstance(setting, list):
        return [str(s) for s in setting]
    servers: list[str] = []
    for candidate in (path, Path("/etc/resolv.conf")):
        try:
            text = candidate.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and not parts[1].startswith("127."):
                servers.append(parts[1])
        if servers:
            break
    return servers


def direct_lookup(host: str, servers: list[str], timeout_s: float = 5) -> DnsResult:
    """Ask the upstream resolver directly for the host's IPv4 address."""
    if not servers:
        return DnsResult(error="no_upstream_resolver")
    last_error = "dns_failure"
    for server in servers[:2]:
        query = dns.message.make_query(host, dns.rdatatype.A)
        start = time.perf_counter()
        try:
            resp = _udp_query(query, server, timeout=timeout_s)
            if resp.flags & dns.flags.TC:  # answer too big for UDP: retry over TCP
                resp = _tcp_query(query, server, timeout=timeout_s)
        except dns.exception.Timeout:
            last_error = "dns_timeout"
            continue
        except (OSError, dns.exception.DNSException) as exc:
            last_error = f"dns_error: {type(exc).__name__}"
            continue
        elapsed = round((time.perf_counter() - start) * 1000, 3)
        rcode = dns.rcode.to_text(resp.rcode())
        if rcode != "NOERROR":
            return DnsResult(ms=elapsed, server=server, error=f"dns_{rcode.lower()}")
        ips: list[str] = []
        ttls: list[int] = []
        for rrset in resp.answer:
            ttls.append(int(rrset.ttl))
            if rrset.rdtype == dns.rdatatype.A:
                ips.extend(r.address for r in rrset)
        if not ips:
            return DnsResult(ms=elapsed, server=server, error="dns_no_address")
        return DnsResult(ms=elapsed, ips=ips, ttl=min(ttls) if ttls else None, server=server)
    return DnsResult(error=last_error, server=servers[0])


def system_lookup(host: str) -> DnsResult:
    """Resolve through the normal system path (systemd-resolved, with its cache)."""
    start = time.perf_counter()
    try:
        infos = _getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return DnsResult(
            ms=round((time.perf_counter() - start) * 1000, 3), error=f"dns_failure: {exc}"
        )
    elapsed = round((time.perf_counter() - start) * 1000, 3)
    ips = list(dict.fromkeys(str(info[4][0]) for info in infos))
    return DnsResult(ms=elapsed, ips=ips, server="system")
