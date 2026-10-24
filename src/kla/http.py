"""One timed HTTPS request with pycurl, split into network phases.

libcurl records a timestamp at each step of a request, all measured from the
moment the request starts:

    start ─ DNS done ─ TCP connected ─ TLS done ─ request sent ─ first byte ─ last byte
            NAMELOOKUP  CONNECT        APPCONNECT  PRETRANSFER    STARTTRANSFER TOTAL

Subtracting neighbouring timestamps gives the time spent in each phase.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pycurl

# Tests replace this with a fake so no real network traffic is ever sent.
CURL_FACTORY: Callable[[], Any] = pycurl.Curl

# Response headers worth keeping: they reveal which CDN edge answered.
KEEP_HEADERS = ("server", "cf-ray", "x-amz-cf-pop", "via", "x-served-by", "x-cache", "alt-svc")

HTTP_VERSIONS = {1: "1.0", 2: "1.1", 3: "2", 30: "3"}

# Which HTTP version to offer. HTTP/1.1 is the default because (a) the official
# Python SDKs (built on httpx) use HTTP/1.1 unless told otherwise, and (b) the
# libcurl 8.22 bundled with pycurl 7.48 stalled ~1 s on small HTTP/2 replies in
# testing (system curl 8.5 did not), which would have polluted the timings.
HTTP_VERSION_OPTS = {
    "1.1": pycurl.CURL_HTTP_VERSION_1_1,
    "2": pycurl.CURL_HTTP_VERSION_2TLS,
}

# libcurl error numbers -> short names used in the data.
CURL_ERRORS = {
    6: "dns_failure",
    7: "connect_failed",
    16: "http2_error",
    18: "partial_body",
    23: "body_cap",  # our own write callback stopped reading (not a network error)
    28: "timeout",
    35: "tls_error",
    47: "too_many_redirects",
    52: "empty_reply",
    55: "send_error",
    56: "recv_error",
    60: "cert_error",
    92: "http2_stream_error",
}


@dataclass
class Phases:
    dns_ms: float | None = None
    tcp_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None  # server wait: request sent -> first byte back
    transfer_ms: float | None = None
    total_ms: float | None = None


@dataclass
class HttpResult:
    phases: Phases
    http_status: int | None = None
    http_version: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    alpn: str | None = None
    remote_ip: str | None = None
    size_bytes: int | None = None
    num_connects: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error_type: str | None = None
    error_code: int | None = None
    error_msg: str | None = None
    edge_pop: str | None = None
    edge_source: str | None = None
    # Our own clock (time.perf_counter), read just before curl starts and just after
    # it returns. AI first-token times use the same clock and the same start, so
    # "first token" and "total" can be compared directly (curl's own total stops
    # a fraction of a millisecond before the last data reaches us).
    started: float | None = None
    wall_ms: float | None = None

    @property
    def ok(self) -> bool:
        """We reached the server and got an HTTP answer (any status code)."""
        return bool(self.http_status) and self.error_type in (None, "body_cap")


def compute_phases(t: dict[str, int], reused: bool = False) -> Phases:
    """Turn libcurl's cumulative microsecond timestamps into per-phase milliseconds.

    A timestamp of 0 means "this step never happened" (for example TLS after a
    connection timeout), so that phase is left empty instead of being a
    misleading negative number.
    """
    nl, co, ac = t.get("namelookup", 0), t.get("connect", 0), t.get("appconnect", 0)
    pt, st, tt = t.get("pretransfer", 0), t.get("starttransfer", 0), t.get("total", 0)

    def span(a: int, b: int) -> float | None:
        return round((b - a) / 1000, 3) if b >= a else None

    p = Phases(total_ms=round(tt / 1000, 3) if tt else None)
    if reused:
        # An already-open connection skips DNS, TCP and TLS entirely.
        p.dns_ms = p.tcp_ms = p.tls_ms = 0.0
    else:
        p.dns_ms = round(nl / 1000, 3) if (nl or co) else None
        p.tcp_ms = span(nl, co) if co else None
        p.tls_ms = span(co, ac) if (co and ac) else None
    if st:
        p.ttfb_ms = span(pt, st) if pt else None
        p.transfer_ms = span(st, tt) if tt else None
    return p


_TLS_RE = re.compile(r"SSL connection using (TLSv[\d.]+|TLS[\d.]+) / ([A-Za-z0-9_\-]+)")
_ALPN_RE = re.compile(r"ALPN[:,] server accepted(?: to use)? (\S+)")


def parse_debug(lines: list[str]) -> tuple[str | None, str | None, str | None]:
    """Find TLS version, cipher and ALPN protocol in libcurl's verbose text."""
    tls_version = cipher = alpn = None
    for line in lines:
        if m := _TLS_RE.search(line):
            tls_version, cipher = m.group(1), m.group(2)
        elif m := _ALPN_RE.search(line):
            alpn = m.group(1)
    return tls_version, cipher, alpn


def edge_from_headers(headers: dict[str, str]) -> tuple[str | None, str | None]:
    """Which CDN city answered? CDNs put an airport code in their headers.

    cf-ray: 8a1b2c3d4e5f6a7b-MBA      -> Cloudflare, Mombasa
    x-amz-cf-pop: NBO50-C1            -> Amazon CloudFront, Nairobi
    x-served-by: cache-jnb7020-JNB    -> Fastly, Johannesburg
    """
    if ray := headers.get("cf-ray"):
        m = re.search(r"-([A-Z]{3})$", ray.strip())
        if m:
            return m.group(1), "cloudflare"
    if pop := headers.get("x-amz-cf-pop"):
        m = re.match(r"([A-Z]{3})", pop.strip())
        if m:
            return m.group(1), "cloudfront"
    if served := headers.get("x-served-by"):
        m = re.search(r"cache-([a-z]{3})\d", served)
        if m:
            return m.group(1).upper(), "fastly"
    return None, None


def classify_error(code: int, t: dict[str, int]) -> str:
    name = CURL_ERRORS.get(code, f"curl_{code}")
    if name == "timeout":
        # Say *where* it timed out: that tells DNS, routing and server problems apart.
        if not t.get("namelookup") and not t.get("connect"):
            return "timeout_dns"
        if not t.get("connect"):
            return "timeout_connect"
        if not t.get("appconnect"):
            return "timeout_tls"
        if not t.get("starttransfer"):
            return "timeout_ttfb"
        return "timeout_transfer"
    return name


def _getinfo_times(c: Any) -> dict[str, int]:
    names = {
        "namelookup": pycurl.NAMELOOKUP_TIME_T,
        "connect": pycurl.CONNECT_TIME_T,
        "appconnect": pycurl.APPCONNECT_TIME_T,
        "pretransfer": pycurl.PRETRANSFER_TIME_T,
        "starttransfer": pycurl.STARTTRANSFER_TIME_T,
        "total": pycurl.TOTAL_TIME_T,
    }
    return {k: int(c.getinfo(v) or 0) for k, v in names.items()}


def request(
    url: str,
    *,
    method: str = "GET",
    headers: list[str] | None = None,
    body: bytes | None = None,
    resolve_ip: str | None = None,
    ip_version: int = 4,
    http_version: str = "1.1",
    connect_timeout_s: float = 10,
    total_timeout_s: float = 20,
    user_agent: str = "kenya-llm-latency",
    max_body_bytes: int = 262_144,
    keep_body: bool = False,
    on_data: Callable[[bytes], None] | None = None,
    handle: Any = None,
) -> HttpResult:
    """Make one request and return its phase timings. Never raises on network errors.

    Pass `handle` to reuse a connection (Part 3 experiment); otherwise a brand-new
    curl handle is used and connection reuse is forbidden, so every probe pays
    the full DNS + TCP + TLS cost like a first visit.
    """
    own_handle = handle is None
    c = CURL_FACTORY() if own_handle else handle
    debug_lines: list[str] = []
    resp_headers: dict[str, str] = {}
    chunks: list[bytes] = []
    received = 0

    def on_header(raw: bytes) -> None:
        line = raw.decode("iso-8859-1").strip()
        if line.startswith("HTTP/"):
            resp_headers.clear()  # a new response (e.g. after 100-continue)
        elif ":" in line:
            name, _, value = line.partition(":")
            if name.strip().lower() in KEEP_HEADERS:
                resp_headers[name.strip().lower()] = value.strip()

    def on_write(data: bytes) -> int | None:
        nonlocal received
        received += len(data)
        if on_data is not None:
            on_data(data)
        if keep_body:
            chunks.append(data)
        if received > max_body_bytes:
            return 0  # stop: we only need the timing, not a big body
        return None

    def on_debug(kind: int, msg: bytes) -> None:
        # Only libcurl's own informational text; never request headers, so an
        # Authorization header can never end up in our logs.
        if kind == pycurl.INFOTYPE_TEXT:
            debug_lines.append(msg.decode("utf-8", "replace").strip())

    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.NOSIGNAL, 1)
    c.setopt(pycurl.FOLLOWLOCATION, 0)
    c.setopt(pycurl.CONNECTTIMEOUT_MS, int(connect_timeout_s * 1000))
    c.setopt(pycurl.TIMEOUT_MS, int(total_timeout_s * 1000))
    c.setopt(pycurl.USERAGENT, user_agent)
    c.setopt(pycurl.HTTP_VERSION, HTTP_VERSION_OPTS[http_version])
    c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V6 if ip_version == 6 else pycurl.IPRESOLVE_V4)
    c.setopt(pycurl.HEADERFUNCTION, on_header)
    c.setopt(pycurl.WRITEFUNCTION, on_write)
    c.setopt(pycurl.VERBOSE, 1)
    c.setopt(pycurl.DEBUGFUNCTION, on_debug)
    c.setopt(pycurl.HTTPHEADER, headers or [])
    if own_handle:
        c.setopt(pycurl.FRESH_CONNECT, 1)
        c.setopt(pycurl.FORBID_REUSE, 1)
        c.setopt(pycurl.DNS_CACHE_TIMEOUT, 0)
        c.setopt(pycurl.SSL_SESSIONID_CACHE, 0)  # no TLS session resumption
    if resolve_ip:
        # Pin the IP we already resolved, so curl's own DNS step is ~0 ms and the
        # DNS time is measured separately (see dnsprobe.py).
        host = url.split("/")[2].split(":")[0]
        c.setopt(pycurl.RESOLVE, [f"{host}:443:{resolve_ip}"])
    if method == "POST":
        c.setopt(pycurl.POST, 1)
        c.setopt(pycurl.POSTFIELDS, body or b"")
    else:
        c.setopt(pycurl.HTTPGET, 1)

    error_code: int | None = None
    error_msg: str | None = None
    started = time.perf_counter()
    try:
        c.perform()
    except pycurl.error as exc:
        error_code = int(exc.args[0]) if exc.args else -1
        error_msg = str(exc.args[1])[:300] if len(exc.args) > 1 else "curl error"
    wall_ms = round((time.perf_counter() - started) * 1000, 3)

    times = _getinfo_times(c)
    num_connects = int(c.getinfo(pycurl.NUM_CONNECTS) or 0)
    status = int(c.getinfo(pycurl.RESPONSE_CODE) or 0) or None
    http_ver = HTTP_VERSIONS.get(int(c.getinfo(pycurl.INFO_HTTP_VERSION) or 0))
    remote_ip = c.getinfo(pycurl.PRIMARY_IP) or None
    size = int(c.getinfo(pycurl.SIZE_DOWNLOAD_T) or 0)
    if own_handle:
        c.close()

    tls_version, cipher, alpn = parse_debug(debug_lines)
    reused = (not own_handle) and num_connects == 0 and status is not None
    pop, pop_source = edge_from_headers(resp_headers)
    return HttpResult(
        phases=compute_phases(times, reused=reused),
        http_status=status,
        http_version=http_ver,
        tls_version=tls_version,
        tls_cipher=cipher,
        alpn=alpn,
        remote_ip=remote_ip,
        size_bytes=size,
        num_connects=num_connects,
        headers=resp_headers,
        body=b"".join(chunks),
        error_type=classify_error(error_code, times) if error_code is not None else None,
        error_code=error_code,
        error_msg=error_msg,
        edge_pop=pop,
        edge_source=pop_source,
        started=started,
        wall_ms=wall_ms,
    )
