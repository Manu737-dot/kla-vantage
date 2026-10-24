import pycurl

from kla import http


def test_phases_from_cumulative_timestamps():
    p = http.compute_phases(
        {
            "namelookup": 50_000,
            "connect": 150_000,
            "appconnect": 350_000,
            "pretransfer": 351_000,
            "starttransfer": 751_000,
            "total": 752_000,
        }
    )
    assert (p.dns_ms, p.tcp_ms, p.tls_ms, p.ttfb_ms, p.transfer_ms, p.total_ms) == (
        50.0,
        100.0,
        200.0,
        400.0,
        1.0,
        752.0,
    )


def test_phase_left_empty_when_step_never_happened():
    # Timed out during TLS: appconnect and starttransfer are 0.
    p = http.compute_phases({"namelookup": 10_000, "connect": 90_000, "total": 10_000_000})
    assert p.tcp_ms == 80.0
    assert p.tls_ms is None and p.ttfb_ms is None and p.transfer_ms is None


def test_connect_before_dns_finished_gives_no_negative_tcp():
    # libcurl can start connecting on the first DNS answer while another is pending.
    p = http.compute_phases({"namelookup": 86_000, "connect": 43_000, "appconnect": 92_000})
    assert p.tcp_ms is None


def test_reused_connection_has_zero_setup_cost():
    p = http.compute_phases(
        {"pretransfer": 100, "starttransfer": 300_100, "total": 300_500}, reused=True
    )
    assert (p.dns_ms, p.tcp_ms, p.tls_ms) == (0.0, 0.0, 0.0)
    assert p.ttfb_ms == 300.0


def test_parse_debug_finds_tls_and_alpn():
    assert http.parse_debug(
        [
            "Trying 1.2.3.4:443...",
            "SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / X25519 / RSASSA-PSS",
            "ALPN: server accepted h2",
        ]
    ) == ("TLSv1.3", "TLS_AES_128_GCM_SHA256", "h2")
    assert http.parse_debug(["ALPN, server accepted to use http/1.1"])[2] == "http/1.1"


def test_edge_from_headers():
    assert http.edge_from_headers({"cf-ray": "a4e1ce61ac38793a-DAR"}) == ("DAR", "cloudflare")
    assert http.edge_from_headers({"x-amz-cf-pop": "NBO50-C1"}) == ("NBO", "cloudfront")
    assert http.edge_from_headers({"x-served-by": "cache-jnb7020-JNB"}) == ("JNB", "fastly")
    assert http.edge_from_headers({"server": "nginx"}) == (None, None)


def test_timeout_is_classified_by_phase():
    assert http.classify_error(28, {}) == "timeout_dns"
    assert http.classify_error(28, {"namelookup": 5}) == "timeout_connect"
    assert http.classify_error(28, {"namelookup": 5, "connect": 9}) == "timeout_tls"
    assert (
        http.classify_error(28, {"namelookup": 5, "connect": 9, "appconnect": 20}) == "timeout_ttfb"
    )
    assert http.classify_error(6, {}) == "dns_failure"
    assert http.classify_error(999, {}) == "curl_999"


def test_request_records_everything(fake_curl):
    made = fake_curl(status=401, chunks=[b'{"error":"no key"}'])
    res = http.request("https://api.example.com/v1/models", resolve_ip="203.0.113.10")
    assert res.ok and res.http_status == 401
    assert res.http_version == "2" and res.tls_version == "TLSv1.3" and res.alpn == "h2"
    assert res.edge_pop == "MBA" and res.edge_source == "cloudflare"
    assert res.headers["server"] == "cloudflare"
    assert res.phases.tcp_ms == 59.9 and res.phases.tls_ms == 120.0
    c = made[0]
    # A brand-new connection every time:
    assert c.opts[pycurl.FRESH_CONNECT] == 1 and c.opts[pycurl.FORBID_REUSE] == 1
    assert c.opts[pycurl.SSL_SESSIONID_CACHE] == 0
    assert c.opts[pycurl.HTTP_VERSION] == pycurl.CURL_HTTP_VERSION_1_1  # see HTTP_VERSION_OPTS
    assert c.opts[pycurl.RESOLVE] == ["api.example.com:443:203.0.113.10"]
    assert c.closed


def test_request_failure_is_data_not_exception(fake_curl):
    fake_curl(
        status=0,
        times={"namelookup": 100, "connect": 70_000},
        headers=[],
        chunks=[],
        error=(28, "Connection timed out after 10001 milliseconds"),
    )
    res = http.request("https://api.example.com/")
    assert not res.ok
    assert res.error_type == "timeout_tls" and res.error_code == 28
    assert res.phases.tcp_ms is not None and res.phases.tls_ms is None
    assert res.started is not None and res.wall_ms is not None and res.wall_ms >= 0


def test_body_cap_stops_download_but_counts_as_answered(fake_curl):
    fake_curl(chunks=[b"x" * 600, b"y" * 600])
    res = http.request("https://api.example.com/", max_body_bytes=1000)
    assert res.error_type == "body_cap" and res.ok


def test_reused_handle_is_not_closed(fake_curl):
    from tests.conftest import FakeCurl

    keep = FakeCurl(num_connects=0)
    res = http.request("https://api.example.com/", handle=keep)
    assert not keep.closed
    assert pycurl.FRESH_CONNECT not in keep.opts
    assert res.phases.tcp_ms == 0.0
