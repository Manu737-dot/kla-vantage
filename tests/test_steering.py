"""The near/far switch check: DNS steering vs anycast, from stored data only."""

from datetime import UTC, datetime, timedelta

from kla import steering
from kla.steering import Obs, Trace

T0 = datetime(2026, 10, 21, 19, 0, tzinfo=UTC)  # 22:00 EAT
CF = "AS37100 SEACOM > AS13335 CLOUDFLARENET"


def at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def test_state_threshold_and_lost_packets():
    assert steering.state_of(12) == "near"
    assert steering.state_of(99.9) == "near"
    assert steering.state_of(100) == "far"
    assert steering.state_of(1319) is None  # a resent packet, not distance
    assert steering.state_of(None) is None


def test_no_switch_is_not_reported():
    obs = [Obs(at(15 * i), "104.18.2.115", 12) for i in range(4)]
    assert steering.classify("openai", obs, []) is None


def test_same_ip_local_ping_far_tcp_is_inside_provider():
    # Tonight's xAI pattern: same IP, ping 14 ms while TCP 219 ms (edge BUD), then local.
    ip = "104.18.18.80"
    obs = [
        Obs(at(m), ip, tcp, 40, edge)
        for m, tcp, edge in [
            (2, 219, "BUD"),
            (15, 273, "GVA"),
            (31, 222, "BUD"),
            (60, 53, "MPM"),
            (75, 16, "DAR"),
            (120, 17, "MBA"),
        ]
    ]
    traces = [Trace(at(1), ip, 14.4, CF, 12), Trace(at(66), ip, 10.1, CF, 12)]
    v = steering.classify("xai", obs, traces)
    assert v.verdict == "inside_provider"
    assert v.shared_ips == {ip}
    assert len(v.switches) == 1 and v.switches[0].direction == "far→near"
    text = "\n".join(v.evidence)
    assert "ping to 104.18.18.80 = 14 ms" in text and "the same IP" in text
    assert "BUD→MPM" in text and "unchanged" in text


def test_disjoint_addresses_is_dns_steering():
    obs = [
        Obs(at(0), "198.51.100.1", 220),
        Obs(at(15), "198.51.100.2", 230),
        Obs(at(30), "203.0.113.1", 12),
        Obs(at(45), "203.0.113.2", 11),
    ]
    v = steering.classify("x", obs, [])
    assert v.verdict == "dns_steering"
    assert "No address was ever seen in both states" in "\n".join(v.evidence)


def test_same_ip_with_far_ping_is_a_route_change():
    ip = "192.0.2.10"
    obs = [Obs(at(0), ip, 220), Obs(at(15), ip, 210), Obs(at(60), ip, 12), Obs(at(75), ip, 14)]
    traces = [Trace(at(1), ip, 205, CF, 14), Trace(at(61), ip, 11, CF, 12)]
    v = steering.classify("x", obs, traces)
    assert v.verdict == "route_change"
    assert "CHANGED" in "\n".join(v.evidence)  # hop count differs


def test_same_ip_different_as_path_is_a_route_change():
    ip = "192.0.2.10"
    obs = [Obs(at(0), ip, 220), Obs(at(15), ip, 210), Obs(at(60), ip, 12), Obs(at(75), ip, 14)]
    traces = [Trace(at(1), ip, 14, "AS1 > AS2 > AS13335", 12), Trace(at(61), ip, 11, CF, 12)]
    assert steering.classify("x", obs, traces).verdict == "route_change"


def test_same_ip_without_traceroutes():
    ip = "192.0.2.10"
    obs = [Obs(at(0), ip, 220), Obs(at(15), ip, 210), Obs(at(60), ip, 12), Obs(at(75), ip, 14)]
    v = steering.classify("x", obs, [Trace(at(500), ip, 11, CF, 12)])  # too far away in time
    assert v.verdict == "same_ip_no_trace"


def test_too_few_observations_is_inconclusive():
    obs = [Obs(at(0), "192.0.2.1", 220), Obs(at(15), "192.0.2.1", 12), Obs(at(30), "192.0.2.1", 11)]
    assert steering.classify("x", obs, []).verdict == "inconclusive"


def test_missing_ips_are_inconclusive_not_same_ip():
    obs = [
        Obs(at(0), None, 220),
        Obs(at(15), None, 210),
        Obs(at(60), None, 12),
        Obs(at(75), None, 14),
    ]
    v = steering.classify("x", obs, [])
    assert v.verdict == "inconclusive" and not v.shared_ips


def test_flapping_and_far_tls_are_flagged():
    # Tonight's Gemini pattern: rotating IPs, TCP flips near/far, TLS stays ~190 ms.
    ips = [f"172.217.{n}.4" for n in (119, 115, 117, 116, 112, 117, 119)]
    tcps = [575, 186, 12, 292, 58, 147, 11]
    obs = [Obs(at(15 * i), ip, tcp, 190) for i, (ip, tcp) in enumerate(zip(ips, tcps, strict=True))]
    traces = [
        Trace(at(-2), "172.217.119.4", 11.3, "AS37100 > AS15169", 11),
        Trace(at(31), "172.217.117.4", 11.4, "AS37100 > AS15169", 11),
    ]
    v = steering.classify("gemini", obs, traces)
    text = "\n".join(v.evidence)
    assert len(v.switches) == 5 and "flipped back and forth 5 times" in text
    assert "TLS handshake still took ~190 ms" in text
    assert v.verdict == "inside_provider"
    assert "ping +0 ms" in text or "ping -0 ms" in text


def test_report_lines_from_table_rows():
    ip = "104.18.18.80"
    probes = [
        {
            "target_id": "xai",
            "ts_utc": at(m).isoformat(),
            "remote_ip": ip,
            "tcp_ms": tcp,
            "tls_ms": 40,
            "edge_pop": edge,
            "ok": 1,
        }
        for m, tcp, edge in [(2, 219, "BUD"), (15, 273, "GVA"), (60, 53, "MPM"), (75, 16, "DAR")]
    ] + [
        {
            "target_id": "openai",
            "ts_utc": at(2).isoformat(),
            "remote_ip": "x",
            "tcp_ms": 11,
            "tls_ms": 30,
            "edge_pop": "MBA",
            "ok": 1,
        }
    ]
    traces = [
        {
            "target_id": "xai",
            "ts_utc": at(1).isoformat(),
            "dest_ip": ip,
            "dest_rtt_ms": 14.4,
            "as_path": CF,
            "hop_count": 12,
            "ok": 1,
        },
        {
            "target_id": "xai",
            "ts_utc": at(61).isoformat(),
            "dest_ip": ip,
            "dest_rtt_ms": 10.1,
            "as_path": CF,
            "hop_count": 12,
            "ok": 1,
        },
    ]
    text = "\n".join(steering.report_lines(probes, traces))
    assert "| xai | 2 | 2 | 1 | 1 | 1 | yes | anycast: same IP and route" in text
    assert "openai" not in text  # never switched
    assert "No target switched" in steering.report_lines(probes[-1:], [])[0]
