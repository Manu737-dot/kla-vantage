import json

import dns.exception
import dns.message
import dns.rcode
import dns.rrset
import pytest

from kla import context, dnsprobe, util


def _answer(query, *records, rcode=dns.rcode.NOERROR):
    resp = dns.message.make_response(query)
    resp.set_rcode(rcode)
    for rec in records:
        resp.answer.append(dns.rrset.from_text(*rec))
    return resp


def test_upstream_servers_skips_local_stub(tmp_path):
    f = tmp_path / "resolv.conf"
    f.write_text("# generated\nnameserver 127.0.0.53\nnameserver 192.168.0.1\nsearch lan\n")
    assert dnsprobe.upstream_servers("auto", f) == ["192.168.0.1"]
    assert dnsprobe.upstream_servers(["1.1.1.1"]) == ["1.1.1.1"]


def test_direct_lookup_follows_cname_and_takes_min_ttl(monkeypatch):
    def fake_udp(query, server, timeout):
        return _answer(
            query,
            ("api.openai.com.", 300, "IN", "CNAME", "api.openai.com.cdn.cloudflare.net."),
            (
                "api.openai.com.cdn.cloudflare.net.",
                42,
                "IN",
                "A",
                "172.66.0.243",
                "162.159.140.245",
            ),
        )

    monkeypatch.setattr(dnsprobe, "_udp_query", fake_udp)
    res = dnsprobe.direct_lookup("api.openai.com", ["192.168.0.1"])
    assert res.ips == ["172.66.0.243", "162.159.140.245"]
    assert res.ttl == 42 and res.server == "192.168.0.1" and res.error is None
    assert res.ms is not None and res.ms >= 0


def test_direct_lookup_tries_second_server_after_timeout(monkeypatch):
    calls = []

    def fake_udp(query, server, timeout):
        calls.append(server)
        if server == "192.168.0.1":
            raise dns.exception.Timeout
        return _answer(query, ("example.com.", 60, "IN", "A", "203.0.113.5"))

    monkeypatch.setattr(dnsprobe, "_udp_query", fake_udp)
    res = dnsprobe.direct_lookup("example.com", ["192.168.0.1", "1.1.1.1"])
    assert calls == ["192.168.0.1", "1.1.1.1"]
    assert res.ips == ["203.0.113.5"] and res.server == "1.1.1.1"


def test_direct_lookup_nxdomain_and_all_timeouts(monkeypatch):
    monkeypatch.setattr(
        dnsprobe, "_udp_query", lambda q, s, timeout: _answer(q, rcode=dns.rcode.NXDOMAIN)
    )
    assert dnsprobe.direct_lookup("nope.invalid", ["192.168.0.1"]).error == "dns_nxdomain"

    def timeout(q, s, timeout):
        raise dns.exception.Timeout

    monkeypatch.setattr(dnsprobe, "_udp_query", timeout)
    assert dnsprobe.direct_lookup("x.com", ["192.168.0.1"]).error == "dns_timeout"
    assert dnsprobe.direct_lookup("x.com", []).error == "no_upstream_resolver"


def test_system_lookup(monkeypatch):
    import socket

    monkeypatch.setattr(
        dnsprobe,
        "_getaddrinfo",
        lambda *a: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 443)),
        ],
    )
    assert dnsprobe.system_lookup("example.com").ips == ["203.0.113.1"]

    def fail(*a):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(dnsprobe, "_getaddrinfo", fail)
    assert dnsprobe.system_lookup("example.com").error.startswith("dns_failure")


# ----------------------------------------------------------------- context


PING = """PING 192.168.0.1 (192.168.0.1) 56(84) bytes of data.
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=4.01 ms
64 bytes from 192.168.0.1: icmp_seq=2 ttl=64 time=2.41 ms
64 bytes from 192.168.0.1: icmp_seq=3 ttl=64 time=2.84 ms

--- 192.168.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 803ms
rtt min/avg/max/mdev = 2.408/3.087/4.013/0.611 ms
"""


def test_parse_ping():
    assert context.parse_ping(PING) == {
        "router_rtt_ms": 2.84,
        "router_rtt_mdev_ms": 0.611,
        "router_loss_pct": 0.0,
    }
    assert context.parse_ping("") == {
        "router_rtt_ms": None,
        "router_rtt_mdev_ms": None,
        "router_loss_pct": None,
    }


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (("wifi", "wlp61s0", "Home", "no (guessed)", "iwlwifi", []), "wifi"),
        (("wifi", "wlp61s0", "Pixel 8", "yes (guessed)", "iwlwifi", []), "hotspot"),
        (("wifi", "wlp61s0", "MyPhone", "no", "iwlwifi", ["myphone"]), "hotspot"),
        (("ethernet", "enx0a", "Wired", "no", "rndis_host", []), "usb-tether"),
        (("ethernet", "enp0s31f6", "Wired", "no", "e1000e", []), "ethernet"),
        (("wireguard", "proton0", "ProtonVPN", "no", None, []), "vpn"),
        ((None, "tun0", None, None, None, []), "vpn"),
        ((None, None, None, None, None, []), "none"),
    ],
)
def test_classify_connection(args, expected):
    assert context.classify_connection(*args) == expected


def test_nmcli_escaped_colons():
    assert context.parse_nmcli_fields(r"*:63:2432 MHz:270 Mbit/s:AA\:BB") == [
        "*",
        "63",
        "2432 MHz",
        "270 Mbit/s",
        "AA:BB",
    ]


def test_wifi_info(monkeypatch):
    monkeypatch.setattr(context, "wifi_dbm", lambda iface: -55.0)
    monkeypatch.setattr(
        util,
        "run_cmd",
        lambda args, timeout=30: util.CmdResult(
            0, "  :40:5180 MHz:540 Mbit/s\n*:63:2432 MHz:270 Mbit/s\n", ""
        ),
    )
    info = context.wifi_info("wlp61s0")
    assert info == {
        "wifi_signal_pct": 63,
        "wifi_freq_mhz": 2432,
        "wifi_band": "2.4GHz",
        "wifi_bitrate_mbps": 270.0,
        "wifi_dbm": -55.0,
    }


def test_wifi_dbm_reads_proc(tmp_path):
    wireless = tmp_path / "wireless"
    wireless.write_text("x\ny\nwlp61s0: 0000   55.  -61.  -256 0 0 0 2 1040 0\n")
    assert context.wifi_dbm("wlp61s0", wireless) == -61.0
    assert context.wifi_dbm("eth0", wireless) is None


def test_egress_route(monkeypatch):
    monkeypatch.setattr(
        util,
        "run_cmd",
        lambda args, timeout=30: util.CmdResult(
            0,
            '[{"dst":"1.1.1.1","gateway":"192.168.0.1","dev":"wlp61s0","prefsrc":"192.168.1.50"}]',
            "",
        ),
    )
    assert context.egress_route() == ("192.168.0.1", "wlp61s0")


def test_on_ac_power(tmp_path):
    for name, typ, online in (("AC", "Mains", "1"), ("BAT0", "Battery", "0")):
        d = tmp_path / name
        d.mkdir()
        (d / "type").write_text(typ)
        (d / "online").write_text(online)
    assert context.on_ac_power(tmp_path) is True
    (tmp_path / "AC" / "online").write_text("0")
    assert context.on_ac_power(tmp_path) is False


TRACE = "fl=12f1\nh=1.1.1.1\nip=198.51.100.77\nts=1.0\ncolo=MBA\nloc=KE\ntls=TLSv1.3\n"


def test_public_info_uses_ripestat_and_never_stores_ip(monkeypatch):
    def fake_get(url, timeout=10):
        if "cdn-cgi/trace" in url:
            return TRACE
        assert "198.51.100.77" in url  # the IP is only sent to RIPEstat to look up the ASN
        holder = "Tawala Networks Limited - Tawala Networks Limited"
        return json.dumps({"status": "ok", "data": {"asns": [{"asn": 329367, "holder": holder}]}})

    monkeypatch.setattr(context, "_http_get_text", fake_get)
    info = context.lookup_public_info()
    assert (info.asn, info.as_name, info.source, info.cf_colo) == (
        329367,
        "Tawala Networks Limited",
        "ripestat",
        "MBA",
    )
    assert "198.51.100.77" not in repr(info)
    ctx = context.NetContext(public=info)
    row = ctx.to_row()
    assert "198.51.100.77" not in str(row.values())
    assert "public_ip" not in row and "gateway" not in row


def test_public_info_falls_back_to_cymru(monkeypatch):
    def fake_get(url, timeout=10):
        if "cdn-cgi/trace" in url:
            return TRACE
        raise OSError("ripestat down")

    txt = {
        "77.100.51.198.origin.asn.cymru.com": "329367 | 198.51.100.0/24 | KE | afrinic "
        "| 2020-01-01",
        "AS329367.asn.cymru.com": (
            "329367 | KE | afrinic | 2020-01-01 | "
            "Tawala Networks Limited - Tawala Networks Limited, KE"
        ),
    }
    monkeypatch.setattr(context, "_http_get_text", fake_get)
    monkeypatch.setattr(context, "_cymru_txt", txt.get)
    info = context.lookup_public_info()
    assert info.asn == 329367 and info.source == "cymru"
    assert info.as_name == "Tawala Networks Limited"  # same spelling as RIPEstat


def test_as_names_are_normalised():
    assert context.clean_as_name("Tawala Networks Limited - Tawala Networks Limited, KE") == (
        "Tawala Networks Limited"
    )
    assert context.clean_as_name("Tawala Networks Limited - Tawala Networks Limited") == (
        "Tawala Networks Limited"
    )
    assert context.clean_as_name("TAWALA-AS, KE") == "TAWALA-AS"
    assert context.clean_as_name(None) is None


def test_public_info_offline(monkeypatch):
    def offline(url, timeout=10):
        raise OSError("Network is unreachable")

    monkeypatch.setattr(context, "_http_get_text", offline)
    info = context.lookup_public_info()
    assert info.asn is None and info.error.startswith("public_ip_failed")
