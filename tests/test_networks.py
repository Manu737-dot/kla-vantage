"""Network fingerprints, VPN detection, labels and mid-run changes. No real network."""

import sqlite3
from datetime import datetime, timedelta

import pytest

from kla import analyze, cli, context, db, netcheck, networks, probe, status, util
from tests.conftest import net_context
from tests.test_pipeline import _fake_dns, _synthetic_db

MAC_TAWALA = "02:00:00:5e:00:41"  # made up (locally administered)
MAC_5G = "02:00:00:5e:00:42"


def eat(text: str) -> datetime:
    return networks.parse_eat(f"2026-10-22 {text}")


def fake_cmds(monkeypatch, answers):
    """run_cmd that answers by the first words of the command."""

    def run(args, timeout=30):
        for prefix, (code, out) in answers.items():
            if " ".join(args).startswith(prefix):
                return util.CmdResult(code, out, "")
        return util.CmdResult(127, "", "not faked")

    monkeypatch.setattr(util, "run_cmd", run)


# ------------------------------------------------------------ detection


@pytest.mark.parametrize(
    ("iface", "nm_type", "tunnel", "expected"),
    [
        ("CloudflareWARP", None, False, "vpn"),  # the 18:31 case: name not known before
        ("utun9", None, True, "vpn"),  # any tun/WireGuard device, whatever its name
        ("wlp61s0", "wifi", False, "wifi"),
    ],
)
def test_warp_and_tunnels_count_as_vpn(iface, nm_type, tunnel, expected):
    args = (nm_type, iface, None, None, None, [])
    assert context.classify_connection(*args, tunnel=tunnel) == expected


def test_is_tunnel_reads_sysfs(tmp_path):
    for name, files in {
        "tun0": {"tun_flags": "0x1001", "type": "65534"},
        "wg0": {"type": "65534"},
        "wlp61s0": {"type": "1"},
    }.items():
        (tmp_path / name).mkdir()
        for f, v in files.items():
            (tmp_path / name / f).write_text(v)
    assert context.is_tunnel("tun0", tmp_path) and context.is_tunnel("wg0", tmp_path)
    assert not context.is_tunnel("wlp61s0", tmp_path)
    assert not context.is_tunnel("missing", tmp_path) and not context.is_tunnel(None, tmp_path)


def test_warp_status(monkeypatch):
    fake_cmds(monkeypatch, {"warp-cli": (0, "Status update: Connected\nNetwork: healthy\n")})
    assert context.warp_status() == "connected"
    fake_cmds(monkeypatch, {"warp-cli": (0, "Status update: Disconnected\nReason: Manual\n")})
    assert context.warp_status() == "disconnected"
    fake_cmds(monkeypatch, {})  # not installed
    assert context.warp_status() is None


def test_vpn_kind(tmp_path):
    assert context.vpn_kind("wlp61s0", "connected", tmp_path) == "cloudflare-warp"
    assert context.vpn_kind("CloudflareWARP", None, tmp_path) == "cloudflare-warp"
    assert context.vpn_kind("proton0", "disconnected", tmp_path) == "tunnel:proton0"
    assert context.vpn_kind("wlp61s0", "disconnected", tmp_path) is None
    assert context.vpn_kind(None, None, tmp_path) is None


ROUTES = (
    '[{"dst":"default","gateway":"10.2.0.1","dev":"proton0","metric":50},'
    '{"dst":"default","gateway":"192.168.0.1","dev":"wlp61s0","metric":600},'
    '{"dst":"default","gateway":"192.168.8.1","dev":"enx0a","metric":700}]'
)


def test_check_network_sees_router_under_warp(monkeypatch):
    fake_cmds(
        monkeypatch,
        {
            "ip -j route get": (0, '[{"dst":"1.1.1.1","dev":"CloudflareWARP"}]'),
            "ip -j route show default": (0, ROUTES),
            "ip -j neigh show 192.168.0.1": (
                0,
                f'[{{"dst":"192.168.0.1","lladdr":"{MAC_TAWALA.upper()}","state":["STALE"]}}]',
            ),
            "warp-cli": (0, "Status update: Connected\n"),
        },
    )
    check = context.check_network()
    assert (check.egress_iface, check.router_ip, check.router_iface) == (
        "CloudflareWARP",
        "192.168.0.1",
        "wlp61s0",
    )
    assert check.router_mac == MAC_TAWALA and check.vpn_kind == "cloudflare-warp"
    assert MAC_TAWALA not in repr(check)  # never printed or logged by accident


def test_router_mac_pings_once_when_neighbour_table_is_empty(monkeypatch):
    calls = []

    def run(args, timeout=30):
        calls.append(args[0])
        if args[:2] == ["ip", "-j"]:
            seen = calls.count("ping") > 0
            body = f'[{{"lladdr":"{MAC_5G}"}}]' if seen else "[]"
            return util.CmdResult(0, body, "")
        return util.CmdResult(0, "", "")

    monkeypatch.setattr(util, "run_cmd", run)
    assert context.router_mac("192.168.150.1", "wlp61s0") == MAC_5G
    assert calls == ["ip", "ping", "ip"]


def test_check_network_offline_is_empty_not_an_error():
    check = context.check_network()  # every command is blocked in tests
    assert check.router_ip is None and check.router_mac is None and not check.vpn_active


def test_run_row_keeps_new_fields_out_of_runs_table():
    ctx = net_context()
    ctx.warp_cli = "connected"
    ctx.start_check = context.NetCheck(ts=util.utc_now(), router_mac=MAC_TAWALA)
    row = ctx.to_row()
    assert not {"warp_cli", "start_check", "gateway"} & set(row)


# ----------------------------------------------------------- fingerprint


def test_salt_is_private_and_stable(tmp_path):
    db_path = tmp_path / "data" / "kla.sqlite3"
    salt = netcheck.load_salt(db_path)
    assert netcheck.load_salt(db_path) == salt and len(salt) == 32
    assert netcheck.salt_path(db_path).stat().st_mode & 0o777 == 0o600


def test_fingerprint_hides_the_mac_and_separates_routers():
    def check(mac, ip="192.168.0.1"):
        return context.NetCheck(
            ts=util.utc_now(), router_ip=ip, router_iface="wlp61s0", router_mac=mac
        )

    a, src = netcheck.fingerprint(check(MAC_TAWALA), "s1")
    assert src == "mac" and len(a) == 12
    assert netcheck.fingerprint(check(MAC_TAWALA), "s1")[0] == a  # stable
    assert netcheck.fingerprint(check(MAC_5G), "s1")[0] != a  # another router
    # Same address on two routers (common: 192.168.1.1) still gives two networks.
    assert netcheck.fingerprint(check(MAC_5G, "192.168.0.1"), "s1")[0] != a
    assert netcheck.fingerprint(check(MAC_TAWALA), "s2")[0] != a  # salt matters
    assert netcheck.fingerprint(check(None), "s1")[1] == "gateway"
    row = netcheck.to_row(check(MAC_TAWALA), "start", "s1")
    assert MAC_TAWALA not in str(row) and row["router_ip"] == "192.168.0.1"
    # A public gateway address would identify the connection, so it is not kept.
    assert netcheck.to_row(check(MAC_TAWALA, "41.80.0.1"), "start", "s1")["router_ip"] is None


def _check_row(fp="aaa", vpn=0, iface="wlp61s0"):
    return {"router_fp": fp, "vpn_active": vpn, "egress_iface": iface}


def test_changes_between_start_and_end():
    assert netcheck.changes(_check_row(), _check_row()) == []
    assert netcheck.changes(_check_row(), _check_row(fp="bbb")) == ["router changed"]
    assert netcheck.changes(_check_row(), _check_row(vpn=1, iface="CloudflareWARP")) == [
        "VPN turned on"
    ]
    assert netcheck.changes(_check_row(vpn=1), _check_row()) == ["VPN turned off"]
    assert netcheck.changes(_check_row(), _check_row(iface="enp0s31f6")) == [
        "interface changed (wlp61s0 → enp0s31f6)"
    ]
    # Wi-Fi gone at the end (an outage) is not a change of network: the run stays in.
    assert netcheck.changes(_check_row(), _check_row(fp=None, iface=None)) == []


def test_probe_run_flags_warp_turning_on_mid_run(cfg, fake_curl, monkeypatch, capsys):
    _fake_dns(monkeypatch)
    ctx = net_context()
    ctx.start_check = context.NetCheck(
        ts=util.utc_now(),
        egress_iface="wlp61s0",
        router_iface="wlp61s0",
        router_ip="192.168.0.1",
        router_mac=MAC_TAWALA,
    )
    monkeypatch.setattr(context, "gather", lambda c, **k: ctx)
    end = context.NetCheck(
        ts=util.utc_now(),
        egress_iface="CloudflareWARP",
        router_iface="wlp61s0",
        router_ip="192.168.0.1",
        router_mac=MAC_TAWALA,
        vpn_kind="cloudflare-warp",
        warp_cli="connected",
    )
    monkeypatch.setattr(context, "check_network", lambda: end)
    fake_curl()
    result = probe.run_probe(cfg)
    assert result["changed"] == ["VPN turned on"]
    assert "network changed mid-run (VPN turned on)" in capsys.readouterr().out

    conn = db.connect(cfg.db_path)
    rows = db.fetch(conn, "SELECT * FROM net_checks ORDER BY id")
    assert [r["phase"] for r in rows] == ["start", "end"]
    assert {r["run_id"] for r in rows} == {result["run_id"]}
    assert rows[0]["router_fp"] == rows[1]["router_fp"] and rows[0]["fp_source"] == "mac"
    assert (rows[0]["vpn_active"], rows[1]["vpn_active"]) == (0, 1)
    assert rows[1]["vpn_kind"] == "cloudflare-warp"
    assert MAC_TAWALA not in "\n".join(conn.iterdump())
    # The run row itself is unchanged by this feature (it still says "no VPN at start").
    run = db.fetch(conn, "SELECT vpn_active FROM runs")[0]
    assert run["vpn_active"] == 0
    nets = networks.assign(*networks.load_all(conn))
    assert nets[result["run_id"]].mixed and nets[result["run_id"]].vpn
    networks.add_label(conn, "Tawala", router_fp=rows[0]["router_fp"])
    for table in ("net_checks", "net_labels"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(f"DELETE FROM {table}")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE net_checks SET vpn_active = 0")


# ------------------------------------------------------------ networks


def _add_run(conn, rid, start, end=None, kind="probe", dns=None, asn=None, as_name=None, vpn=0):
    db.insert(
        conn,
        "runs",
        {
            "run_id": rid,
            "kind": kind,
            "started_utc": util.iso(start),
            "started_eat": util.iso(util.to_eat(start)),
            "finished_utc": util.iso(end or start + timedelta(seconds=30)),
            "hour_eat": util.to_eat(start).hour,
            "weekday_eat": 3,
            "tool_version": "t",
            "dns_servers": dns,
            "asn": asn,
            "as_name": as_name,
            "vpn_active": vpn,
        },
    )


TAWALA = {"dns": "192.168.0.1", "asn": 329367, "as_name": "Tawala Networks Limited"}
FIVE_G = {"dns": "192.168.150.1,2001:4860:4860::8888", "asn": 33771, "as_name": "Safaricom"}


def _today(conn):
    """Today's events: Tawala, Wi-Fi gone 10:06-11:10 (5G), outage, switch at 18:31."""
    with conn:
        _add_run(conn, "p0945", eat("09:45"), **TAWALA)
        _add_run(conn, "p1000", eat("10:00"), **TAWALA)
        _add_run(conn, "t1004", eat("10:04"), eat("10:08"), kind="trace")  # crossed 10:06
        _add_run(conn, "p1015", eat("10:15"), dns=FIVE_G["dns"])  # ASN lookup failed
        _add_run(conn, "p1030", eat("10:30"), **FIVE_G)
        _add_run(conn, "t1100", eat("11:00"), eat("11:04"), kind="trace")
        _add_run(conn, "p1101", eat("11:01"), dns=FIVE_G["dns"])
        _add_run(conn, "p1115", eat("11:15"), **TAWALA)
        _add_run(conn, "p1630", eat("16:30"), dns="192.168.0.1")  # outage: no ASN
        _add_run(conn, "p1831", eat("18:31:18"), eat("18:34:05"), dns="192.168.0.1")
        # First run with fingerprints, back on Tawala.
        _add_run(conn, "p1915", eat("19:15"), **TAWALA)
        for phase in ("start", "end"):
            db.insert(
                conn,
                "net_checks",
                {
                    "run_id": "p1915",
                    "phase": phase,
                    "ts_utc": util.iso(eat("19:15")),
                    "egress_iface": "wlp61s0",
                    "router_ip": "192.168.0.1",
                    "router_fp": "a1b2c3aaaaaa",
                    "fp_source": "mac",
                    "vpn_active": 0,
                },
            )
    networks.add_label(conn, "Safaricom 5G", start=eat("10:06"), end=eat("11:10"))
    networks.add_label(
        conn, "Safaricom 5G", start=eat("18:31:32"), end=eat("18:40:48"), note="switched"
    )


def test_todays_networks(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    _today(conn)
    nets = networks.assign(*networks.load_all(conn))
    tawala = "router a1b2c3"  # old runs joined the fingerprinted router by its address
    for rid in ("p0945", "p1000", "p1115", "p1630", "p1915"):
        assert nets[rid].network == tawala and not nets[rid].mixed, rid
    assert nets["p1630"].how == "router address (before fingerprints)"
    for rid in ("p1015", "p1030", "t1100", "p1101"):
        assert nets[rid].network == "Safaricom 5G" and not nets[rid].mixed, rid
    # Runs that crossed a switch are flagged, with the reason.
    for rid in ("t1004", "p1831"):
        assert nets[rid].changed == [f"network changed: {tawala} → Safaricom 5G"], rid

    with conn:  # an old run with the raw RIPEstat spelling of the same ISP
        _add_run(
            conn,
            "old",
            eat("09:30"),
            dns="192.168.0.1",
            asn=329367,
            as_name="Tawala Networks Limited - Tawala Networks Limited",
        )
    with conn:  # a WARP run on the same router: its ISP is Cloudflare, not the router's
        _add_run(
            conn, "warp", eat("19:30"), dns="192.168.0.1", asn=13335, as_name="CLOUDFLARENET", vpn=1
        )
    nets = networks.assign(*networks.load_all(conn))
    assert networks.isp_names(db.fetch(conn, "SELECT * FROM runs"), nets) == {
        tawala: "AS329367 Tawala Networks Limited",
        "Safaricom 5G": "AS33771 Safaricom",
    }
    networks.add_label(conn, "Tawala", router_fp="a1b2c3aaaaaa")
    nets = networks.assign(*networks.load_all(conn))
    assert {nets[r].network for r in ("p0945", "p1630", "p1915")} == {"Tawala"}
    assert nets["p1915"].how == "label (router)"


def test_trace_runs_borrow_the_nearest_probe_address():
    runs = [
        {
            "run_id": "p",
            "kind": "probe",
            "started_utc": util.iso(eat("10:00")),
            "dns_servers": "192.168.0.1",
        },
        {
            "run_id": "t",
            "kind": "trace",
            "started_utc": util.iso(eat("10:04")),
            "dns_servers": None,
        },
        {
            "run_id": "far",
            "kind": "trace",
            "started_utc": util.iso(eat("13:00")),
            "dns_servers": None,
        },
    ]
    out = networks._legacy_addresses(runs, set())
    assert out == {"p": "192.168.0.1", "t": "192.168.0.1", "far": None}


def test_same_address_on_two_routers_is_not_guessed(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    _today(conn)
    with conn:
        _add_run(conn, "fibre", eat("20:00"), dns="192.168.0.1")
        db.insert(
            conn,
            "net_checks",
            {
                "run_id": "fibre",
                "phase": "start",
                "ts_utc": util.iso(eat("20:00")),
                "router_ip": "192.168.0.1",
                "router_fp": "ffff00000000",
                "vpn_active": 0,
            },
        )
    nets = networks.assign(*networks.load_all(conn))
    assert nets["p0945"].network == "router 192.168.0.1"
    assert nets["fibre"].network == "router ffff00"


def test_newest_label_wins_and_clear_falls_back(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    _today(conn)
    networks.add_label(conn, "Phone hotspot", start=eat("10:20"), end=eat("10:40"))
    nets = networks.assign(*networks.load_all(conn))
    assert nets["p1030"].network == "Phone hotspot" and nets["p1015"].network == "Safaricom 5G"
    # --clear means "no manual name in this period": back to the router's own name.
    networks.add_label(conn, None, start=eat("10:20"), end=eat("10:40"))
    nets = networks.assign(*networks.load_all(conn))
    assert nets["p1030"].network == "router 192.168.150.1"
    assert nets["p1015"].network == "Safaricom 5G"
    assert conn.execute("SELECT COUNT(*) FROM net_labels").fetchone()[0] == 4  # nothing edited


def test_add_label_rejects_bad_input(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    with pytest.raises(ValueError):
        networks.add_label(conn, "x")
    with pytest.raises(ValueError):
        networks.add_label(conn, "x", start=eat("11:00"), end=eat("10:00"))
    # The database itself refuses a label that names neither a router nor a period.
    with pytest.raises(sqlite3.IntegrityError), conn:
        db.insert(conn, "net_labels", {"created_utc": "x", "label": "x"})


def test_legacy_address_and_match():
    assert networks.legacy_address("192.168.150.1,2001:4860:4860::8888") == "192.168.150.1"
    assert networks.legacy_address("127.0.0.53") is None
    assert networks.legacy_address(None) is None
    names = ["Tawala", "Safaricom 5G", "Safaricom Fibre"]
    assert networks.match("tawala", names) == "Tawala"
    assert networks.match("safaricom 5", names) == "Safaricom 5G"
    assert networks.match("safaricom", names) is None  # ambiguous


# ------------------------------------------------------------- analysis


def _two_networks(cfg):
    _synthetic_db(cfg)
    conn = db.connect(cfg.db_path)
    first = util.parse_iso(conn.execute("SELECT MIN(started_utc) FROM runs").fetchone()[0])
    mid = first + timedelta(days=1)
    networks.add_label(conn, "Net A", start=first - timedelta(hours=1), end=mid)
    networks.add_label(conn, "Net B", start=mid, end=first + timedelta(days=3))
    with conn:  # run0 switched routers while it ran
        for phase, fp in (("start", "aaaaaaaaaaaa"), ("end", "bbbbbbbbbbbb")):
            db.insert(
                conn,
                "net_checks",
                {
                    "run_id": "run0",
                    "phase": phase,
                    "ts_utc": util.iso(first),
                    "router_fp": fp,
                    "vpn_active": 0,
                    "egress_iface": "wlp61s0",
                },
            )
    conn.close()


def test_select_leaves_out_mixed_and_vpn_runs(cfg):
    _two_networks(cfg)
    raw = analyze.load(cfg, None)
    default = analyze.select(raw)
    assert all(p["run_id"] != "run0" for p in default["probes"])
    assert any(p["run_id"] == "run0" for p in analyze.select(raw, include_mixed=True)["probes"])
    only_a = analyze.select(raw, network="Net A")
    assert {p["network"] for p in only_a["probes"]} == {"Net A"}
    assert analyze.available_networks(default) == ["Net A", "Net B"]


def test_report_compares_networks_and_can_focus_on_one(cfg):
    _two_networks(cfg)
    text = analyze.run(cfg, echo=lambda s: None).read_text()
    assert "## Networks" in text and "Same targets, different networks" in text
    assert "| target | Net A | Net B |" in text
    assert "This report combines 2 networks" in text
    assert "router changed" in text  # run0 is listed as left out
    assert "### Net A" in text  # near/far switches checked inside each network
    one = analyze.run(cfg, network="net a", out_dir=cfg.root / "a", echo=lambda s: None)
    one_text = one.read_text()
    assert one_text.startswith("# kenya-llm-latency report: Net A")
    assert "Probe runs on other networks:" in one_text
    with pytest.raises(ValueError, match="Net A, Net B"):
        analyze.run(cfg, network="nope", echo=lambda s: None)


def test_cli_label_networks_and_each_network(cfg, capsys):
    cfg_path = str(cfg.root / "config" / "config.yaml")
    _two_networks(cfg)
    args = ["--config", cfg_path]
    assert (
        cli.main(
            [
                *args,
                "label",
                "Safaricom 5G",
                "--from",
                "2026-10-22 10:06",
                "--to",
                "2026-10-22 11:10",
            ]
        )
        == 0
    )
    conn = db.connect(cfg.db_path)
    row = db.fetch(conn, "SELECT * FROM net_labels ORDER BY id DESC LIMIT 1")[0]
    assert (row["from_utc"], row["to_utc"]) == (
        "2026-10-22T10:06:00.000+03:00",
        "2026-10-22T11:10:00.000+03:00",
    )
    assert cli.main([*args, "label", "Tawala", "--router", "bbbb"]) == 0
    assert (
        db.fetch(conn, "SELECT router_fp FROM net_labels ORDER BY id DESC LIMIT 1")[0]["router_fp"]
        == "bbbbbbbbbbbb"
    )
    capsys.readouterr()
    assert cli.main([*args, "label"]) == 2  # no name and no --clear
    assert cli.main([*args, "label", "X"]) == 2  # no router reachable in tests
    assert "no router found" in capsys.readouterr().err
    assert cli.main([*args, "networks"]) == 0
    out = capsys.readouterr().out
    assert "| Net A |" in out and '"Safaricom 5G": period 22 Oct 10:06' in out
    assert "router changed" in out
    assert cli.main([*args, "analyze", "--each-network"]) == 0
    for slug in ("net-a", "net-b"):
        assert (cfg.root / "reports" / "networks" / slug / "report.md").exists()
    assert cli.main([*args, "analyze", "--network", "nope"]) == 2


def test_status_warns_loudly_about_vpn():
    on = context.NetCheck(
        ts=util.utc_now(), egress_iface="CloudflareWARP", vpn_kind="cloudflare-warp"
    )
    banner = "\n".join(status.vpn_banner(on))
    assert "VPN IS ON NOW: Cloudflare WARP" in banner and "warp-cli disconnect" in banner
    assert banner.startswith("!!!!")
    off = context.NetCheck(ts=util.utc_now(), egress_iface="wlp61s0")
    assert status.vpn_banner(off) == []
    assert "3 run(s) in the last 24 h" in "\n".join(status.vpn_banner(off, 3))
