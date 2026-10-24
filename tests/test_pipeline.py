"""End-to-end: probe run -> DB -> analysis / experiments / export / CLI, all with fakes."""

import json
import random
import sqlite3
from datetime import timedelta

import pytest
import yaml

import kla
from kla import analyze, cli, context, db, dnsprobe, experiments, export, probe, systemd, util
from kla.config import ConfigError, load_config
from tests.conftest import net_context

PUBLIC_IP = "198.51.100.77"


def _fake_dns(monkeypatch):
    monkeypatch.setattr(
        dnsprobe,
        "direct_lookup",
        lambda host, servers, timeout_s=5: dnsprobe.DnsResult(
            ms=25.0, ips=["203.0.113.10"], ttl=60, server="192.168.0.1"
        ),
    )
    monkeypatch.setattr(
        dnsprobe,
        "system_lookup",
        lambda host: dnsprobe.DnsResult(ms=0.4, ips=["203.0.113.10"], server="system"),
    )
    monkeypatch.setattr(dnsprobe, "upstream_servers", lambda setting="auto": ["192.168.0.1"])


def test_real_config_is_valid():
    cfg = load_config()
    groups = [t.group for t in cfg.targets]
    assert groups.count("llm") == 9 and groups.count("cloud") == 9 and groups.count("local") >= 2
    assert all(t.source for t in cfg.targets)
    for provider in ("AWS", "Azure", "Google Cloud"):
        geos = sorted(t.geo for t in cfg.targets if t.provider == provider)
        assert geos == ["africa", "europe", "us"]
    later = {t.id: t for t in cfg.targets if t.group == "ai-cloud"}
    assert sorted(later) == ["aws-bedrock-af-south-1", "azure-ai-southafricanorth", "cf-workers-ai"]
    assert all(t.added == "2026-10-23" and t.source.startswith("https://") for t in later.values())
    assert [t.id for t in cfg.targets if t.added] == list(later)  # only the new ones


def test_added_date_must_be_a_date(cfg, tmp_path):
    raw = yaml.safe_load(cfg.root.joinpath("config", "config.yaml").read_text())
    raw["targets"][0]["added"] = "23 Oct"
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError, match="added must be a date"):
        load_config(path)


def test_probe_run_end_to_end(cfg, fake_curl, monkeypatch, capsys):
    _fake_dns(monkeypatch)
    monkeypatch.setattr(context, "gather", lambda c, **k: net_context(PUBLIC_IP))
    fake_curl(status=401, chunks=[f'{{"msg":"hello {PUBLIC_IP}"}}'.encode()])
    result = probe.run_probe(cfg)
    assert len(result["rows"]) == len(cfg.targets)
    assert "Tawala" in capsys.readouterr().out

    conn = sqlite3.connect(cfg.db_path)
    rows = conn.execute(
        "SELECT target_id, ok, dns_direct_ms, tcp_ms, tls_ms, total_ms, edge_pop, "
        "http_version FROM probes"
    ).fetchall()
    assert len(rows) == len(cfg.targets)
    by_id = {r[0]: r for r in rows}
    assert by_id["openai"][1] == 1 and by_id["openai"][6] == "MBA" and by_id["openai"][7] == "2"
    assert by_id["openai"][2] == 25.0  # DNS measured directly
    # total = direct DNS + curl total (401 ms)
    assert by_id["openai"][5] == 25.0 + 401.0
    assert by_id["local-cloudflare"][2] is None  # IP literal: no DNS step
    # The public IP must not appear anywhere in the database.
    dump = "\n".join(conn.iterdump())
    assert PUBLIC_IP not in dump


def test_probe_records_dns_failure_without_request(cfg, fake_curl, monkeypatch):
    monkeypatch.setattr(
        dnsprobe, "direct_lookup", lambda *a, **k: dnsprobe.DnsResult(error="dns_timeout")
    )
    monkeypatch.setattr(
        dnsprobe, "system_lookup", lambda h: dnsprobe.DnsResult(error="dns_failure: x")
    )
    made = fake_curl()
    row = probe.probe_target(cfg.targets[0], cfg, ["192.168.0.1"])
    assert row["ok"] == 0 and row["error_type"] == "dns_failure" and made == []


def _synthetic_db(cfg):
    """A few days of fake data across hours, two connection types, traces and AI calls."""
    rng = random.Random(7)
    conn = db.connect(cfg.db_path)
    start = util.utc_now() - timedelta(days=2)
    with conn:
        for i in range(0, 2 * 24 * 4, 3):
            t = start + timedelta(minutes=15 * i)
            eat = util.to_eat(t)
            conn_type = "hotspot" if i % 7 == 0 else "wifi"
            run_id = f"run{i}"
            db.insert(
                conn,
                "runs",
                {
                    "run_id": run_id,
                    "kind": "probe",
                    "started_utc": util.iso(t),
                    "started_eat": util.iso(eat),
                    "finished_utc": util.iso(t),
                    "hour_eat": eat.hour,
                    "weekday_eat": eat.weekday(),
                    "tool_version": "t",
                    "asn": 329367,
                    "as_name": "Tawala",
                    "conn_type": conn_type,
                    "router_rtt_ms": rng.uniform(2, 9),
                    "vpn_active": 0,
                },
            )
            evening = 1.6 if 19 <= eat.hour <= 23 else 1.0
            for target in cfg.targets:
                base = {
                    "llm": 250,
                    "cloud": {"africa": 70, "europe": 180, "us": 230}.get(target.geo, 200),
                    "local": 12,
                    "ai-cloud": 70,
                }[target.group]
                tcp = base * evening * rng.uniform(0.9, 1.3)
                failed = rng.random() < 0.03
                db.insert(
                    conn,
                    "probes",
                    {
                        "run_id": run_id,
                        "ts_utc": util.iso(t),
                        "target_id": target.id,
                        "host": target.host,
                        "grp": target.group,
                        "provider": target.provider,
                        "region": target.region,
                        "geo": target.geo,
                        "dns_direct_ms": rng.uniform(5, 300),
                        "dns_system_ms": 0.3,
                        "tcp_ms": tcp,
                        "tls_ms": 2 * tcp,
                        "ttfb_ms": tcp * 1.2,
                        "transfer_ms": 1.0,
                        "total_ms": None if failed else 4.2 * tcp + 30,
                        "http_status": None if failed else 401,
                        "http_version": "2",
                        "tls_version": "TLSv1.3",
                        "edge_pop": "MBA" if target.group == "llm" else None,
                        "edge_source": "cloudflare",
                        "server_header": "cloudflare",
                        "ok": int(not failed),
                        "error_type": "timeout_tls" if failed else None,
                    },
                )
                blocked = target.id == "azure-westeurope"
                db.insert(
                    conn,
                    "pings",
                    {
                        "run_id": run_id,
                        "ts_utc": util.iso(t),
                        "target_id": target.id,
                        "ip": "203.0.113.10",
                        "status": "no_reply" if blocked else "ok",
                        "sent": 3,
                        "received": 0 if blocked else 3,
                        "rtt_median_ms": None if blocked else 11.0,
                    },
                )
        db.insert(
            conn,
            "runs",
            {
                "run_id": "tr",
                "kind": "trace",
                "started_utc": util.iso(start),
                "started_eat": util.iso(start),
                "finished_utc": util.iso(start),
                "hour_eat": 1,
                "weekday_eat": 1,
                "tool_version": "t",
            },
        )
        db.insert(
            conn,
            "traces",
            {
                "run_id": "tr",
                "ts_utc": util.iso(start),
                "target_id": "openai",
                "host": "api.openai.com",
                "ok": 1,
                "hop_count": 12,
                "reached": 1,
                "dest_rtt_ms": 11.0,
                "biggest_jump_ms": 6.0,
                "biggest_jump_from": "hop 7 ae-1.cr-01-nbo [Nairobi, KE?]",
                "as_path": "AS329367 TAWALA > AS37100 SEACOM > AS13335 CLOUDFLARENET",
                "location_hints": "Nairobi, KE > Mombasa, KE",
                "hops_json": "[]",
            },
        )
        db.insert(
            conn,
            "runs",
            {
                "run_id": "ai1",
                "kind": "ai",
                "started_utc": util.iso(start),
                "started_eat": util.iso(start),
                "finished_utc": util.iso(start),
                "hour_eat": 1,
                "weekday_eat": 1,
                "tool_version": kla.__version__,
                "conn_type": "wifi",
            },
        )
        for k in range(6):
            db.insert(
                conn,
                "ai_calls",
                {
                    "run_id": "ai1",
                    "ts_utc": util.iso(start),
                    "provider": "groq",
                    "model": "openai/gpt-oss-20b",
                    "mode": "stream",
                    "ok": 1,
                    "ttft_visible_ms": 600 + k * 40,
                    "total_ms": 900 + k * 40,
                },
            )
    conn.close()


def test_analyze_writes_report_and_charts(cfg):
    _synthetic_db(cfg)
    report = analyze.run(cfg, echo=lambda s: None)
    text = report.read_text()
    for section in (
        "Likely packet loss",
        "Near/far switches: DNS steering or anycast?",
        "Ping vs real connection",
        "Data coverage",
        "Per target and phase",
        "By hour of day",
        "By connection type",
        "Cloud regions",
        "Routes",
        "AI time to first token",
    ):
        assert section in text
    assert "TCP connect (ms)" in text and "| openai | llm |" in text
    assert "AS37100 SEACOM" in text
    assert "| azure-westeurope |" in text and "0 (blocks ping)" in text
    assert "Ping replies missing, counting only hosts that answer ping: 0 of" in text
    assert "Targets added on 2026-10-23, so no data before then: cf-workers-ai (ai-cloud)" in text
    pngs = sorted(p.name for p in report.parent.glob("*.png"))
    assert pngs == [
        "ai_first_token.png",
        "connection_type.png",
        "distribution_llm.png",
        "hourly_eat.png",
        "phase_breakdown.png",
        "ping_vs_tcp.png",
        "regions.png",
    ]
    assert json.loads((report.parent / "summary.json").read_text())["probe_runs"] > 50


def test_analyze_on_empty_db_does_not_crash(cfg):
    report = analyze.run(cfg, echo=lambda s: None)
    assert "No probe runs yet" in report.read_text()


def test_region_experiment_and_export(cfg):
    _synthetic_db(cfg)
    lines = experiments.region(cfg, echo=lambda s: None)
    table = "\n".join(lines)
    assert "| AWS | af-south-1 | africa |" in table and "| AWS | us-east-1 | us |" in table
    paths = export.export(cfg)
    assert {p.name for p in paths} >= {"runs.csv", "probes.csv", "traces.csv", "ai_calls.csv"}
    header = (cfg.path("export_dir") / "probes.csv").read_text().splitlines()[0]
    assert "tcp_ms" in header


def test_reuse_experiment(cfg, monkeypatch):
    from kla import http
    from tests.conftest import FakeCurl

    monkeypatch.setattr(context, "gather", lambda c, **k: net_context())
    handles = []

    def factory():
        # The first handle created is the kept-alive one: after the warm-up it reports
        # num_connects = 0 (no new connection was needed).
        c = FakeCurl(num_connects=0 if not handles else 1)
        handles.append(c)
        return c

    monkeypatch.setattr(http, "CURL_FACTORY", factory)
    monkeypatch.setattr(experiments.time, "sleep", lambda s: None)
    rows = experiments.reuse(cfg, n=3, target_ids=["openai"], echo=lambda s: None)
    assert [r["arm"] for r in rows] == ["fresh", "reused"] * 3
    assert all(r["reused"] == 1 for r in rows if r["arm"] == "reused")
    assert all(r["tcp_ms"] == 0.0 for r in rows if r["arm"] == "reused")
    md = next((cfg.path("reports_dir") / "experiments").glob("*-reuse.md")).read_text()
    assert "fresh median" in md and "Connection actually reused in 3/3" in md


def test_compare_table_percent_change():
    a = [{"total_ms": v} for v in (100, 200, 300)]
    b = [{"total_ms": v} for v in (50, 100, 150)]
    lines = experiments.compare("fresh", a, "reused", b, [("total_ms", "total")])
    assert "| total (ms) | 200 | 100 | -50% |" in lines[2]


def test_systemd_units(cfg, tmp_path):
    service, timer = systemd.render(cfg, "probe")
    assert f"WorkingDirectory={cfg.root}" in service
    assert "ExecStart=" in service and " probe" in service
    assert "OnCalendar=*:0/15" in timer and "Persistent=true" in timer
    assert "RandomizedDelaySec=90" in timer
    paths = systemd.write_units(cfg, ["probe", "trace"], tmp_path)
    assert sorted(p.name for p in paths) == [
        "kla-probe.service",
        "kla-probe.timer",
        "kla-trace.service",
        "kla-trace.timer",
    ]


def test_cli_start_print_and_status(cfg, capsys, monkeypatch):
    cfg_path = str(cfg.root / "config" / "config.yaml")
    assert cli.main(["--config", cfg_path, "start", "--print"]) == 0
    out = capsys.readouterr().out
    assert "kla-probe.timer" in out and "kla-ai" not in out  # no keys -> no AI timer
    assert cli.main(["--config", cfg_path, "status"]) == 0
    assert "no runs yet" in capsys.readouterr().out


def test_cli_reports_config_errors(tmp_path, capsys):
    bad = tmp_path / "config"
    bad.mkdir()
    (bad / "config.yaml").write_text(
        "targets:\n  - {id: a, url: 'http://x', group: llm, provider: X, geo: us, source: s}\n"
    )
    assert cli.main(["--config", str(bad / "config.yaml"), "status"]) == 2
    assert "https://" in capsys.readouterr().err


PING_OK = """64 bytes from 203.0.113.10: icmp_seq=1 ttl=57 time=12.0 ms
64 bytes from 203.0.113.10: icmp_seq=2 ttl=57 time=11.0 ms
64 bytes from 203.0.113.10: icmp_seq=3 ttl=57 time=10.0 ms

--- 203.0.113.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 402ms
rtt min/avg/max/mdev = 10.000/11.000/12.000/0.816 ms
"""
PING_BLOCKED = """--- 203.0.113.10 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2046ms
"""


def test_probe_run_pings_after_each_probe(cfg, monkeypatch):
    """Order is probe, ping, probe, ping ...; blocked pings are missing, not failures."""
    from kla import http
    from tests.conftest import FakeCurl

    _fake_dns(monkeypatch)
    monkeypatch.setattr(context, "gather", lambda c, **k: net_context(PUBLIC_IP))
    events = []

    def factory():
        events.append("probe")
        return FakeCurl(status=401)

    calls = {"n": 0}

    def run_cmd(args, timeout=30):
        assert args[0] == "ping"
        events.append("ping")
        calls["n"] += 1
        if calls["n"] % 3 == 0:  # every third host "blocks ping"
            return util.CmdResult(1, PING_BLOCKED, "")
        return util.CmdResult(0, PING_OK, "")

    monkeypatch.setattr(http, "CURL_FACTORY", factory)
    monkeypatch.setattr(util, "run_cmd", run_cmd)
    result = probe.run_probe(cfg, echo=lambda s: None)

    n = len(cfg.targets)
    assert events == ["probe", "ping"] * n
    conn = sqlite3.connect(cfg.db_path)
    conn.row_factory = sqlite3.Row
    probes = conn.execute("SELECT * FROM probes ORDER BY seq").fetchall()
    pings = conn.execute("SELECT * FROM pings ORDER BY seq").fetchall()
    assert len(probes) == len(pings) == n
    assert all(p["ok"] == 1 for p in probes)  # probes unaffected by blocked pings
    assert [(p["run_id"], p["target_id"], p["seq"]) for p in probes] == [
        (g["run_id"], g["target_id"], g["seq"]) for g in pings
    ]
    statuses = [g["status"] for g in pings]
    assert statuses.count("no_reply") == n // 3 and "ok" in statuses
    blocked = [g for g in pings if g["status"] == "no_reply"]
    assert all(g["rtt_median_ms"] is None for g in blocked)
    answered = [g for g in pings if g["status"] == "ok"]
    assert all(g["rtt_median_ms"] == 11.0 and g["ip"] == "203.0.113.10" for g in answered)
    assert result["pings"] and PUBLIC_IP not in "\n".join(conn.iterdump())
    # same append-only rule as every other measurement table
    import pytest

    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE pings SET status = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM pings")


def test_probe_rows_identical_with_and_without_ping(cfg, monkeypatch, tmp_path):
    """Adding the ping must not change what the probe itself records."""
    import copy

    from kla.config import Config

    _fake_dns(monkeypatch)
    monkeypatch.setattr(context, "gather", lambda c, **k: net_context(PUBLIC_IP))
    monkeypatch.setattr(probe.random, "shuffle", lambda x: None)  # same order both times
    monkeypatch.setattr(util, "run_cmd", lambda args, timeout=30: util.CmdResult(0, PING_OK, ""))
    from kla import http
    from tests.conftest import FakeCurl

    monkeypatch.setattr(http, "CURL_FACTORY", lambda: FakeCurl(status=401))
    with_ping = probe.run_probe(cfg, echo=lambda s: None)["rows"]
    raw = copy.deepcopy(cfg.raw)
    raw["ping"] = {"enabled": False}
    raw["storage"]["db_path"] = str(tmp_path / "noping.sqlite3")
    no_ping_cfg = Config(root=cfg.root, targets=cfg.targets, raw=raw)
    result = probe.run_probe(no_ping_cfg, echo=lambda s: None)
    without = result["rows"]
    assert result["pings"] == []

    def strip(rows):
        return [{k: v for k, v in r.items() if k != "ts_utc"} for r in rows]

    assert strip(with_ping) == strip(without)
