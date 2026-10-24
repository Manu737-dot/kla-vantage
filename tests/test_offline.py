"""Runs made with no network connection: no AI calls, no spend, left out of analysis."""

from datetime import timedelta

import pytest

from kla import ai, analyze, cli, context, db, experiments, util
from kla.ai import online as real_online  # conftest replaces ai.online in every test
from tests.test_paid import _spend
from tests.test_pipeline import _synthetic_db


def test_online_waits_for_a_route(cfg, monkeypatch):
    routes = iter([(None, None), ("192.168.100.1", "wlp61s0")])
    monkeypatch.setattr(context, "egress_route", lambda: next(routes))
    monkeypatch.setattr(context.time, "sleep", lambda s: None)
    assert context.wait_for_route(60)[:2] == ("192.168.100.1", "wlp61s0")
    monkeypatch.setattr(context, "egress_route", lambda: (None, None))
    assert context.wait_for_route(0) == (None, None, 0.0)
    raw = {**cfg.raw, "context": {**cfg.raw["context"], "wait_for_network_s": 0}}
    assert real_online(type(cfg)(root=cfg.root, targets=cfg.targets, raw=raw)) is False


def test_no_ai_calls_and_no_spend_when_offline(cfg, fake_curl, monkeypatch):
    monkeypatch.setattr(ai, "online", lambda cfg: False)
    (cfg.root / ".env").write_text("OPENAI_API_KEY=sk-test\nGROQ_API_KEY=gsk_test\n")
    made = fake_curl()
    lines: list[str] = []
    assert ai.run_ai(cfg, echo=lines.append) is None
    assert "Part 2 skipped: no network connection, so no AI calls were made." in lines
    assert made == [] and _spend(cfg) == []
    conn = db.connect(cfg.db_path)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0  # nothing stored
    conn.close()
    with pytest.raises(SystemExit, match="no network connection"):
        experiments.stream(cfg, "groq", n=1, echo=lambda s: None)


def test_a_paid_call_that_never_connected_costs_nothing(cfg, fake_curl):
    fake_curl(
        status=0,
        times={"namelookup": 0, "connect": 0},
        headers=[],
        chunks=[],
        error=(6, "Could not resolve host: api.openai.com"),
    )
    row = ai.call_model(cfg, ai.model_choice(cfg, "openai", "small"), "k")
    assert row["ok"] == 0 and row["http_status"] is None
    [s] = _spend(cfg)
    assert s["basis"] == "not_sent" and s["cost_usd"] == 0
    # connected and TLS done, then the reply never came: it may have been billed
    fake_curl(
        status=0,
        times={"namelookup": 100, "connect": 60_000, "appconnect": 180_000},
        headers=[],
        chunks=[],
        error=(28, "Operation timed out after 60000 milliseconds"),
    )
    ai.call_model(cfg, ai.model_choice(cfg, "openai", "small"), "k")
    assert _spend(cfg)[1]["basis"] == "worst_case" and _spend(cfg)[1]["cost_usd"] > 0


def _offline_runs(cfg, n: int = 2) -> list[str]:
    """n probe runs with no network, 15 min apart, after the synthetic data."""
    conn = db.connect(cfg.db_path)
    last = util.parse_iso(conn.execute("SELECT MAX(started_utc) FROM runs").fetchone()[0])
    ids = []
    with conn:
        for i in range(n):
            t = last + timedelta(minutes=15 * (i + 1))
            run_id = f"offline{i}"
            ids.append(run_id)
            db.insert(
                conn,
                "runs",
                {
                    "run_id": run_id,
                    "kind": "probe",
                    "started_utc": util.iso(t),
                    "started_eat": util.iso(util.to_eat(t)),
                    "finished_utc": util.iso(t),
                    "hour_eat": util.to_eat(t).hour,
                    "weekday_eat": util.to_eat(t).weekday(),
                    "tool_version": "0.4.1",
                    "conn_type": "none",
                },
            )
            for target in cfg.targets:
                db.insert(
                    conn,
                    "probes",
                    {
                        "run_id": run_id,
                        "ts_utc": util.iso(t),
                        "target_id": target.id,
                        "grp": target.group,
                        "ok": 0,
                        "error_type": "dns_failure",
                    },
                )
    conn.close()
    return ids


def test_offline_runs_are_left_out_of_the_analysis_by_default(cfg):
    _synthetic_db(cfg)
    ids = _offline_runs(cfg)
    raw = analyze.load(cfg, None)
    assert not any(p["run_id"] in ids for p in analyze.select(raw)["probes"])
    kept = analyze.select(raw, include_offline=True)["probes"]
    assert sum(p["run_id"] in ids for p in kept) == 2 * len(cfg.targets)

    text = analyze.run(cfg, echo=lambda s: None).read_text()
    line = next(x for x in text.splitlines() if "no network connection" in x)
    assert line.startswith("- Probe runs with no network connection (laptop offline): 2 (")
    assert "–" in line and line.endswith("(left out; --include-offline)")
    assert "| openai | llm |" in text and "dns_failure" not in text  # no offline failures


def test_cli_include_offline(cfg):
    _synthetic_db(cfg)
    _offline_runs(cfg, n=1)
    out = cfg.root / "with-offline"
    args = ["--config", str(cfg.root / "config" / "config.yaml"), "analyze"]
    assert cli.main([*args, "--include-offline", "--out", str(out)]) == 0
    text = (out / "report.md").read_text()
    assert "(laptop offline): 1 (" in text and "(included: --include-offline)" in text
    assert "dns_failure" in text  # its failures are back in
