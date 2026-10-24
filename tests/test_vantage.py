"""The comparison vantage point: the laptop's measurement code, its own files, ledger and cap."""

import dataclasses
import sqlite3
import subprocess
from datetime import UTC, datetime

import pytest
import yaml

from kla import ai, context, db, probe, util, vantage
from kla.config import Config

RUNNER_IP = "203.0.113.50"


@pytest.fixture
def runner(cfg: Config, tmp_path, monkeypatch: pytest.MonkeyPatch):
    """A fake runner: GitHub's environment, keys, and no real network."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    for key in ("GEMINI_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(key, f"secret-{key}")
    pub = context.PublicInfo(
        asn=8075, as_name="Microsoft Corporation", source="ripestat", cf_colo="IAD"
    )
    pub.public_ip = RUNNER_IP
    row = {"runner_ip": RUNNER_IP, "asn": 8075, "cf_colo": "IAD", "azure_region": "eastus"}
    monkeypatch.setattr(vantage, "runner_context", lambda root=None: (row, pub))
    monkeypatch.setattr(vantage.dnsprobe, "upstream_servers", lambda setting: ["168.63.129.16"])

    def fake_probe(target, cfg, servers):
        return {
            "ts_utc": util.iso(util.utc_now()),
            "target_id": target.id,
            "host": target.host,
            "grp": target.group,
            "tcp_ms": 2.0,
            "edge_pop": "IAD",
            "ok": 1,
        }

    monkeypatch.setattr(probe, "probe_target", fake_probe)
    monkeypatch.setattr(ai, "openrouter_is_free", lambda model_id, fetch=None: True)
    calls: list[str] = []

    def fake_call(cfg, choice, key, *, stream=True, run_id=None, experiment=None):
        assert key == f"secret-{ai.providers(cfg)[choice.provider]['env_key']}"
        calls.append(choice.provider)
        if ai.is_paid(ai.providers(cfg)[choice.provider]):
            spend = ai.spend_row(cfg, choice, 200, (13, 10))
            spend.update(run_id=run_id, recorded_in=cfg.db_path.name)
            ai.record_spend(cfg, spend)
        return {
            "ts_utc": util.iso(util.utc_now()),
            "provider": choice.provider,
            "model": choice.id,
            "size": choice.size,
            "mode": "stream",
            "ok": 1,
            "http_status": 200,
            "ttft_visible_ms": 300.0,
            "total_ms": 400.0,
            "error_type": None,
        }

    monkeypatch.setattr(ai, "call_model", fake_call)
    data = tmp_path / "vantage-data"
    vantage.init_data_dir(data)
    vcfg, v = vantage.load(cfg)
    return vcfg, v, data, calls


def _at(monkeypatch: pytest.MonkeyPatch, hour_utc: int, minute: int) -> None:
    when = datetime(2026, 10, 25, hour_utc, minute, tzinfo=UTC)
    monkeypatch.setattr(util, "utc_now", lambda: when)


def _rows(path, sql):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(sql)]
    conn.close()
    return rows


def test_runner_config_keeps_the_laptops_measurement_settings(cfg, tmp_path):
    vcfg, v = vantage.load(cfg)
    llm = [t.id for t in cfg.targets if t.group == "llm"]
    assert [t.id for t in vcfg.targets] == llm and len(llm) == 9
    for section in ("probe", "dns"):
        assert vcfg.section(section) == cfg.section(section)
    assert vcfg.section("ai")["prompt"] == cfg.section("ai")["prompt"]
    for name, pcfg in ai.providers(cfg).items():
        assert ai.providers(vcfg)[name]["models"] == pcfg["models"]
    assert ai.providers(vcfg)["openai"]["spend_cap_usd"] == 0.25
    assert ai.providers(cfg)["openai"]["spend_cap_usd"] == 1.0  # the laptop's is untouched
    assert (v.name, v.odd_hours_only) == ("us-runner", ("gemini", "openrouter"))
    assert v.db_path == cfg.root / "data" / "vantage.sqlite3" != cfg.db_path
    assert v.repo_url == "https://github.com/Manu737-dot/kla-vantage.git"
    # Raising the cap in the override file has no effect: the code caps it at 0.25.
    raised = tmp_path / "vantage.yaml"
    raised.write_text(
        yaml.safe_dump({"overrides": {"ai": {"providers": {"openai": {"spend_cap_usd": 5}}}}})
    )
    assert ai.providers(vantage.load(cfg, raised)[0])["openai"]["spend_cap_usd"] == 0.25


def test_slot_hour_is_the_scheduled_hour_even_when_github_starts_late():
    def slot(h, m):
        return vantage.slot_hour_eat(datetime(2026, 10, 25, h, m, tzinfo=UTC), 45)

    # 18:46 UTC = 21:46 EAT; 19:30 UTC = 22:30 EAT (a late start of the 21:45 run)
    assert (slot(18, 46), slot(19, 30), slot(19, 44), slot(19, 46)) == (21, 21, 21, 22)


def test_run_writes_one_file_with_the_laptop_tables_and_where_the_runner_was(runner, monkeypatch):
    vcfg, v, data, calls = runner
    _at(monkeypatch, 18, 50)  # 21:50 EAT: an odd hour, so all four providers
    result = vantage.run(vcfg, v, data, echo=lambda s: None)
    [path] = list((data / "runs").glob("*/*.sqlite3"))
    assert path == result["file"] and path.parent.name == "2026-10-25"
    assert sorted(calls) == ["gemini", "groq", "openai", "openrouter"]
    runs = _rows(path, "SELECT * FROM runs ORDER BY kind DESC")
    assert [r["kind"] for r in runs] == ["probe", "ai"]
    assert {r["notes"] for r in runs} == {"vantage=us-runner"} and runs[0]["cf_colo"] == "IAD"
    assert len(_rows(path, "SELECT * FROM probes")) == 9
    assert len(_rows(path, "SELECT * FROM ai_calls")) == 4
    [ctx] = _rows(path, "SELECT * FROM vantage_context")
    assert (ctx["vantage"], ctx["runner_ip"], ctx["azure_region"]) == (
        "us-runner",
        RUNNER_IP,
        "eastus",
    )
    assert ctx["slot_hour_eat"] == 21 and ctx["probe_run_id"] == runs[0]["run_id"]
    [spend] = _rows(data / vantage.LEDGER, "SELECT * FROM ai_spend")
    assert spend["provider"] == "openai" and spend["recorded_in"] == path.name
    assert not _rows(path, "SELECT * FROM ai_spend")  # spend lives only in the ledger
    assert "secret-" not in path.read_bytes().decode("latin-1")
    assert not vcfg.db_path.exists()  # the Kenya database is never created or touched


def test_even_hours_skip_gemini_and_openrouter_and_history_spaces_the_calls(runner, monkeypatch):
    vcfg, v, data, calls = runner
    _at(monkeypatch, 19, 50)  # 22:50 EAT
    result = vantage.run(vcfg, v, data, echo=lambda s: None)
    assert sorted(calls) == ["groq", "openai"]
    assert "gemini: odd EAT hours only" in result["notes"]
    calls.clear()
    _at(monkeypatch, 20, 20)  # 23:20 EAT, a late start of the 22:45 slot: nothing is due
    result = vantage.run(vcfg, v, data, echo=lambda s: None)
    assert calls == []
    assert any(n.startswith("groq: not due") for n in result["notes"])
    _at(monkeypatch, 20, 50)  # 23:50 EAT: an odd hour, and an hour after the last calls
    vantage.run(vcfg, v, data, echo=lambda s: None)
    assert sorted(calls) == ["gemini", "groq", "openai", "openrouter"]


def test_no_paid_call_without_the_ledger_or_past_the_cap(runner, monkeypatch):
    vcfg, v, data, calls = runner
    _at(monkeypatch, 18, 50)
    (data / vantage.LEDGER).unlink()
    result = vantage.run(vcfg, v, data, echo=lambda s: None)
    assert "openai" not in calls and not (data / vantage.LEDGER).exists()
    assert any(n.startswith("openai: REFUSED - no spend ledger") for n in result["notes"])
    # A ledger already at the cap: one more worst-case call could pass $0.25.
    conn = db.connect(data / vantage.LEDGER)
    choice = ai.model_choice(vcfg, "openai", "small")
    with conn:
        db.insert(
            conn,
            "ai_spend",
            {
                **ai.spend_row(vcfg, choice, 200, (1, 1)),
                "cost_usd": 0.25 - ai.worst_case_usd(vcfg, choice) / 2,
            },
        )
    conn.close()
    calls.clear()
    _at(monkeypatch, 20, 50)
    result = vantage.run(vcfg, v, data, echo=lambda s: None)
    assert "openai" not in calls and "groq" in calls
    assert any("spend cap reached" in n for n in result["notes"])


def test_run_refuses_outside_github_actions(runner, monkeypatch):
    vcfg, v, data, _ = runner
    monkeypatch.delenv("GITHUB_ACTIONS")
    with pytest.raises(vantage.VantageError, match="only runs on a GitHub runner"):
        vantage.run(vcfg, v, data)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with pytest.raises(vantage.VantageError, match="not a checkout"):
        vantage.run(vcfg, v, data.parent)


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_pull_imports_into_its_own_labelled_database_once(runner, monkeypatch, tmp_path):
    vcfg, v, data, _ = runner
    _at(monkeypatch, 18, 50)
    vantage.run(vcfg, v, data, echo=lambda s: None)
    # The runner's branch, in a stand-in for the GitHub repo ...
    _git(data, "init", "-q", "-b", vantage.BRANCH)
    _git(data, "add", "-A")
    _git(data, "commit", "-q", "-m", "run")
    # ... and the laptop's copy of the code, pointed at that repo.
    _git(vcfg.root, "init", "-q")
    v = dataclasses.replace(v, repo_url=str(data))
    out = []
    got = vantage.pull(vcfg, v, echo=out.append)
    assert got == {"new": 1, "files": 1, "spend_rows": 1}
    dest = v.db_path
    assert {r["vantage"] for r in _rows(dest, "SELECT vantage FROM probes")} == {"us-runner"}
    assert len(_rows(dest, "SELECT * FROM probes")) == 9
    assert len(_rows(dest, "SELECT * FROM ai_calls")) == 4
    assert [r["vantage"] for r in _rows(dest, "SELECT * FROM ai_spend")] == ["us-runner"]
    assert _rows(dest, "SELECT runner_ip FROM vantage_context") == [{"runner_ip": RUNNER_IP}]
    assert vantage.pull(vcfg, v, echo=out.append) == {"new": 0, "files": 1, "spend_rows": 0}
    assert not vcfg.db_path.exists()  # nothing went near the Kenya database
    kenya = dataclasses.replace(v, db_path=vcfg.db_path)
    with pytest.raises(vantage.VantageError, match="Kenya database"):
        vantage.pull(vcfg, kenya)
