"""Paid AI providers: opt-in only, every call priced, and a hard total spend cap."""

import copy
import json
import sqlite3

import pytest

from kla import ai, db, status, util
from kla.config import Config
from tests.conftest import net_context


def _with(cfg: Config, **openai: object) -> Config:
    raw = copy.deepcopy(cfg.raw)
    raw["ai"]["providers"]["openai"].update(openai)
    return Config(root=cfg.root, targets=cfg.targets, raw=raw)


def _stream(usage: tuple[int, int] | None = (20, 5)) -> list[bytes]:
    chunks = [
        b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n',
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n',
    ]
    if usage:
        tokens = {"prompt_tokens": usage[0], "completion_tokens": usage[1]}
        chunks.append(f"data: {json.dumps({'choices': [], 'usage': tokens})}\n\n".encode())
    return [*chunks, b"data: [DONE]\n\n"]


def _spend(cfg: Config) -> list[dict]:
    conn = db.connect(cfg.spend_db_path)
    rows = db.fetch(conn, "SELECT * FROM ai_spend ORDER BY id")
    conn.close()
    return rows


def test_paid_provider_needs_opt_in_a_listed_price_and_a_cap(cfg):
    choice = ai.model_choice(cfg, "openai", "small")
    assert choice.id == "gpt-5-nano"
    ai.assert_free(cfg, choice)  # opted in, priced and capped in config.yaml
    assert cfg.section("ai")["allow_paid"] is False  # the global "anything paid" switch stays off
    for changes, why in [
        ({"opt_in": False}, "opt_in"),
        ({"spend_cap_usd": 0}, "spend_cap_usd"),
        ({"paid_models": {}}, "no listed price"),
    ]:
        with pytest.raises(ai.PaidModelRefused, match=why):
            ai.assert_free(_with(cfg, **changes), choice)


def test_openai_request_caps_completion_tokens_and_asks_for_usage(cfg):
    choice = ai.model_choice(cfg, "openai", "small")
    url, _, body = ai.build_request(
        "openai", "https://api.openai.com/v1", choice, "hi", 64, True, "sk-x"
    )
    b = json.loads(body)
    assert url == "https://api.openai.com/v1/chat/completions"
    assert b["max_completion_tokens"] == 64 and "max_tokens" not in b and "temperature" not in b
    assert b["stream_options"] == {"include_usage": True} and b["reasoning_effort"] == "minimal"
    _, _, plain = ai.build_request("openai", "https://x", choice, "hi", 64, False, "k")
    assert "stream_options" not in json.loads(plain)  # only allowed when streaming
    groq = ai.model_choice(cfg, "groq", "small")
    g = json.loads(ai.build_request("openai", "https://x", groq, "hi", 128, True, "k")[2])
    assert g["max_tokens"] == 128 and g["temperature"] == 0 and "stream_options" not in g


def test_paid_call_is_priced_from_the_tokens_reported(cfg, fake_curl):
    fake_curl(chunks=_stream((20, 5)))
    row = ai.call_model(cfg, ai.model_choice(cfg, "openai", "small"), "sk-secret", run_id="r1")
    assert row["ok"] == 1 and "sk-secret" not in json.dumps(row)
    [s] = _spend(cfg)
    assert (s["basis"], s["input_tokens"], s["output_tokens"]) == ("usage", 20, 5)
    assert s["cost_usd"] == pytest.approx((20 * 0.05 + 5 * 0.40) / 1e6)
    assert s["run_id"] == "r1" and s["recorded_in"] == cfg.db_path.name
    fake_curl(chunks=_stream((20, 5)))
    ai.call_model(cfg, ai.model_choice(cfg, "groq", "small"), "k")
    assert len(_spend(cfg)) == 1  # free providers never touch the ledger


def test_unreported_tokens_count_at_worst_case_and_rejections_at_zero(cfg, fake_curl):
    choice = ai.model_choice(cfg, "openai", "small")
    fake_curl(chunks=_stream(None))
    ai.call_model(cfg, choice, "k")
    fake_curl(status=429, chunks=[b'{"error":{"message":"Rate limit reached"}}'])
    ai.call_model(cfg, choice, "k")
    worst, rejected = _spend(cfg)
    prompt_tokens = len(cfg.section("ai")["prompt"].encode()) + ai.CHAT_OVERHEAD_TOKENS
    expected = (prompt_tokens * 0.05 + 64 * 0.40) / 1e6
    assert worst["basis"] == "worst_case" and worst["cost_usd"] == pytest.approx(expected)
    assert rejected["basis"] == "rejected" and rejected["cost_usd"] == 0


def test_spend_cap_stops_calls_before_it_is_reached(cfg):
    conn = db.connect(cfg.db_path)
    now = util.utc_now()
    choice = ai.model_choice(cfg, "openai", "small")
    worst = ai.worst_case_usd(cfg, choice)
    assert ai.due(conn, cfg, "openai", now, scheduled=True) == (True, "ok")
    ai.record_spend(cfg, {**ai.spend_row(cfg, choice, 200, (0, 0)), "cost_usd": 1.0 - 1.5 * worst})
    assert ai.due(conn, cfg, "openai", now, scheduled=True) == (True, "ok")  # one more fits
    ok, why = ai.due(conn, cfg, "openai", now, scheduled=False, needed=2)  # two would not
    assert not ok and "spend cap reached" in why
    ai.record_spend(cfg, {**ai.spend_row(cfg, choice, 200, (0, 0)), "cost_usd": worst})
    ok, why = ai.due(conn, cfg, "openai", now, scheduled=True)
    assert not ok and "spend cap reached" in why
    assert ai.due(conn, cfg, "groq", now, scheduled=True)[0]  # free providers unaffected
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM ai_spend")
    conn.close()


def test_a_dry_run_still_logs_its_spend_in_the_main_database(cfg, fake_curl, tmp_path):
    raw = copy.deepcopy(cfg.raw)
    raw["storage"]["spend_db_path"] = raw["storage"]["db_path"]
    raw["storage"]["db_path"] = str(tmp_path / "dryrun.sqlite3")
    dry = Config(root=cfg.root, targets=cfg.targets, raw=raw)
    fake_curl(chunks=_stream((20, 5)))
    ai.call_model(dry, ai.model_choice(dry, "openai", "small"), "k")
    assert [s["recorded_in"] for s in _spend(cfg)] == ["dryrun.sqlite3"]
    assert ai.spent_usd(dry, "openai") == ai.spent_usd(cfg, "openai") > 0


def test_scheduled_run_calls_openai_only_with_a_key_and_links_spend(cfg, fake_curl, monkeypatch):
    monkeypatch.setattr(ai.context, "gather", lambda *_: net_context())
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    (cfg.root / ".env").write_text("GROQ_API_KEY=gsk_test\n")
    fake_curl(chunks=_stream((20, 5)))
    lines: list[str] = []
    ai.run_ai(cfg, echo=lines.append)
    assert "  openai: skipped (no OPENAI_API_KEY in .env)" in lines and _spend(cfg) == []
    (cfg.root / ".env").write_text("OPENAI_API_KEY=sk-test\n")
    out = ai.run_ai(cfg, echo=lines.append)
    [s] = _spend(cfg)
    assert [r["provider"] for r in out["rows"]] == ["openai"] and s["run_id"] == out["run_id"]
    conn = db.connect(cfg.db_path)
    sql = "SELECT COUNT(*) FROM ai_calls WHERE run_id = ?"
    assert conn.execute(sql, (out["run_id"],)).fetchone()[0] == 1
    conn.close()


def test_status_shows_spend_against_the_cap(cfg):
    p = ai.providers(cfg)["openai"]
    assert "$0.000000 of $1.00 cap spent over 0 call(s)" in status.paid_line(cfg, "openai", p)
    choice = ai.model_choice(cfg, "openai", "small")
    ai.record_spend(cfg, ai.spend_row(cfg, choice, 200, (20, 5)))
    assert "$0.000003 of $1.00 cap spent over 1 call(s)" in status.paid_line(cfg, "openai", p)
    off = ai.providers(_with(cfg, opt_in=False))["openai"]
    assert "never called" in status.paid_line(cfg, "openai", off)
