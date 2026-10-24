import json
from datetime import timedelta

import pytest

from kla import ai, analyze, db, util


def test_build_request_gemini_streams_with_key_in_header():
    choice = ai.ModelChoice(
        "gemini", "small", "gemini-3.5-flash-lite", {"thinking_level": "MINIMAL"}
    )
    url, headers, body = ai.build_request(
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta",
        choice,
        "hi",
        32,
        True,
        "KEY123",
    )
    assert url.endswith("/models/gemini-3.5-flash-lite:streamGenerateContent?alt=sse")
    assert "KEY123" not in url  # key goes in a header, never in the URL (URLs end up in logs)
    assert "x-goog-api-key: KEY123" in headers
    payload = json.loads(body)
    assert payload["generationConfig"] == {
        "maxOutputTokens": 32,
        "temperature": 0,
        "thinkingConfig": {"thinkingLevel": "MINIMAL"},
    }


def test_build_request_openai_compatible():
    choice = ai.ModelChoice(
        "groq", "small", "openai/gpt-oss-20b", {"extra": {"reasoning_effort": "low"}}
    )
    url, headers, body = ai.build_request(
        "openai", "https://api.groq.com/openai/v1", choice, "hi", 64, False, "gsk_x"
    )
    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert "Authorization: Bearer gsk_x" in headers
    assert json.loads(body) == {
        "model": "openai/gpt-oss-20b",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 64,
        "temperature": 0,
        "stream": False,
        "reasoning_effort": "low",
    }


def test_extract_reasoning_vs_visible():
    got = ai.extract("openai", {"choices": [{"delta": {"reasoning": "thinking..."}}]})
    assert got["any"] and got["visible"] == ""
    got = ai.extract(
        "gemini",
        {
            "candidates": [
                {
                    "content": {"parts": [{"text": "plan", "thought": True}, {"text": "Hello"}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {"candidatesTokenCount": 1},
        },
    )
    assert got["visible"] == "Hello" and got["finish"] == "STOP" and got["tokens"] == 1


def test_stream_parser_timestamps_first_tokens():
    ticks = iter([1.10, 1.20, 1.30, 1.40])
    p = ai.StreamParser("openai", clock=lambda: next(ticks))
    p.feed(b": OPENROUTER PROCESSING\r\n\r\n")  # keep-alive comment, not a token
    p.feed(b'data: {"choices":[{"delta":{"reasoning":"hmm"}}]}\n\ndata: {"choi')  # split mid-event
    p.feed(b'ces":[{"delta":{"content":"Hello"}}]}\n\n')
    p.feed(
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],'
        b'"usage":{"completion_tokens":3}}\n\n'
        b"data: [DONE]\n\n"
    )
    assert p.ms_since(1.0) == pytest.approx((200.0, 300.0))
    assert p.text == "Hello" and p.finish == "stop" and p.tokens == 3


def test_last_event_without_blank_line_is_timed_when_it_arrived():
    ticks = iter([2.5])
    p = ai.StreamParser("openai", clock=lambda: next(ticks))
    p.feed(b'data: {"choices":[{"delta":{"content":"hi"}}]}')  # no "\n\n" after it
    assert p.visible_at is None
    p.close()  # must not read the clock again (it would raise StopIteration)
    assert p.ms_since(2.0) == pytest.approx((500.0, 500.0)) and p.text == "hi"


def test_free_guard(cfg):
    paid = ai.ModelChoice("gemini", "small", "gemini-4-argon", {})
    with pytest.raises(ai.PaidModelRefused):
        ai.assert_free(cfg, paid)
    ai.assert_free(cfg, ai.model_choice(cfg, "gemini", "small"))  # on the verified list

    free_or = ai.model_choice(cfg, "openrouter", "small")
    zero = json.dumps({"data": {"endpoints": [{"pricing": {"prompt": "0", "completion": "0"}}]}})
    priced = json.dumps(
        {"data": {"endpoints": [{"pricing": {"prompt": "0.0000002", "completion": "0"}}]}}
    )
    ai.assert_free(cfg, free_or, fetch=lambda url: zero)
    with pytest.raises(ai.PaidModelRefused):
        ai.assert_free(cfg, free_or, fetch=lambda url: priced)

    def offline(url):
        raise OSError("down")

    with pytest.raises(ai.PaidModelRefused):  # cannot verify -> refuse
        ai.assert_free(cfg, free_or, fetch=offline)


def _call(provider, ts, status=200, experiment=None):
    return {
        "run_id": "r",
        "ts_utc": util.iso(ts),
        "provider": provider,
        "model": "m",
        "mode": "stream",
        "ok": 1,
        "http_status": status,
        "experiment": experiment,
    }


def test_budget_interval_and_cooldown(cfg):
    conn = db.connect(cfg.db_path)
    now = util.utc_now()
    with conn:
        db.insert(
            conn,
            "runs",
            {
                "run_id": "r",
                "kind": "ai",
                "started_utc": util.iso(now),
                "started_eat": util.iso(now),
                "finished_utc": util.iso(now),
                "hour_eat": 0,
                "weekday_eat": 0,
                "tool_version": "t",
            },
        )
    assert ai.due(conn, cfg, "groq", now, scheduled=True) == (True, "ok")
    with conn:
        db.insert(conn, "ai_calls", _call("groq", now - timedelta(minutes=10)))
    ok, why = ai.due(conn, cfg, "groq", now, scheduled=True)
    assert not ok and "within" in why
    assert ai.due(conn, cfg, "groq", now, scheduled=False)[0]  # experiments ignore the interval
    with conn:
        db.insert(conn, "ai_calls", _call("gemini", now - timedelta(minutes=30), status=429))
    ok, why = ai.due(conn, cfg, "gemini", now, scheduled=False)
    assert not ok and "429" in why
    budget = cfg.section("ai")["providers"]["openrouter"]["daily_budget"]
    ok, why = ai.due(conn, cfg, "openrouter", now, scheduled=False, needed=budget + 1)
    assert not ok and "budget" in why


def test_call_model_streaming(cfg, fake_curl):
    chunks = [
        b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n',
        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
    ]
    made = fake_curl(chunks=chunks)
    row = ai.call_model(cfg, ai.model_choice(cfg, "groq", "small"), "gsk_secret")
    assert row["ok"] == 1 and row["error_type"] is None
    assert row["ttft_visible_ms"] is not None and row["output_chars"] == 5
    sent_headers = made[0].opts[__import__("pycurl").HTTPHEADER]
    assert "Authorization: Bearer gsk_secret" in sent_headers
    assert "gsk_secret" not in json.dumps(row)


def test_first_token_and_total_share_one_clock(cfg, fake_curl, monkeypatch):
    """The Gemini case from 22 Oct: a slow first-call setup must not count, and the
    total must come from the same clock as the first token, not from curl's."""
    fake_curl(
        chunks=[
            b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n',
            b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        ]
    )  # curl's own total in the fake is 401 ms
    readings = [10.000, 10.4000, 10.4004, 10.4006]  # curl starts, two chunks, curl returns
    monkeypatch.setattr(ai.time, "perf_counter", lambda: readings.pop(0))
    row = ai.call_model(cfg, ai.model_choice(cfg, "groq", "small"), "k")
    assert readings == []
    assert row["ttft_any_ms"] == row["ttft_visible_ms"] == pytest.approx(400.0)
    assert row["total_ms"] == pytest.approx(400.6)
    assert row["ttft_visible_ms"] <= row["total_ms"]


def test_analysis_leaves_out_first_token_times_from_before_one_clock():
    rows = [
        {
            "provider": "gemini",
            "model": "m",
            "mode": "stream",
            "experiment": None,
            "ok": 1,
            "ttft_any_ms": 1588.9,
            "ttft_visible_ms": 1588.9,
            "total_ms": 1579.9,
            "tool_version": "0.2.0",
        },
        {
            "provider": "gemini",
            "model": "m",
            "mode": "stream",
            "experiment": None,
            "ok": 1,
            "ttft_any_ms": 1500.0,
            "ttft_visible_ms": 1500.0,
            "total_ms": 1510.0,
            "tool_version": "0.3.0",
        },
    ]
    failed_old = {**rows[0], "ok": 0, "ttft_any_ms": None, "ttft_visible_ms": None}
    rows.append(failed_old)  # never had a first token: nothing to leave out
    fixed = analyze.ai_on_one_clock(rows)
    assert fixed[0]["ttft_visible_ms"] is None and fixed[0]["total_ms"] == 1579.9
    assert fixed[1] is rows[1]
    assert rows[0]["ttft_visible_ms"] == 1588.9  # the input (stored data) is not changed
    text = "\n".join(analyze.ai_table(fixed))
    assert fixed[2] is failed_old
    assert "| gemini | m | stream | scheduled | 3 | 2 | 1,500 |" in text
    assert "First-token times of 1 call(s) made before tool version 0.3.0" in text


def test_call_model_rate_limited_and_key_scrubbed(cfg, fake_curl):
    body = json.dumps({"error": {"message": "Rate limit reached for key gsk_secret"}}).encode()
    fake_curl(status=429, chunks=[body])
    row = ai.call_model(cfg, ai.model_choice(cfg, "groq", "small"), "gsk_secret")
    assert row["ok"] == 0 and row["error_type"] == "rate_limited"
    assert "gsk_secret" not in row["error_msg"] and "Rate limit" in row["error_msg"]


def test_call_model_hidden_reasoning_only(cfg, fake_curl):
    fake_curl(
        chunks=[b'data: {"choices":[{"delta":{"reasoning":"..."},"finish_reason":"length"}]}\n\n']
    )
    row = ai.call_model(cfg, ai.model_choice(cfg, "groq", "small"), "k")
    assert row["ok"] == 0 and row["error_type"] == "no_visible_output"
    assert row["ttft_any_ms"] is not None and row["ttft_visible_ms"] is None


def test_call_model_non_streaming(cfg, fake_curl):
    fake_curl(
        chunks=[
            json.dumps(
                {"choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}]}
            ).encode()
        ]
    )
    row = ai.call_model(cfg, ai.model_choice(cfg, "groq", "small"), "k", stream=False)
    assert row["ok"] == 1 and row["ttft_visible_ms"] == row["total_ms"]


def test_keys_loaded_from_dotenv_and_skip_without_keys(cfg, capsys):
    assert ai.run_ai(cfg) is None
    assert "no API keys" in capsys.readouterr().out
    (cfg.root / ".env").write_text("GROQ_API_KEY=gsk_test\nGEMINI_API_KEY=\n")
    keys = ai.load_keys(cfg.root)
    assert keys["GROQ_API_KEY"] == "gsk_test" and "GEMINI_API_KEY" not in keys
