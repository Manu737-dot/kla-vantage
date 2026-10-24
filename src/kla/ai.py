"""Part 2: how long until an AI model starts answering? (free tiers only)

For each provider that has a key in .env we send one tiny fixed prompt with
streaming on and record:

    ttfb_ms          request sent -> first byte of the HTTP response
    ttft_any_ms      request start -> first generated token of any kind
                     (including hidden "reasoning" tokens some models stream)
    ttft_visible_ms  request start -> first piece of text a user would see
    total_ms         request start -> answer finished

"Request start" is the moment curl starts. The two first-token times and the
total are read from one clock (see http.HttpResult.started), so a first token
can never come after the total. Before tool version 0.3.0 the first-token clock
started earlier, before curl was set up; analyze.py leaves those times out.

Safety rules (enforced in code, not just documented):
- only models on the provider's verified free list; OpenRouter models must
  also end in ":free" and show a price of 0 in OpenRouter's live model data;
- the one exception is a provider marked `paid: true` that you opted into
  (`opt_in: true`): it may use only its listed `paid_models`, every call's cost
  is logged in the ai_spend table, and no call is made that could push the
  total past `spend_cap_usd` (a hard cap over all runs, ever);
- a rolling 24-hour call budget per provider, a minimum interval between
  scheduled calls, and a cool-down after any HTTP 429 (rate limited);
- keys are read from .env, sent only in request headers, never printed, and
  scrubbed from anything that is stored.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from dotenv import dotenv_values

from kla import context, db, http, netcheck, privacy, util
from kla.config import Config
from kla.probe import run_row


class PaidModelRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelChoice:
    provider: str
    size: str
    id: str
    params: dict[str, Any] = field(default_factory=dict)


def load_keys(root: Path) -> dict[str, str]:
    """API keys from .env (and the environment). Values are never printed."""
    keys = {k: v for k, v in dotenv_values(root / ".env").items() if v}
    keys.update({k: v for k, v in os.environ.items() if k.endswith("_API_KEY") and v})
    return keys


def providers(cfg: Config) -> dict[str, dict[str, Any]]:
    return dict(cfg.section("ai").get("providers") or {})


def model_choice(cfg: Config, provider: str, size: str) -> ModelChoice:
    pcfg = providers(cfg)[provider]
    if size not in (pcfg.get("models") or {}):
        raise ValueError(f"{provider} has no '{size}' model in config.yaml")
    spec = dict(pcfg["models"][size])
    model_id = str(spec.pop("id"))
    return ModelChoice(provider=provider, size=size, id=model_id, params=spec)


# --------------------------------------------------------------- free guard


def openrouter_is_free(model_id: str, fetch: Callable[[str], str] | None = None) -> bool:
    """Ask OpenRouter's public endpoint list whether this model is priced at 0."""
    fetch = fetch or context._http_get_text
    author_slug = quote(model_id, safe="/:")
    try:
        data = json.loads(fetch(f"https://openrouter.ai/api/v1/models/{author_slug}/endpoints"))
        endpoints = data["data"]["endpoints"]
    except (OSError, ValueError, KeyError, TypeError):
        return False  # cannot verify -> treat as not free
    if not endpoints:
        return False
    for ep in endpoints:
        pricing = ep.get("pricing") or {}
        for key in ("prompt", "completion", "request"):
            if float(pricing.get(key) or 0) != 0:
                return False
    return True


def assert_free(
    cfg: Config, choice: ModelChoice, fetch: Callable[[str], str] | None = None
) -> None:
    ai_cfg = cfg.section("ai")
    if ai_cfg.get("allow_paid") is True:
        return
    pcfg = providers(cfg)[choice.provider]
    if is_paid(pcfg):
        assert_paid_allowed(pcfg, choice)
        return
    if choice.id not in (pcfg.get("free_models") or []):
        raise PaidModelRefused(
            f"{choice.provider}/{choice.id} is not on the verified free list; refusing. "
            "Set ai.allow_paid: true in config.yaml only if you accept charges."
        )
    if "openrouter.ai" in str(pcfg.get("base_url", "")):
        if not choice.id.endswith(":free"):
            raise PaidModelRefused(f"OpenRouter model {choice.id} does not end in ':free'")
        if not openrouter_is_free(choice.id, fetch):
            raise PaidModelRefused(f"OpenRouter does not currently list {choice.id} as free")


# -------------------------------------------------- paid providers (opt-in)
#
# A paid provider is used only while config.yaml says `paid: true` AND
# `opt_in: true` AND its key is in .env. Each call is priced from the token
# counts the provider reports; when it reports none, the call is counted at the
# most it could have cost. Requests the provider rejects (HTTP 4xx) are not
# billed and count as $0.
# Prompt bytes are an upper bound on prompt tokens; this covers the chat wrapper.
CHAT_OVERHEAD_TOKENS = 64


def is_paid(pcfg: dict[str, Any]) -> bool:
    return pcfg.get("paid") is True


def assert_paid_allowed(pcfg: dict[str, Any], choice: ModelChoice) -> None:
    if pcfg.get("opt_in") is not True:
        raise PaidModelRefused(
            f"{choice.provider} is a paid provider and opt_in is not true in config.yaml"
        )
    if float(pcfg.get("spend_cap_usd") or 0) <= 0:
        raise PaidModelRefused(f"{choice.provider} has no spend_cap_usd; refusing")
    prices = (pcfg.get("paid_models") or {}).get(choice.id)
    if not prices or "input" not in prices or "output" not in prices:
        raise PaidModelRefused(
            f"{choice.provider}/{choice.id} has no listed price in paid_models; refusing"
        )


def price(pcfg: dict[str, Any], model_id: str) -> tuple[float, float]:
    """(USD per 1M input tokens, USD per 1M output tokens)."""
    p = pcfg["paid_models"][model_id]
    return float(p["input"]), float(p["output"])


def max_output_tokens(cfg: Config, choice: ModelChoice) -> int:
    return int(choice.params.get("max_tokens") or cfg.section("ai").get("max_tokens", 32))


def worst_case_usd(cfg: Config, choice: ModelChoice) -> float:
    """The most one call can cost: every prompt byte a token, and the full output cap."""
    p_in, p_out = price(providers(cfg)[choice.provider], choice.id)
    prompt_tokens = len(str(cfg.section("ai").get("prompt")).encode()) + CHAT_OVERHEAD_TOKENS
    return (prompt_tokens * p_in + max_output_tokens(cfg, choice) * p_out) / 1e6


def spent_usd(cfg: Config, provider: str) -> float:
    conn = db.connect(cfg.spend_db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM ai_spend WHERE provider = ?", (provider,)
        ).fetchone()
    finally:
        conn.close()
    return float(row[0])


def spend_row(
    cfg: Config,
    choice: ModelChoice,
    http_status: int | None,
    usage: tuple[int | None, int | None],
    *,
    sent: bool = True,
) -> dict[str, Any]:
    """`sent=False`: the connection never got as far as the encrypted session, so
    the request itself was never sent and cannot have been billed."""
    p_in, p_out = price(providers(cfg)[choice.provider], choice.id)
    tokens_in, tokens_out = usage
    if http_status == 200 and tokens_in is not None and tokens_out is not None:
        basis, cost = "usage", (tokens_in * p_in + tokens_out * p_out) / 1e6
    elif http_status is None and not sent:
        basis, cost = "not_sent", 0.0
    elif http_status is not None and 400 <= http_status < 500:
        basis, cost = "rejected", 0.0
    else:
        basis, cost = "worst_case", worst_case_usd(cfg, choice)
    return {
        "ts_utc": util.iso(util.utc_now()),
        "provider": choice.provider,
        "model": choice.id,
        "http_status": http_status,
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        "basis": basis,
        "usd_per_mtok_in": p_in,
        "usd_per_mtok_out": p_out,
        "cost_usd": round(cost, 9),
    }


def record_spend(cfg: Config, row: dict[str, Any]) -> None:
    conn = db.connect(cfg.spend_db_path)
    try:
        with conn:
            db.insert(conn, "ai_spend", row)
    finally:
        conn.close()


def spend_check(cfg: Config, provider: str, needed: int) -> tuple[bool, str]:
    """Would `needed` more calls, each at its worst case, stay within the cap?"""
    pcfg = providers(cfg)[provider]
    cap = float(pcfg.get("spend_cap_usd") or 0)
    spent = spent_usd(cfg, provider)
    worst = max(
        worst_case_usd(cfg, model_choice(cfg, provider, size))
        for size, spec in (pcfg.get("models") or {}).items()
        if str(spec.get("id")) in (pcfg.get("paid_models") or {})
    )
    if spent + needed * worst > cap:
        return False, (
            f"spend cap reached: ${spent:.6f} of ${cap:.2f} spent; {needed} more call(s) "
            f"could cost up to ${needed * worst:.6f}"
        )
    return True, "ok"


# ---------------------------------------------------------- budget / pacing


def due(
    conn: Any, cfg: Config, provider: str, now: datetime, *, scheduled: bool, needed: int = 1
) -> tuple[bool, str]:
    pcfg = providers(cfg)[provider]
    since = util.iso(now - timedelta(hours=24))
    used = conn.execute(
        "SELECT COUNT(*) FROM ai_calls WHERE provider = ? AND ts_utc >= ?", (provider, since)
    ).fetchone()[0]
    budget = int(pcfg.get("daily_budget", 10))
    if used + needed > budget:
        return False, f"24h budget: {used}/{budget} used, {needed} more would exceed it"
    cooldown = timedelta(minutes=float(pcfg.get("cooldown_after_429_minutes", 240)))
    hit = conn.execute(
        "SELECT MAX(ts_utc) FROM ai_calls WHERE provider = ? AND http_status = 429", (provider,)
    ).fetchone()[0]
    if hit and util.parse_iso(hit) > now - cooldown:
        return False, f"cooling down after a 429 at {hit}"
    if scheduled:
        last = conn.execute(
            "SELECT MAX(ts_utc) FROM ai_calls WHERE provider = ? AND experiment IS NULL",
            (provider,),
        ).fetchone()[0]
        gap = timedelta(minutes=float(pcfg.get("min_interval_minutes", 60)))
        # 5-minute slack so the hourly timer's random delay does not skip a slot.
        if last and util.parse_iso(last) > now - gap + timedelta(minutes=5):
            return False, f"last scheduled call {last} is within {gap}"
    if is_paid(pcfg):
        return spend_check(cfg, provider, needed)
    return True, "ok"


# ------------------------------------------------------------ request/parse


def build_request(
    api: str,
    base_url: str,
    choice: ModelChoice,
    prompt: str,
    max_tokens: int,
    stream: bool,
    key: str,
) -> tuple[str, list[str], bytes]:
    if api == "gemini":
        method = "streamGenerateContent?alt=sse" if stream else "generateContent"
        url = f"{base_url}/models/{choice.id}:{method}"
        gen: dict[str, Any] = {"maxOutputTokens": max_tokens, "temperature": 0}
        if level := choice.params.get("thinking_level"):
            gen["thinkingConfig"] = {"thinkingLevel": level}
        body: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": gen,
        }
        headers = [f"x-goog-api-key: {key}", "Content-Type: application/json"]
    else:  # OpenAI-compatible (OpenAI, OpenRouter, Groq)
        url = f"{base_url}/chat/completions"
        body = {
            "model": choice.id,
            "messages": [{"role": "user", "content": prompt}],
            # OpenAI's reasoning models take max_completion_tokens, not max_tokens.
            str(choice.params.get("token_param") or "max_tokens"): max_tokens,
            "stream": stream,
        }
        # temperature: null in config = leave it out (models that only allow the default)
        temperature = choice.params.get("temperature", 0)
        if temperature is not None:
            body["temperature"] = temperature
        if stream and choice.params.get("stream_usage"):
            body["stream_options"] = {"include_usage": True}  # token counts for pricing
        body.update(choice.params.get("extra") or {})
        headers = [f"Authorization: Bearer {key}", "Content-Type: application/json"]
    return url, headers, json.dumps(body).encode()


def extract(api: str, obj: dict[str, Any]) -> dict[str, Any]:
    """Pull tokens out of one streamed chunk (or one full non-streamed reply)."""
    out: dict[str, Any] = {
        "any": False,
        "visible": "",
        "finish": None,
        "tokens": None,
        "prompt_tokens": None,
        "error": None,
    }
    if "error" in obj:
        err = obj["error"]
        out["error"] = err.get("message") if isinstance(err, dict) else str(err)
        return out
    if api == "gemini":
        cand = (obj.get("candidates") or [{}])[0]
        for part in (cand.get("content") or {}).get("parts") or []:
            text = part.get("text") or ""
            if text:
                out["any"] = True
                if not part.get("thought"):
                    out["visible"] += text
        out["finish"] = cand.get("finishReason")
        usage = obj.get("usageMetadata") or {}
        if usage.get("thoughtsTokenCount"):
            out["any"] = True
        out["tokens"] = usage.get("candidatesTokenCount")
        out["prompt_tokens"] = usage.get("promptTokenCount")
    else:
        for choice in obj.get("choices") or []:
            delta = choice.get("delta") or choice.get("message") or {}
            content = delta.get("content") or ""
            reasoning = delta.get("reasoning") or delta.get("reasoning_content") or ""
            if content or reasoning:
                out["any"] = True
            out["visible"] += content
            out["finish"] = choice.get("finish_reason") or out["finish"]
        usage = obj.get("usage") or {}
        out["tokens"] = usage.get("completion_tokens")
        out["prompt_tokens"] = usage.get("prompt_tokens")
    return out


class StreamParser:
    """Reads Server-Sent Events as they arrive and notes when the first tokens came.

    It keeps raw clock readings; `ms_since(start)` turns them into milliseconds
    from the moment curl started, the same start and clock as the total.
    """

    def __init__(self, api: str, clock: Callable[[], float] | None = None) -> None:
        self.api, self.clock = api, clock or time.perf_counter
        self.buf = b""
        self.head = b""  # first bytes, kept to explain non-SSE error replies
        self.last_at: float | None = None  # when the latest bytes arrived
        self.any_at: float | None = None
        self.visible_at: float | None = None
        self.text = ""
        self.finish: str | None = None
        self.tokens: int | None = None
        self.prompt_tokens: int | None = None
        self.error: str | None = None

    def feed(self, data: bytes) -> None:
        now = self.last_at = self.clock()
        if len(self.head) < 4096:
            self.head += data[: 4096 - len(self.head)]
        self.buf = (self.buf + data).replace(b"\r\n", b"\n")
        while b"\n\n" in self.buf:
            event, self.buf = self.buf.split(b"\n\n", 1)
            self._event(event, now)

    def close(self) -> None:
        """Handle a last event that had no blank line after it, timed when it arrived."""
        self.buf += b"\n\n"
        while b"\n\n" in self.buf:
            event, self.buf = self.buf.split(b"\n\n", 1)
            self._event(event, self.last_at or self.clock())

    def ms_since(self, start: float) -> tuple[float | None, float | None]:
        """(first token of any kind, first visible text) in ms after `start`."""

        def ms(at: float | None) -> float | None:
            return round((at - start) * 1000, 3) if at is not None else None

        return ms(self.any_at), ms(self.visible_at)

    def _event(self, event: bytes, now: float) -> None:
        lines = [ln[5:].strip() for ln in event.split(b"\n") if ln.startswith(b"data:")]
        payload = b"\n".join(lines).decode("utf-8", "replace")
        if not payload or payload == "[DONE]":
            return  # keep-alive comments (": OPENROUTER PROCESSING") land here too
        try:
            obj = json.loads(payload)
        except ValueError:
            return
        got = extract(self.api, obj)
        if got["error"]:
            self.error = got["error"]
        if got["any"] and self.any_at is None:
            self.any_at = now
        if got["visible"].strip() and self.visible_at is None:
            self.visible_at = now
        self.text += got["visible"]
        self.finish = got["finish"] or self.finish
        self.tokens = got["tokens"] or self.tokens
        self.prompt_tokens = got["prompt_tokens"] or self.prompt_tokens


def status_error(status: int | None) -> str | None:
    if status is None or status == 200:
        return None
    if status == 429:
        return "rate_limited"
    if status in (401, 403):
        return "auth_error"
    if status == 404:
        return "model_not_found"
    if 500 <= status < 600:
        return "server_error"
    return f"http_{status}"


def call_model(
    cfg: Config,
    choice: ModelChoice,
    key: str,
    *,
    stream: bool = True,
    run_id: str | None = None,
    experiment: str | None = None,
) -> dict[str, Any]:
    """One timed call. Returns a row for the ai_calls table (keys scrubbed).

    For a paid provider the call's cost is written to ai_spend straight away, so
    it counts against the cap even if the run fails before it is saved.
    """
    ai_cfg = cfg.section("ai")
    pcfg = providers(cfg)[choice.provider]
    api = str(pcfg.get("api", "openai"))
    max_tokens = max_output_tokens(cfg, choice)
    url, headers, body = build_request(
        api, str(pcfg["base_url"]), choice, str(ai_cfg.get("prompt")), max_tokens, stream, key
    )
    p = cfg.section("probe")
    parser = StreamParser(api)
    res = http.request(
        url,
        method="POST",
        headers=headers,
        body=body,
        ip_version=int(p.get("ip_version", 4)),
        http_version=str(p.get("http_version", "1.1")),
        connect_timeout_s=float(p.get("connect_timeout_s", 10)),
        total_timeout_s=60,
        user_agent=str(p.get("user_agent", "kenya-llm-latency")),
        max_body_bytes=1_000_000,
        keep_body=not stream,
        on_data=parser.feed if stream else None,
    )
    ph = res.phases
    row: dict[str, Any] = {
        "ts_utc": util.iso(util.utc_now()),
        "provider": choice.provider,
        "model": choice.id,
        "size": choice.size,
        "mode": "stream" if stream else "nonstream",
        "http_status": res.http_status,
        "dns_ms": ph.dns_ms,
        "tcp_ms": ph.tcp_ms,
        "tls_ms": ph.tls_ms,
        "ttfb_ms": ph.ttfb_ms,
        "total_ms": res.wall_ms,  # same clock and start as the first-token times
        "http_version": res.http_version,
        "remote_ip": res.remote_ip,
        "edge_pop": res.edge_pop,
    }
    if stream:
        parser.close()
        text, finish, tokens, err = parser.text, parser.finish, parser.tokens, parser.error
        row["ttft_any_ms"], row["ttft_visible_ms"] = (
            parser.ms_since(res.started) if res.started is not None else (None, None)
        )
        raw = parser.head
        prompt_tokens = parser.prompt_tokens
    else:
        raw = res.body
        try:
            got = extract(api, json.loads(res.body or b"{}"))
        except ValueError:
            got = {"visible": "", "finish": None, "tokens": None, "prompt_tokens": None}
            got.update(error=None, any=False)
        text, finish, tokens, err = got["visible"], got["finish"], got["tokens"], got["error"]
        prompt_tokens = got["prompt_tokens"]
        # Without streaming, nothing is visible until the whole answer has arrived.
        done = res.wall_ms if res.ok and text else None
        row["ttft_any_ms"], row["ttft_visible_ms"] = done, done
    if is_paid(pcfg):
        # The request goes out only after the TLS handshake; no handshake and no
        # HTTP reply means it never left the laptop.
        sent = res.http_status is not None or ph.tls_ms is not None
        spend = spend_row(cfg, choice, res.http_status, (prompt_tokens, tokens), sent=sent)
        spend.update(run_id=run_id, experiment=experiment, recorded_in=cfg.db_path.name)
        record_spend(cfg, spend)

    error_type = res.error_type or status_error(res.http_status)
    if error_type is None and not text.strip():
        error_type = "no_visible_output"  # e.g. all tokens spent on hidden reasoning
    if err is None and res.http_status not in (None, 200):
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
            parsed = parsed[0] if isinstance(parsed, list) and parsed else parsed
            err = extract(api, parsed)["error"] if isinstance(parsed, dict) else None
        except ValueError:
            err = raw[:200].decode("utf-8", "replace")
    message = err or res.error_msg
    row.update(
        ok=int(res.http_status == 200 and res.error_type is None and bool(text.strip())),
        error_type=error_type,
        error_msg=str(message)[:300] if message else None,
        output_chars=len(text),
        output_tokens=tokens,
        finish_reason=finish,
    )
    return privacy.scrub(row, [key])


# --------------------------------------------------------------- scheduled


def online(cfg: Config) -> bool:
    """Is there any network route? Waits as long as a probe would (wait_for_network_s).

    With no network every call would fail anyway: skipping keeps the free budgets
    and the paid ledger for real attempts, and keeps the schedule's slots.
    """
    wait = float(cfg.section("context").get("wait_for_network_s", 60))
    return context.wait_for_route(wait)[1] is not None


def run_ai(cfg: Config, *, echo: Callable[[str], None] = print) -> dict[str, Any] | None:
    keys = load_keys(cfg.root)
    configured = providers(cfg)
    have = {name: p for name, p in configured.items() if keys.get(str(p.get("env_key")))}
    for name, pcfg in configured.items():
        if name not in have:
            echo(f"  {name}: skipped (no {pcfg.get('env_key')} in .env)")
    if not have:
        echo("Part 2 skipped: no API keys found.")
        return None
    if not online(cfg):
        echo("Part 2 skipped: no network connection, so no AI calls were made.")
        return None

    with util.file_lock(cfg.path("lock_path")):
        conn = db.connect(cfg.db_path)
        started = util.utc_now()
        plan: list[ModelChoice] = []
        for name, pcfg in have.items():
            sizes = list(pcfg.get("scheduled") or ["small"])
            ok, why = due(conn, cfg, name, started, scheduled=True, needed=len(sizes))
            if not ok:
                echo(f"  {name}: not due ({why})")
                continue
            for size in sizes:
                choice = model_choice(cfg, name, size)
                try:
                    assert_free(cfg, choice)
                except PaidModelRefused as exc:
                    echo(f"  {name}: REFUSED - {exc}")
                    continue
                plan.append(choice)
        if not plan:
            conn.close()
            echo("Part 2: nothing due this run.")
            return None
        ctx = context.gather(cfg.section("context"))
        run_id = uuid.uuid4().hex  # before the calls, so paid calls' spend rows carry it
        rows = []
        for choice in plan:
            key = keys[str(configured[choice.provider]["env_key"])]
            rows.append(call_model(cfg, choice, key, stream=True, run_id=run_id))
        finished = util.utc_now()
        secrets = [ctx.public.public_ip or "", *keys.values()]
        with conn:
            db.insert(
                conn, "runs", privacy.scrub(run_row(run_id, "ai", started, finished, ctx), secrets)
            )
            netcheck.save(conn, run_id, ctx, cfg.db_path)
            for row in rows:
                db.insert(conn, "ai_calls", privacy.scrub({**row, "run_id": run_id}, secrets))
        conn.close()
    for row in rows:
        echo(
            f"  {row['provider']:<10} {row['model']:<34} first visible token "
            f"{row['ttft_visible_ms']} ms, total {row['total_ms']} ms"
            + (f"  [{row['error_type']}]" if row["error_type"] else "")
        )
    return {"run_id": run_id, "rows": rows}
