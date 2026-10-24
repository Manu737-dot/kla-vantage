"""Part 3: on-demand "fix" experiments with before/after tables.

reuse       fresh connection per request vs one kept-alive (HTTP/2) connection
stream      streaming vs non-streaming: when does the first word appear?
model-size  small vs larger free model: time to first token
region      Africa vs Europe vs US cloud regions (uses Part 1 data, no new traffic)

Each experiment alternates between its two arms (A, B, A, B, ...) so that a
change in network conditions during the test hits both arms equally.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pycurl

from kla import ai, context, db, http, netcheck, privacy, util
from kla.config import Config
from kla.probe import run_row
from kla.stats import fmt, fmt_pct, pct_change, percentile, reliability_note

Echo = Callable[[str], None]


def compare(
    a_name: str,
    a_rows: list[dict[str, Any]],
    b_name: str,
    b_rows: list[dict[str, Any]],
    metrics: list[tuple[str, str]],
) -> list[str]:
    """Markdown table: median and p95 for each arm and the % change from A to B."""
    out = [
        f"| metric | {a_name} median | {b_name} median | change | {a_name} p95 | {b_name} p95 "
        "| change |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for key, label in metrics:
        a = [r[key] for r in a_rows if r.get(key) is not None]
        b = [r[key] for r in b_rows if r.get(key) is not None]
        a50, b50 = percentile(a, 50), percentile(b, 50)
        a95, b95 = percentile(a, 95), percentile(b, 95)
        out.append(
            f"| {label} (ms) | {fmt(a50)} | {fmt(b50)} | {fmt_pct(pct_change(a50, b50))} "
            f"| {fmt(a95)}{reliability_note(len(a), 95)} "
            f"| {fmt(b95)}{reliability_note(len(b), 95)} "
            f"| {fmt_pct(pct_change(a95, b95))} |"
        )
    out.append(
        f"\nn = {len(a_rows)} ({a_name}) and {len(b_rows)} ({b_name}). "
        "`*` = too few samples for a reliable p95."
    )
    return out


def save_report(cfg: Config, name: str, lines: list[str], echo: Echo) -> Path:
    out_dir = cfg.path("reports_dir") / "experiments"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{util.utc_now().strftime('%Y%m%dT%H%M%SZ')}-{name}.md"
    path.write_text("\n".join(lines) + "\n")
    echo("\n".join(lines))
    echo(f"\nsaved {path}")
    return path


def _store(
    cfg: Config,
    kind: str,
    started: Any,
    ctx: context.NetContext,
    table: str,
    rows: list[dict[str, Any]],
    secrets: list[str],
    experiment: str,
) -> str:
    run_id = uuid.uuid4().hex
    conn = db.connect(cfg.db_path)
    with conn:
        db.insert(
            conn,
            "runs",
            privacy.scrub(
                run_row(run_id, kind, started, util.utc_now(), ctx, notes=experiment), secrets
            ),
        )
        netcheck.save(conn, run_id, ctx, cfg.db_path)
        for row in rows:
            db.insert(conn, table, privacy.scrub({**row, "run_id": run_id}, secrets))
    conn.close()
    return run_id


# ----------------------------------------------------------------- reuse


def _sample(arm: str, seq: int, target_id: str, host: str, res: http.HttpResult) -> dict[str, Any]:
    ph = res.phases
    return {
        "ts_utc": util.iso(util.utc_now()),
        "experiment": "reuse",
        "arm": arm,
        "target_id": target_id,
        "host": host,
        "seq": seq,
        "reused": int(arm == "reused" and res.num_connects == 0 and res.ok),
        "dns_ms": ph.dns_ms,
        "tcp_ms": ph.tcp_ms,
        "tls_ms": ph.tls_ms,
        "ttfb_ms": ph.ttfb_ms,
        "total_ms": ph.total_ms if res.ok else None,
        "http_status": res.http_status,
        "http_version": res.http_version,
        "ok": int(res.ok),
        "error_type": res.error_type,
    }


def reuse(
    cfg: Config,
    *,
    n: int = 20,
    target_ids: list[str] | None = None,
    pause_s: float = 0.5,
    echo: Echo = print,
) -> list[dict[str, Any]]:
    """Fresh connection per request vs. one reused connection, per LLM host."""
    targets = [t for t in cfg.targets if (t.id in target_ids if target_ids else t.group == "llm")]
    p = cfg.section("probe")
    opts = {
        "ip_version": int(p.get("ip_version", 4)),
        "http_version": str(p.get("http_version", "1.1")),
        "connect_timeout_s": float(p.get("connect_timeout_s", 10)),
        "total_timeout_s": float(p.get("total_timeout_s", 20)),
        "user_agent": str(p.get("user_agent", "kenya-llm-latency")),
    }
    with util.file_lock(cfg.path("lock_path")):
        started = util.utc_now()
        ctx = context.gather(cfg.section("context"))
        rows: list[dict[str, Any]] = []
        for target in targets:
            echo(f"  {target.id}: {n} fresh + {n} reused requests ...")
            keep = http.CURL_FACTORY()
            keep.setopt(pycurl.SSL_SESSIONID_CACHE, 1)
            http.request(target.url, handle=keep, **opts)  # warm-up: opens the connection
            for i in range(n):
                res = http.request(target.url, **opts)
                rows.append(_sample("fresh", i, target.id, target.host, res))
                time.sleep(pause_s)
                res = http.request(target.url, handle=keep, **opts)
                rows.append(_sample("reused", i, target.id, target.host, res))
                time.sleep(pause_s)
            keep.close()
        _store(
            cfg,
            "experiment",
            started,
            ctx,
            "experiment_samples",
            rows,
            [ctx.public.public_ip or ""],
            "reuse",
        )

    lines = [
        "# Experiment: fresh vs reused connection",
        "",
        f"Run at {util.iso(util.to_eat(started))} EAT on {ctx.conn_type}, "
        f"AS{ctx.public.asn} {ctx.public.as_name}.",
        "",
        "*fresh* = new DNS lookup + TCP + TLS for every request (what our probes measure). "
        "*reused* = the same open HTTP/2 or keep-alive connection, so only the request "
        "itself travels.",
        "",
    ]
    for target in targets:
        a = [r for r in rows if r["target_id"] == target.id and r["arm"] == "fresh"]
        b = [r for r in rows if r["target_id"] == target.id and r["arm"] == "reused"]
        reused_ok = sum(r["reused"] for r in b)
        lines += [
            f"## {target.id} ({target.host})",
            "",
            f"Connection actually reused in {reused_ok}/{len(b)} requests "
            "(the server may close idle connections).",
            "",
        ]
        lines += compare(
            "fresh", a, "reused", b, [("total_ms", "total"), ("ttfb_ms", "server wait")]
        )
        lines.append("")
    save_report(cfg, "reuse", lines, echo)
    return rows


# --------------------------------------------------------- AI experiments


def _ai_pairs(
    cfg: Config,
    provider: str,
    arms: list[tuple[str, ai.ModelChoice, bool]],
    n: int,
    experiment: str,
    echo: Echo,
    pause_s: float = 2.0,
) -> list[dict[str, Any]]:
    keys = ai.load_keys(cfg.root)
    pcfg = ai.providers(cfg).get(provider)
    if pcfg is None:
        raise SystemExit(f"unknown provider {provider!r}; choose from {list(ai.providers(cfg))}")
    key = keys.get(str(pcfg["env_key"]))
    if not key:
        raise SystemExit(
            f"{provider}: no {pcfg['env_key']} in .env, so this experiment is skipped."
        )
    for _, choice, _ in arms:
        ai.assert_free(cfg, choice)
    if not ai.online(cfg):
        raise SystemExit("no network connection, so the experiment was not run.")
    with util.file_lock(cfg.path("lock_path")):
        conn = db.connect(cfg.db_path)
        ok, why = ai.due(conn, cfg, provider, util.utc_now(), scheduled=False, needed=n * len(arms))
        conn.close()
        if not ok:
            raise SystemExit(f"{provider}: not enough budget left ({why}). Try a smaller --n.")
        started = util.utc_now()
        ctx = context.gather(cfg.section("context"))
        rows = []
        for i in range(n):
            for arm, choice, stream in arms:
                row = ai.call_model(cfg, choice, key, stream=stream, experiment=experiment)
                row.update(experiment=experiment, arm=arm)
                rows.append(row)
                echo(
                    f"  {i + 1}/{n} {arm:<10} first visible {row['ttft_visible_ms']} ms"
                    + (f" [{row['error_type']}]" if row["error_type"] else "")
                )
                time.sleep(pause_s)
        _store(
            cfg,
            "experiment",
            started,
            ctx,
            "ai_calls",
            rows,
            [ctx.public.public_ip or "", key],
            experiment,
        )
    return rows


def stream(
    cfg: Config, provider: str, *, n: int = 5, size: str = "small", echo: Echo = print
) -> list[dict[str, Any]]:
    choice = ai.model_choice(cfg, provider, size)
    rows = _ai_pairs(
        cfg, provider, [("nonstream", choice, False), ("stream", choice, True)], n, "stream", echo
    )
    a = [r for r in rows if r["arm"] == "nonstream"]
    b = [r for r in rows if r["arm"] == "stream"]
    lines = [
        "# Experiment: streaming vs non-streaming",
        "",
        f"{provider} / {choice.id}. Metric = time until the first word is visible to a user.",
        "Without streaming that is when the whole answer has arrived.",
        "",
    ]
    lines += compare(
        "non-stream",
        a,
        "stream",
        b,
        [("ttft_visible_ms", "first visible word"), ("total_ms", "total")],
    )
    save_report(cfg, f"stream-{provider}", lines, echo)
    return rows


def model_size(
    cfg: Config, provider: str, *, n: int = 5, echo: Echo = print
) -> list[dict[str, Any]]:
    try:
        small = ai.model_choice(cfg, provider, "small")
        large = ai.model_choice(cfg, provider, "large")
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"model-size: {exc}") from None
    rows = _ai_pairs(
        cfg, provider, [("small", small, True), ("large", large, True)], n, "model-size", echo
    )
    a = [r for r in rows if r["arm"] == "small"]
    b = [r for r in rows if r["arm"] == "large"]
    lines = [
        "# Experiment: small vs larger model",
        "",
        f"{provider}: small = {small.id}, large = {large.id} (both streaming).",
        "",
    ]
    lines += compare(
        "small",
        a,
        "large",
        b,
        [
            ("ttft_visible_ms", "first visible token"),
            ("ttft_any_ms", "first token (any)"),
            ("total_ms", "total"),
        ],
    )
    save_report(cfg, f"model-size-{provider}", lines, echo)
    return rows


# ---------------------------------------------------------------- region


def region(cfg: Config, *, echo: Echo = print) -> list[str]:
    """Near (Africa) vs far (Europe, US) cloud regions, from stored Part 1 probes."""
    conn = db.connect(cfg.db_path)
    rows = db.fetch(
        conn,
        "SELECT provider, region, geo, tcp_ms, ttfb_ms, total_ms, ok "
        "FROM probes WHERE grp = 'cloud'",
    )
    conn.close()
    if not rows:
        raise SystemExit("no Part 1 cloud probes yet - run `kla probe` (or start the timers) first")
    lines = [
        "# Experiment: near vs far cloud region (from Part 1 data)",
        "",
        "TCP connect ≈ one network round trip to the region. "
        "% change is relative to the Africa region of the same cloud.",
        "",
        "| cloud | region | geo | n | TCP p50 | TCP p95 | total p50 | total p95 | TCP vs Africa "
        "| total vs Africa |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for provider in sorted({r["provider"] for r in rows}):
        mine = [r for r in rows if r["provider"] == provider and r["ok"]]
        africa = [r for r in mine if r["geo"] == "africa"]
        base_tcp = percentile([r["tcp_ms"] for r in africa], 50)
        base_total = percentile([r["total_ms"] for r in africa], 50)
        for geo in ("africa", "europe", "us"):
            sel = [r for r in mine if r["geo"] == geo]
            if not sel:
                continue
            tcp = [r["tcp_ms"] for r in sel]
            tot = [r["total_ms"] for r in sel]
            t50, tot50 = percentile(tcp, 50), percentile(tot, 50)
            lines.append(
                f"| {provider} | {sel[0]['region']} | {geo} | {len(sel)} | {fmt(t50)} "
                f"| {fmt(percentile(tcp, 95))}{reliability_note(len(sel), 95)} | {fmt(tot50)} "
                f"| {fmt(percentile(tot, 95))}{reliability_note(len(sel), 95)} "
                f"| {fmt_pct(pct_change(base_tcp, t50))} "
                f"| {fmt_pct(pct_change(base_total, tot50))} |"
            )
    lines.append("\n`*` = too few samples for a reliable p95.")
    save_report(cfg, "region", lines, echo)
    return lines
