"""Part 1: one probe run = context + one fresh request to every target."""

from __future__ import annotations

import ipaddress
import random
import time
import uuid
from collections.abc import Callable
from typing import Any

from kla import __version__, context, db, dnsprobe, gaps, http, netcheck, pinger, privacy, util
from kla.config import Config, Target


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def probe_target(target: Target, cfg: Config, servers: list[str]) -> dict[str, Any]:
    """Measure one target: DNS (two ways), then one fresh HTTPS request with the IP pinned."""
    p = cfg.section("probe")
    dns_cfg = cfg.section("dns")
    row: dict[str, Any] = {
        "ts_utc": util.iso(util.utc_now()),
        "target_id": target.id,
        "host": target.host,
        "grp": target.group,
        "provider": target.provider,
        "region": target.region,
        "geo": target.geo,
        "ip_version": int(p.get("ip_version", 4)),
    }
    pin_ip: str | None = None
    dns_ms: float | None = None
    if is_ip_literal(target.host):
        row["dns_used"] = "none (ip literal)"
        dns_ms = 0.0
    else:
        direct = dnsprobe.direct_lookup(target.host, servers, float(dns_cfg.get("timeout_s", 5)))
        system = dnsprobe.system_lookup(target.host)
        row.update(
            dns_direct_ms=direct.ms,
            dns_direct_server=direct.server,
            dns_direct_ttl=direct.ttl,
            dns_direct_error=direct.error,
            dns_system_ms=system.ms,
            dns_system_error=system.error,
        )
        if direct.ips:
            pin_ip, dns_ms, row["dns_used"] = direct.ips[0], direct.ms, "direct"
        elif system.ips:
            pin_ip, dns_ms, row["dns_used"] = system.ips[0], system.ms, "system"
        else:
            row["dns_used"] = "failed"

    if pin_ip is None and row["dns_used"] == "failed":
        # Both lookups failed: record the failure without sending a request.
        row.update(ok=0, error_type="dns_failure", error_msg=row.get("dns_direct_error"))
        return row

    res = http.request(
        target.url,
        resolve_ip=pin_ip,
        ip_version=int(p.get("ip_version", 4)),
        http_version=str(p.get("http_version", "1.1")),
        connect_timeout_s=float(p.get("connect_timeout_s", 10)),
        total_timeout_s=float(p.get("total_timeout_s", 20)),
        user_agent=str(p.get("user_agent", "kenya-llm-latency")),
        max_body_bytes=int(p.get("max_body_bytes", 262_144)),
    )
    ph = res.phases
    total = None
    if ph.total_ms is not None and dns_ms is not None:
        total = round(ph.total_ms + dns_ms, 3)
    row.update(
        curl_dns_ms=ph.dns_ms,
        tcp_ms=ph.tcp_ms,
        tls_ms=ph.tls_ms,
        ttfb_ms=ph.ttfb_ms,
        transfer_ms=ph.transfer_ms,
        curl_total_ms=ph.total_ms,
        total_ms=total if res.ok else None,
        http_status=res.http_status,
        http_version=res.http_version,
        tls_version=res.tls_version,
        tls_cipher=res.tls_cipher,
        alpn=res.alpn,
        remote_ip=res.remote_ip,
        edge_pop=res.edge_pop,
        edge_source=res.edge_source,
        server_header=res.headers.get("server"),
        alt_svc_h3=int("h3" in res.headers.get("alt-svc", "")),
        size_bytes=res.size_bytes,
        ok=int(res.ok),
        error_type=res.error_type,
        error_code=res.error_code,
        error_msg=res.error_msg,
    )
    return row


def ping_after_probe(row: dict[str, Any], ping_cfg: dict[str, Any]) -> dict[str, Any]:
    """Light ping to the IP the probe just connected to. Never raises."""
    base = {"ts_utc": util.iso(util.utc_now()), "target_id": row["target_id"], "seq": row["seq"]}
    try:
        result = pinger.ping_ip(
            row.get("remote_ip"),
            count=int(ping_cfg.get("count", 3)),
            deadline_s=float(ping_cfg.get("deadline_s", 3)),
        )
    except Exception as exc:  # the ping must never cost us the probe data
        result = {"ip": row.get("remote_ip"), "status": "error", "error_msg": repr(exc)[:200]}
    return {**base, **result}


def run_row(
    run_id: str, kind: str, started: Any, finished: Any, ctx: context.NetContext, **extra: Any
) -> dict[str, Any]:
    eat = util.to_eat(started)
    row = {
        "run_id": run_id,
        "kind": kind,
        "started_utc": util.iso(started),
        "started_eat": util.iso(eat),
        "finished_utc": util.iso(finished),
        "hour_eat": eat.hour,
        "weekday_eat": eat.weekday(),
        "tool_version": __version__,
        **ctx.to_row(),
    }
    row.update(extra)
    return row


def run_probe(cfg: Config, *, echo: Callable[[str], None] = print) -> dict[str, Any]:
    """Run Part 1 once and store the results. Returns a small summary."""
    p = cfg.section("probe")
    with util.file_lock(cfg.path("lock_path")):
        started = util.utc_now()
        ctx = context.gather(cfg.section("context"))
        conn = db.connect(cfg.db_path)
        gap = gaps.detect(
            conn,
            started,
            ctx.boot_id,
            ctx.suspended_total_s,
            float(p.get("gap_threshold_minutes", 25)),
        )
        servers = dnsprobe.upstream_servers(cfg.section("dns").get("direct_servers", "auto"))
        targets = list(cfg.targets)
        if p.get("shuffle_targets", True):
            random.shuffle(targets)
        rows = []
        pings = []
        ping_cfg = cfg.section("ping")
        for seq, target in enumerate(targets):
            try:
                row = probe_target(target, cfg, servers)
            except Exception as exc:  # a bug in one probe must not lose the whole run
                row = {
                    "ts_utc": util.iso(util.utc_now()),
                    "target_id": target.id,
                    "host": target.host,
                    "grp": target.group,
                    "provider": target.provider,
                    "region": target.region,
                    "geo": target.geo,
                    "ok": 0,
                    "error_type": "internal_error",
                    "error_msg": repr(exc)[:300],
                }
            row["seq"] = seq
            rows.append(row)
            if ping_cfg.get("enabled", True):
                pings.append(ping_after_probe(row, ping_cfg))
            time.sleep(float(p.get("pause_between_targets_s", 0.3)))
        finished = util.utc_now()

        run_id = uuid.uuid4().hex
        secrets = [ctx.public.public_ip or ""]
        run = run_row(
            run_id,
            "probe",
            started,
            finished,
            ctx,
            dns_servers=",".join(servers),
            after_gap=int(gap is not None),
        )
        with conn:  # one transaction: a run and its probes are saved together or not at all
            db.insert(conn, "runs", privacy.scrub(run, secrets))
            changed = netcheck.save(conn, run_id, ctx, cfg.db_path)
            for row in rows:
                db.insert(conn, "probes", privacy.scrub({**row, "run_id": run_id}, secrets))
            for ping in pings:
                db.insert(conn, "pings", privacy.scrub({**ping, "run_id": run_id}, secrets))
            if gap:
                db.insert(conn, "gaps", gap)
        conn.close()

    ok = sum(r["ok"] for r in rows)
    echo(
        f"probe run {run_id[:8]} saved: {ok}/{len(rows)} targets answered | "
        f"{ctx.conn_type} | AS{ctx.public.asn} {ctx.public.as_name} | "
        f"router {ctx.router_rtt_ms} ms"
        + (
            f" | ping replies {sum(g['status'] == 'ok' for g in pings)}/{len(pings)}"
            if pings
            else ""
        )
        + (f" | GAP {gap['gap_minutes']} min ({gap['cause']})" if gap else "")
        + (" | WARNING: VPN active" if ctx.vpn_active else "")
        + (f" | WARNING: network changed mid-run ({'; '.join(changed)})" if changed else "")
    )
    return {
        "run_id": run_id,
        "rows": rows,
        "pings": pings,
        "context": ctx,
        "gap": gap,
        "changed": changed,
    }
