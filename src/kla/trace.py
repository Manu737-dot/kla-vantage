"""Hourly route tracing with mtr: which networks and cities does my traffic cross?

mtr sends packets with increasing TTL ("time to live") so each router on the
path reports back. For each hop we keep its hostname, network (ASN), packet
loss and round-trip time. Private hops and anything that reveals my own IP
are masked before saving.
"""

from __future__ import annotations

import itertools
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from kla import context, db, dnsprobe, netcheck, privacy, util
from kla.config import Config
from kla.probe import is_ip_literal, run_row

# Airport / city codes that network operators put in router names, e.g.
# ae-1.cr-01-nbo.ke.seacomnet.com (Nairobi) or ae-3.r20.mrslfr02.fr.bb.gin.ntt.net
# (Marseille). These are HINTS: operators are not consistent, so they are always
# labelled as unverified.
CITY_HINTS: dict[str, str] = {
    # East & southern Africa
    "nbo": "Nairobi, KE",
    "nairobi": "Nairobi, KE",
    "mba": "Mombasa, KE",
    "mombasa": "Mombasa, KE",
    "dar": "Dar es Salaam, TZ",
    "ebb": "Kampala, UG",
    "kla": "Kampala, UG",
    "kgl": "Kigali, RW",
    "jnb": "Johannesburg, ZA",
    "jhb": "Johannesburg, ZA",
    "johannesburg": "Johannesburg, ZA",
    "cpt": "Cape Town, ZA",
    "capetown": "Cape Town, ZA",
    "djb": "Djibouti, DJ",
    "jib": "Djibouti, DJ",
    "djibouti": "Djibouti, DJ",
    "los": "Lagos, NG",
    "lagos": "Lagos, NG",
    "acc": "Accra, GH",
    "cai": "Cairo, EG",
    # Middle East / Asia (subsea cable landings)
    "fjr": "Fujairah, AE",
    "dxb": "Dubai, AE",
    "dubai": "Dubai, AE",
    "jed": "Jeddah, SA",
    "mct": "Muscat, OM",
    "bom": "Mumbai, IN",
    "mum": "Mumbai, IN",
    "mumbai": "Mumbai, IN",
    "sin": "Singapore, SG",
    "hkg": "Hong Kong, HK",
    # Europe
    "mrs": "Marseille, FR",
    "mrslfr": "Marseille, FR",
    "marseille": "Marseille, FR",
    "par": "Paris, FR",
    "parfr": "Paris, FR",
    "cdg": "Paris, FR",
    "paris": "Paris, FR",
    "fra": "Frankfurt, DE",
    "ffm": "Frankfurt, DE",
    "frankfurt": "Frankfurt, DE",
    "lon": "London, GB",
    "lhr": "London, GB",
    "ldn": "London, GB",
    "london": "London, GB",
    "ams": "Amsterdam, NL",
    "amsterdam": "Amsterdam, NL",
    "amsnl": "Amsterdam, NL",
    "mad": "Madrid, ES",
    "lis": "Lisbon, PT",
    "mil": "Milan, IT",
    "mxp": "Milan, IT",
    "zrh": "Zurich, CH",
    "vie": "Vienna, AT",
    "otp": "Bucharest, RO",
    "sof": "Sofia, BG",
    "dub": "Dublin, IE",
    "dublin": "Dublin, IE",
    "bru": "Brussels, BE",
    "arn": "Stockholm, SE",
    # North America
    "iad": "Ashburn, US",
    "ash": "Ashburn, US",
    "ashburn": "Ashburn, US",
    "wdc": "Washington DC, US",
    "nyc": "New York, US",
    "jfk": "New York, US",
    "ewr": "Newark, US",
    "atl": "Atlanta, US",
    "mia": "Miami, US",
    "dfw": "Dallas, US",
    "chi": "Chicago, US",
    "ord": "Chicago, US",
    "lax": "Los Angeles, US",
    "sjc": "San Jose, US",
    "sfo": "San Francisco, US",
    "sea": "Seattle, US",
    "yul": "Montreal, CA",
    "yyz": "Toronto, CA",
}


@dataclass
class Hop:
    n: int
    hostname: str | None
    ip: str | None
    asn: str | None
    loss_pct: float | None
    sent: int | None
    best_ms: float | None
    avg_ms: float | None
    worst_ms: float | None
    stdev_ms: float | None
    hint: str | None = None


def split_host(raw: str) -> tuple[str | None, str | None]:
    """mtr prints 'name (1.2.3.4)', '1.2.3.4' or '???' (no reply)."""
    raw = raw.strip()
    if raw in ("", "???"):
        return None, None
    m = re.match(r"^(.*?) \(([0-9a-fA-F:.]+)\)$", raw)
    if m:
        return m.group(1), m.group(2)
    if is_ip_literal(raw):
        return None, raw
    return raw, None


def location_hint(hostname: str | None) -> str | None:
    if not hostname:
        return None
    for token in re.split(r"[.\-_]", hostname.lower()):
        letters = re.sub(r"\d+", "", token)
        if letters in CITY_HINTS:
            return CITY_HINTS[letters]
    return None


def parse_mtr_json(text: str) -> list[Hop]:
    hubs = json.loads(text)["report"]["hubs"]
    hops = []
    for hub in hubs:
        hostname, ip = split_host(str(hub.get("host", "")))
        asn = hub.get("ASN")
        hops.append(
            Hop(
                n=int(hub.get("count", 0)),
                hostname=hostname,
                ip=ip,
                asn=None if asn in (None, "AS???") else str(asn),
                loss_pct=_f(hub.get("Loss%")),
                sent=hub.get("Snt"),
                best_ms=_f(hub.get("Best")),
                avg_ms=_f(hub.get("Avg")),
                worst_ms=_f(hub.get("Wrst")),
                stdev_ms=_f(hub.get("StDev")),
            )
        )
    return hops


def mask_hops(hops: list[Hop], public_ip: str | None) -> list[Hop]:
    """Hide anything that identifies my home: private hops and my public IP."""
    masked = []
    for hop in hops:
        h = Hop(**asdict(hop))
        # Checked first: a hop that reveals my IP is masked even if it also looks private.
        if public_ip and (
            h.ip == public_ip
            or (h.hostname and any(v in h.hostname for v in privacy.ip_variants(public_ip)))
        ):
            h.hostname, h.ip = "your-connection", "masked"
        elif h.ip and privacy.is_private(h.ip):
            h.hostname, h.ip = "private-hop", "private"
        h.hint = location_hint(h.hostname)
        masked.append(h)
    return masked


def summarize(hops: list[Hop], dest_ip: str | None) -> dict[str, Any]:
    responding = [h for h in hops if h.best_ms is not None and (h.loss_pct or 0) < 100 and h.ip]
    last = hops[-1] if hops else None
    jump, jump_from, jump_to = None, None, None
    for a, b in itertools.pairwise(responding):
        delta = (b.best_ms or 0) - (a.best_ms or 0)
        if jump is None or delta > jump:
            jump, jump_from, jump_to = delta, a, b
    as_path: list[str] = []
    for h in hops:
        if h.asn and (not as_path or as_path[-1] != h.asn):
            as_path.append(h.asn)
    hints: list[str] = []
    for h in hops:
        if h.hint and h.hint not in hints:
            hints.append(h.hint)

    def label(h: Hop | None) -> str | None:
        if h is None:
            return None
        return f"hop {h.n} {h.hostname or h.ip}" + (f" [{h.hint}?]" if h.hint else "")

    return {
        "hop_count": len(hops),
        "reached": int(bool(last and dest_ip and last.ip == dest_ip)),
        "dest_rtt_ms": last.best_ms if last else None,
        "dest_loss_pct": last.loss_pct if last else None,
        "biggest_jump_ms": round(jump, 1) if jump is not None else None,
        "biggest_jump_from": label(jump_from),
        "biggest_jump_to": label(jump_to),
        "as_path": " > ".join(as_path),
        "location_hints": " > ".join(hints),
    }


def named_as_path(as_path: str, cache: dict[str, str | None]) -> str:
    """'AS37100 > AS13335' -> 'AS37100 SEACOM > AS13335 CLOUDFLARENET' (names via Team Cymru)."""
    parts = []
    for asn in filter(None, as_path.split(" > ")):
        num = asn.removeprefix("AS")
        if asn not in cache:
            cache[asn] = context.asn_name_from_cymru(int(num)) if num.isdigit() else None
        name = (cache[asn] or "").split(" - ")[0].split(",")[0].strip()
        parts.append(f"{asn} {name}".strip())
    return " > ".join(parts)


def trace_one(host: str, cfg: Config) -> tuple[str | None, util.CmdResult, list[str]]:
    t = cfg.section("trace")
    resolved = dnsprobe.system_lookup(host)
    dest_ip = resolved.ips[0] if resolved.ips else None
    args = [
        "mtr",
        "--json",
        "-z",
        "-b",
        "-c",
        str(int(t.get("cycles", 5))),
        "-m",
        str(int(t.get("max_hops", 30))),
        dest_ip or host,
    ]
    return dest_ip, util.run_cmd(args, timeout=float(t.get("timeout_s", 90))), args


def run_traces(cfg: Config, *, echo: Callable[[str], None] = print) -> dict[str, Any]:
    t = cfg.section("trace")
    targets = cfg.targets_in(list(t.get("groups") or ["llm"]))
    with util.file_lock(cfg.path("lock_path")):
        started = util.utc_now()
        ctx = context.gather(cfg.section("context"))
        public_ip = ctx.public.public_ip
        asn_cache: dict[str, str | None] = {}
        rows = []
        for target in targets:
            row: dict[str, Any] = {
                "ts_utc": util.iso(util.utc_now()),
                "target_id": target.id,
                "host": target.host,
            }
            dest_ip, res, args = trace_one(target.host, cfg)
            row["dest_ip"] = dest_ip
            row["mtr_args"] = " ".join(args[:-1])  # without the destination
            if not res.ok:
                row.update(
                    ok=0, error_type="mtr_failed", error_msg=(res.stderr or res.stdout)[:300]
                )
                rows.append(row)
                continue
            try:
                hops = mask_hops(parse_mtr_json(res.stdout), public_ip)
            except (ValueError, KeyError, TypeError) as exc:
                row.update(ok=0, error_type="mtr_parse_error", error_msg=repr(exc)[:300])
                rows.append(row)
                continue
            summary = summarize(hops, dest_ip)
            summary["as_path"] = named_as_path(summary["as_path"], asn_cache)
            row.update(summary)
            row.update(ok=1, hops_json=json.dumps([asdict(h) for h in hops]))
            rows.append(row)
        finished = util.utc_now()
        run_id = uuid.uuid4().hex
        secrets = [public_ip or ""]
        conn = db.connect(cfg.db_path)
        with conn:
            db.insert(
                conn,
                "runs",
                privacy.scrub(run_row(run_id, "trace", started, finished, ctx), secrets),
            )
            changed = netcheck.save(conn, run_id, ctx, cfg.db_path)
            for row in rows:
                db.insert(conn, "traces", privacy.scrub({**row, "run_id": run_id}, secrets))
        conn.close()
    for row in rows:
        if row.get("ok"):
            echo(
                f"  {row['target_id']:<11} {row['hop_count']:>2} hops, "
                f"{row.get('dest_rtt_ms')} ms | {row.get('location_hints') or '-'} "
                f"| {row['as_path']}"
            )
        else:
            echo(f"  {row['target_id']:<11} FAILED: {row.get('error_type')}")
    echo(
        f"trace run {run_id[:8]} saved: {sum(r.get('ok', 0) for r in rows)}/{len(rows)} routes"
        + (" | WARNING: VPN active" if ctx.vpn_active else "")
        + (f" | WARNING: network changed mid-run ({'; '.join(changed)})" if changed else "")
    )
    return {"run_id": run_id, "rows": rows}


def _f(value: Any) -> float | None:
    try:
        return round(float(value), 3)
    except (TypeError, ValueError):
        return None
