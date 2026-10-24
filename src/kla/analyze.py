"""Turn the SQLite data into a markdown report (numbers only) and PNG charts."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # render to files; no screen needed (works under systemd too)
import matplotlib.pyplot as plt

from kla import db, gaps, networks, steering, util
from kla.config import Config
from kla.stats import fmt, percentile, reliability_note, summary

# Validated categorical palette (fixed order; checked for colour-blind separation).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
SURFACE, INK, INK_2, MUTED, GRID, BASELINE = (
    "#fcfcfb",
    "#0b0b0b",
    "#52514e",
    "#898781",
    "#e1e0d9",
    "#c3c2b7",
)
GEO_COLOR = {"africa": SERIES[0], "europe": SERIES[1], "us": SERIES[2]}
GEO_LABEL = {"africa": "Africa", "europe": "Europe", "us": "US"}

PHASES = [
    ("dns_direct_ms", "DNS (direct to router)"),
    ("dns_system_ms", "DNS (system, may be cached)"),
    ("tcp_ms", "TCP connect"),
    ("tls_ms", "TLS handshake"),
    ("ttfb_ms", "Server wait (TTFB)"),
    ("total_ms", "Total, fresh connection"),
]
STACK = [
    ("dns_direct_ms", "DNS"),
    ("tcp_ms", "TCP connect"),
    ("tls_ms", "TLS handshake"),
    ("ttfb_ms", "Server wait"),
    ("transfer_ms", "Download"),
]

Echo = Callable[[str], None]


def _style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "font.family": "sans-serif",
            "font.size": 10,
            "text.color": INK,
            "axes.labelcolor": INK_2,
            "axes.titlecolor": INK,
            "axes.titlesize": 12,
            "axes.titleweight": "bold",
            "axes.titlelocation": "left",
            "xtick.color": MUTED,
            "ytick.color": INK_2,
            "axes.edgecolor": BASELINE,
            "axes.linewidth": 1,
            "axes.grid": True,
            "grid.color": GRID,
            "grid.linewidth": 0.8,
            "grid.linestyle": "-",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.left": False,
            "legend.frameon": False,
            "legend.fontsize": 9,
            "lines.linewidth": 2,
            "lines.solid_capstyle": "round",
        }
    )


# ------------------------------------------------------------------ load


MEASURED = ("runs", "probes", "traces", "ai", "pings")


def load(cfg: Config, since_days: float | None) -> dict[str, Any]:
    """Every row in the period, plus each run's network (no filtering yet; see select)."""
    conn = db.connect(cfg.db_path)
    since = util.iso(util.utc_now() - timedelta(days=since_days)) if since_days else ""
    data: dict[str, Any] = {
        "runs": db.fetch(
            conn, "SELECT * FROM runs WHERE started_utc >= ? ORDER BY started_utc", (since,)
        ),
        "probes": db.fetch(
            conn,
            "SELECT p.*, r.hour_eat, r.conn_type, r.vpn_active, r.router_rtt_ms, r.asn, r.as_name "
            "FROM probes p JOIN runs r USING (run_id) WHERE p.ts_utc >= ?",
            (since,),
        ),
        "traces": db.fetch(
            conn,
            "SELECT t.* FROM traces t JOIN runs r USING (run_id) WHERE t.ts_utc >= ?",
            (since,),
        ),
        "ai": ai_on_one_clock(
            db.fetch(
                conn,
                "SELECT a.*, r.hour_eat, r.conn_type, r.tool_version "
                "FROM ai_calls a JOIN runs r USING (run_id) WHERE a.ts_utc >= ?",
                (since,),
            )
        ),
        "gaps": db.fetch(
            conn, "SELECT * FROM gaps WHERE this_run_utc >= ? ORDER BY this_run_utc", (since,)
        ),
        "pings": db.fetch(
            conn,
            "SELECT g.*, r.tool_version FROM pings g JOIN runs r USING (run_id) "
            "WHERE g.ts_utc >= ?",
            (since,),
        ),
    }
    # Networks are worked out over all runs: old runs borrow their router
    # address from neighbouring runs, which may fall outside the period.
    all_runs, checks, labels = networks.load_all(conn)
    conn.close()
    data["nets"] = networks.assign(all_runs, checks, labels)
    data["labels"] = labels
    return data


def select(
    data: dict[str, Any],
    *,
    include_vpn: bool = False,
    include_mixed: bool = False,
    include_offline: bool = False,
    network: str | None = None,
) -> dict[str, Any]:
    """Keep the runs a comparison should use, and tag every row with its network.

    Left out by default: runs made through a VPN (they measure the VPN), runs
    where the network changed mid-run (they measure two networks at once), and
    runs made with no network connection at all (they measure the laptop being
    offline, not the providers).
    """
    nets: dict[str, networks.RunNet] = data["nets"]
    offline = {r["run_id"] for r in data["runs"] if is_offline(r)}

    def keep(run_id: str) -> bool:
        if run_id in offline and not include_offline:
            return False
        n = nets.get(run_id)
        if n is None:
            return True
        if (n.vpn and not include_vpn) or (n.mixed and not include_mixed):
            return False
        return network is None or n.network == network

    out: dict[str, Any] = {
        key: [
            {**r, "network": nets[r["run_id"]].network if r["run_id"] in nets else "unknown"}
            for r in data[key]
            if keep(r["run_id"])
        ]
        for key in MEASURED
    }
    out.update(
        gaps=data["gaps"],
        all_runs=data["runs"],
        nets=nets,
        labels=data["labels"],
        network=network,
        include_vpn=include_vpn,
        include_mixed=include_mixed,
        include_offline=include_offline,
    )
    return out


def is_offline(run: dict[str, Any]) -> bool:
    """No network route at all when the run started (Wi-Fi off, router gone)."""
    return run.get("conn_type") == "none"


def offline_spans(probe_runs: list[dict[str, Any]]) -> list[str]:
    """Consecutive offline probe runs as 'DD Mon HH:MM–HH:MM' (EAT)."""
    spans: list[list[dict[str, Any]]] = []
    prev_offline = False
    for r in probe_runs:
        if is_offline(r):
            if prev_offline:
                spans[-1].append(r)
            else:
                spans.append([r])
        prev_offline = is_offline(r)
    out = []
    for span in spans:
        a, b = (
            util.to_eat(util.parse_iso(span[0]["started_utc"])),
            util.to_eat(util.parse_iso(span[-1]["started_utc"])),
        )
        out.append(a.strftime("%d %b %H:%M") + ("" if a == b else b.strftime("–%H:%M")))
    return out


def available_networks(data: dict[str, Any]) -> list[str]:
    """Networks with at least one usable probe run, in order of first appearance."""
    return list(dict.fromkeys(r["network"] for r in data["runs"] if r["kind"] == "probe"))


def network_names(
    cfg: Config,
    since_days: float | None = None,
    include_vpn: bool = False,
    include_mixed: bool = False,
    include_offline: bool = False,
) -> list[str]:
    data = select(
        load(cfg, since_days),
        include_vpn=include_vpn,
        include_mixed=include_mixed,
        include_offline=include_offline,
    )
    return available_networks(data)


# --------------------------------------------------------------- tables


def _by(rows: list[dict[str, Any]], key: str) -> dict[Any, list[dict[str, Any]]]:
    out: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        out[r[key]].append(r)
    return out


def _target_order(cfg: Config) -> list[str]:
    return [t.id for t in cfg.targets]


def phase_tables(cfg: Config, probes: list[dict[str, Any]]) -> list[str]:
    by_target = _by(probes, "target_id")
    order = [t for t in _target_order(cfg) if t in by_target]
    out = []
    for key, label in PHASES:
        out += [
            f"### {label} (ms)",
            "",
            "| target | group | n | p50 | p95 | p99 | failure rate |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
        for tid in order:
            rows = by_target[tid]
            ok_rows = [r for r in rows if r["ok"]]
            s = summary(r[key] for r in ok_rows)
            fail = 1 - len(ok_rows) / len(rows) if rows else 0
            n = int(s["n"] or 0)
            out.append(
                f"| {tid} | {rows[0]['grp']} | {n} | {fmt(s['p50'])} "
                f"| {fmt(s['p95'])}{reliability_note(n, 95)} "
                f"| {fmt(s['p99'])}{reliability_note(n, 99)} "
                f"| {fail:.1%} |"
            )
        out.append("")
    return out


def failure_table(probes: list[dict[str, Any]]) -> list[str]:
    failed = [r for r in probes if not r["ok"]]
    if not failed:
        return ["No failed probes in this period.", ""]
    out = ["| target | error type | count |", "|---|---|---:|"]
    for (tid, err), count in Counter(
        (r["target_id"], r["error_type"]) for r in failed
    ).most_common():
        out.append(f"| {tid} | {err} | {count} |")
    return [*out, ""]


def retransmit_table(probes: list[dict[str, Any]]) -> list[str]:
    """Handshakes that took over 1 s although the usual round trip is far shorter.

    Linux resends a lost connection packet (SYN) after 1 s, and a lost TLS
    packet after a similar timeout, so a TCP or TLS step of >= 1,000 ms on a
    ~10-250 ms path is very likely a lost packet that had to be resent. This is
    an inference from the timing, not a direct packet capture.
    """
    out = [
        "| target | n | TCP ≥ 1 s | TLS ≥ 1 s | share of requests | TCP p50 for comparison |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    any_rows = False
    for tid, rows in _by([r for r in probes if r["ok"]], "target_id").items():
        tcp_slow = sum(1 for r in rows if (r["tcp_ms"] or 0) >= 1000)
        tls_slow = sum(1 for r in rows if (r["tls_ms"] or 0) >= 1000)
        if not (tcp_slow or tls_slow):
            continue
        any_rows = True
        share = (tcp_slow + tls_slow) / len(rows)
        out.append(
            f"| {tid} | {len(rows)} | {tcp_slow} | {tls_slow} | {share:.1%} "
            f"| {fmt(percentile([r['tcp_ms'] for r in rows], 50))} |"
        )
    if not any_rows:
        return ["No handshakes of 1 s or more in this period.", ""]
    return [*out, ""]


def hourly_table(probes: list[dict[str, Any]], runs: list[dict[str, Any]]) -> list[str]:
    out = [
        "| hour (EAT) | LLM total p50 | LLM n | local total p50 | local n | router ping p50 |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    probe_runs = [r for r in runs if r["kind"] == "probe"]
    for hour in range(24):
        llm = [
            r["total_ms"] for r in probes if r["hour_eat"] == hour and r["grp"] == "llm" and r["ok"]
        ]
        loc = [
            r["total_ms"]
            for r in probes
            if r["hour_eat"] == hour and r["grp"] == "local" and r["ok"]
        ]
        router = [r["router_rtt_ms"] for r in probe_runs if r["hour_eat"] == hour]
        if not (llm or loc or router):
            continue
        out.append(
            f"| {hour:02d}:00 | {fmt(percentile(llm, 50))} | {len(llm)} "
            f"| {fmt(percentile(loc, 50))} | {len(loc)} | {fmt(percentile(router, 50), 1)} |"
        )
    return [*out, ""]


def conn_table(probes: list[dict[str, Any]], runs: list[dict[str, Any]]) -> list[str]:
    probe_runs = [r for r in runs if r["kind"] == "probe"]
    types = sorted({r["conn_type"] or "unknown" for r in probe_runs})
    out = [
        "| connection | runs | LLM TCP p50 | LLM total p50 | LLM total p95 | router ping p50 "
        "| failure rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for ct in types:
        runs_ct = [r for r in probe_runs if (r["conn_type"] or "unknown") == ct]
        llm = [r for r in probes if (r["conn_type"] or "unknown") == ct and r["grp"] == "llm"]
        ok = [r for r in llm if r["ok"]]
        fail = 1 - len(ok) / len(llm) if llm else 0
        out.append(
            f"| {ct} | {len(runs_ct)} | {fmt(percentile([r['tcp_ms'] for r in ok], 50))} "
            f"| {fmt(percentile([r['total_ms'] for r in ok], 50))} "
            f"| {fmt(percentile([r['total_ms'] for r in ok], 95))}{reliability_note(len(ok), 95)} "
            f"| {fmt(percentile([r['router_rtt_ms'] for r in runs_ct], 50), 1)} | {fail:.1%} |"
        )
    if len(types) < 2:
        out.append(
            "\nOnly one connection type was observed, so no Wi-Fi vs mobile comparison is possible "
            "yet."
        )
    return [*out, ""]


def region_table(probes: list[dict[str, Any]]) -> list[str]:
    cloud = [r for r in probes if r["grp"] == "cloud" and r["ok"]]
    out = [
        "| cloud | region | geo | n | TCP connect p50 | TCP p95 | server wait p50 | total p50 |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for (prov, region, geo), rows in sorted(
        _by_tuple(cloud, ("provider", "region", "geo")).items()
    ):
        out.append(
            f"| {prov} | {region} | {geo} | {len(rows)} "
            f"| {fmt(percentile([r['tcp_ms'] for r in rows], 50))} "
            "| "
            f"{fmt(percentile([r['tcp_ms'] for r in rows], 95))}{reliability_note(len(rows), 95)} "
            f"| {fmt(percentile([r['ttfb_ms'] for r in rows], 50))} "
            f"| {fmt(percentile([r['total_ms'] for r in rows], 50))} |"
        )
    return [*out, ""]


def edge_table(probes: list[dict[str, Any]]) -> list[str]:
    llm = [r for r in probes if r["grp"] in ("llm", "local") and r["ok"]]
    out = [
        "| target | edge city codes seen (count) | server header | HTTP | TLS |",
        "|---|---|---|---|---|",
    ]
    for tid, rows in _by(llm, "target_id").items():
        pops = Counter(f"{r['edge_pop']} ({r['edge_source']})" for r in rows if r["edge_pop"])
        servers = Counter(r["server_header"] for r in rows if r["server_header"])
        https = Counter(r["http_version"] for r in rows if r["http_version"])
        tls = Counter(r["tls_version"] for r in rows if r["tls_version"])
        out.append(
            f"| {tid} | {', '.join(f'{k} ×{v}' for k, v in pops.most_common(4)) or 'not exposed'} "
            f"| {servers.most_common(1)[0][0] if servers else '–'} "
            f"| {'/'.join(sorted(https))} | {'/'.join(sorted(tls))} |"
        )
    return [*out, ""]


def route_table(traces: list[dict[str, Any]], probes: list[dict[str, Any]]) -> list[str]:
    """Route summary. Also puts the traceroute (ICMP) round trip next to the TCP
    connect time from the probes: if ping says 10 ms but TCP takes 150 ms, the
    host answering pings is not the one accepting connections."""
    if not traces:
        return ["No traceroutes yet (they run hourly).", ""]
    tcp_by_target = _by([r for r in probes if r["ok"]], "target_id")
    out = [
        "| target | traces | hops p50 | ping RTT to last hop p50 | TCP connect p50 (probes) "
        "| most common network path | city hints (unverified) | biggest RTT jump (most common) |",
        "|---|---:|---:|---:|---:|---|---|---|",
    ]
    for tid, rows in _by(traces, "target_id").items():
        ok = [r for r in rows if r["ok"]]
        if not ok:
            out.append(f"| {tid} | {len(rows)} | – | – | – | all traces failed | – | – |")
            continue
        path = Counter(r["as_path"] for r in ok).most_common(1)[0][0]
        hints = Counter(r["location_hints"] for r in ok if r["location_hints"]).most_common(1)
        jumps = Counter(
            f"+{round(r['biggest_jump_ms'] or 0, -1):.0f} ms after {r['biggest_jump_from']}"
            for r in ok
            if r["biggest_jump_ms"]
        ).most_common(1)
        out.append(
            f"| {tid} | {len(rows)} | {fmt(percentile([r['hop_count'] for r in ok], 50))} "
            f"| {fmt(percentile([r['dest_rtt_ms'] for r in ok], 50), 1)} "
            f"| {fmt(percentile([r['tcp_ms'] for r in tcp_by_target.get(tid, [])], 50), 1)} "
            f"| {path or '–'} "
            f"| {hints[0][0] if hints else '–'} | {jumps[0][0] if jumps else '–'} |"
        )
    return [*out, ""]


# Before tool version 0.3.0 an AI call's first-token clock started before curl was
# set up (up to ~25 ms early on the first call of a run), while its total came
# from curl's own clock, so a first token could even appear to arrive after the
# total. Those first-token times are left out; the stored rows are untouched and
# the call's success and total are still used.
AI_ONE_CLOCK_SINCE = (0, 3, 0)


def ai_on_one_clock(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def old_times(r: dict[str, Any]) -> bool:
        has = r.get("ttft_any_ms") is not None or r.get("ttft_visible_ms") is not None
        return has and _version(r.get("tool_version")) < AI_ONE_CLOCK_SINCE

    return [
        {**r, "ttft_any_ms": None, "ttft_visible_ms": None, "ttft_left_out": True}
        if old_times(r)
        else r
        for r in rows
    ]


def ai_table(ai_rows: list[dict[str, Any]]) -> list[str]:
    if not ai_rows:
        return ["No AI timing data (Part 2 runs only when API keys are in .env).", ""]
    out = [
        "| provider | model | mode | experiment | n | ok | first visible token p50 | p95 "
        "| total p50 |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for (prov, model, mode, exp), rows in sorted(
        _by_tuple(ai_rows, ("provider", "model", "mode", "experiment")).items(),
        key=lambda kv: str(kv[0]),
    ):
        ok = [r for r in rows if r["ok"]]
        vis = [r["ttft_visible_ms"] for r in ok if r["ttft_visible_ms"] is not None]
        out.append(
            f"| {prov} | {model} | {mode} | {exp or 'scheduled'} | {len(rows)} | {len(ok)} "
            f"| {fmt(percentile(vis, 50))} "
            f"| {fmt(percentile(vis, 95))}{reliability_note(len(vis), 95)} "
            f"| {fmt(percentile([r['total_ms'] for r in ok], 50))} |"
        )
    old = sum(1 for r in ai_rows if r.get("ttft_left_out"))
    if old:
        out += [
            "",
            f"First-token times of {old} call(s) made before tool version 0.3.0 are left "
            "out: their first-token clock started before the request was set up, so they "
            "read a few ms high. Their success/failure and total are still counted.",
        ]
    return [*out, ""]


def coverage(cfg: Config, data: dict[str, Any]) -> list[str]:
    runs = [r for r in data["runs"] if r["kind"] == "probe"]
    if not runs:
        any_runs = any(r["kind"] == "probe" for r in data["all_runs"])
        return ["No probe runs in this selection." if any_runs else "No probe runs yet."]
    first, last = runs[0]["started_eat"], runs[-1]["started_eat"]
    span_h = (
        util.parse_iso(runs[-1]["started_utc"]) - util.parse_iso(runs[0]["started_utc"])
    ).total_seconds() / 3600
    interval = float(cfg.section("probe").get("expected_interval_minutes", 15))
    expected = int(span_h * 60 / interval) + 1
    coverage_txt = (
        f"{min(len(runs) / expected, 1):.0%} coverage"
        if span_h * 60 >= 2 * interval
        else "coverage n/a: period shorter than two intervals"
    )
    threshold = float(cfg.section("probe").get("gap_threshold_minutes", 25))
    # Gaps are about the collector being down, so they use every probe run.
    all_probe_runs = [r for r in data["all_runs"] if r["kind"] == "probe"]
    gap_list = gaps.from_runs([util.parse_iso(r["started_utc"]) for r in all_probe_runs], threshold)
    names = {r["asn"]: r["as_name"] for r in runs if r["asn"]}
    asns = Counter(f"AS{r['asn']} {names.get(r['asn'], '')}".strip() for r in runs)
    conns = Counter(r["conn_type"] for r in runs)
    nets = data["nets"]
    flags = [nets[r["run_id"]] for r in all_probe_runs if r["run_id"] in nets]
    vpn_runs = sum(n.vpn for n in flags)
    mixed_runs = sum(n.mixed for n in flags)
    offline = [r for r in all_probe_runs if is_offline(r)]
    online_flags = [
        nets[r["run_id"]] for r in all_probe_runs if r["run_id"] in nets and not is_offline(r)
    ]
    other = (
        sum(1 for n in online_flags if n.network != data["network"] and not (n.vpn or n.mixed))
        if data["network"]
        else 0
    )
    causes = Counter(g["cause"] for g in data["gaps"])
    return [
        f"- Period (EAT): {first[:16]} → {last[:16]} ({span_h:.1f} h)",
        f"- Probe runs: {len(runs)} of ~{expected} expected ({coverage_txt})",
        f"- Gaps > {threshold:g} min: {len(gap_list)}, total {sum(g[2] for g in gap_list):.0f} min"
        + (f" (causes: {', '.join(f'{k} ×{v}' for k, v in causes.items())})" if causes else ""),
        f"- ISPs seen: {', '.join(f'{k} ({v} runs)' for k, v in asns.most_common())}",
        f"- Connection types: {', '.join(f'{k} ({v})' for k, v in conns.most_common())}",
        f"- Probe runs with a VPN active: {vpn_runs} "
        + ("(included: --include-vpn)" if data["include_vpn"] else "(left out; --include-vpn)"),
        f"- Probe runs where the network changed mid-run: {mixed_runs} "
        + (
            "(included: --include-mixed)"
            if data["include_mixed"]
            else "(left out; --include-mixed)"
        ),
        f"- Probe runs with no network connection (laptop offline): {len(offline)}"
        + (f" ({', '.join(offline_spans(all_probe_runs))})" if offline else "")
        + (
            " (included: --include-offline)"
            if data["include_offline"]
            else " (left out; --include-offline)"
        ),
        *([f"- Probe runs on other networks: {other} (not in this report)"] if other else []),
        *added_targets(cfg),
        "- `*` after a number = too few samples for that percentile to be reliable "
        "(p95 needs ≥ 40 samples, p99 ≥ 200).",
        "",
    ]


def added_targets(cfg: Config) -> list[str]:
    """Targets added after collection began have no data before their date."""
    later = [t for t in cfg.targets if t.added]
    by_date: dict[str, list[str]] = defaultdict(list)
    for t in later:
        by_date[t.added].append(f"{t.id} ({t.group})")
    return [
        f"- Targets added on {day}, so no data before then: {', '.join(ids)}"
        for day, ids in sorted(by_date.items())
    ]


def network_section(cfg: Config, data: dict[str, Any], compare: dict[str, Any]) -> list[str]:
    """Which networks the data covers, and the same targets measured on each of them."""
    nets = data["nets"]
    all_runs = [r for r in data["all_runs"] if r["run_id"] in nets]
    out = [
        "Each run is matched to the router it used (fingerprint, label, or for runs made "
        "before fingerprints existed, the router's local address). See README: Networks.",
        "",
        *networks.table_lines(all_runs, nets),
        "",
    ]
    if data["labels"]:
        out += ["Labels:", "", *networks.label_lines(data["labels"]), ""]
    changed = networks.changed_lines(all_runs, nets)
    if changed:
        out += [
            "Runs where the network changed mid-run"
            + (" (included here: --include-mixed):" if data["include_mixed"] else " (left out):"),
            "",
            *changed,
            "",
        ]
    names = available_networks(compare)
    if len(names) < 2:
        return out
    probes = compare["probes"]
    out += [
        "### Same targets, different networks",
        "",
        "TCP connect p50 / total p50 in ms (n = answered requests). VPN runs and runs that "
        "changed network mid-run are left out unless included with the flags above.",
        "",
        "| target | " + " | ".join(names) + " |",
        "|---|" + "---:|" * len(names),
    ]
    cells: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in probes:
        cells[(r["target_id"], r["network"])].append(r)
    for tid in _target_order(cfg):
        row = []
        for net in names:
            ok = [r for r in cells.get((tid, net), []) if r["ok"]]
            row.append(
                f"{fmt(percentile([r['tcp_ms'] for r in ok], 50))} / "
                f"{fmt(percentile([r['total_ms'] for r in ok], 50))} ({len(ok)})"
                if ok
                else "-"
            )
        if any(c != "-" for c in row):
            out.append(f"| {tid} | " + " | ".join(row) + " |")
    fail = []
    for net in names:
        rows = [r for r in probes if r["network"] == net]
        fail.append(f"{1 - sum(r['ok'] for r in rows) / len(rows):.1%}" if rows else "-")
    out += ["| **failure rate, all targets** | " + " | ".join(fail) + " |", ""]
    return out


def steering_section(data: dict[str, Any]) -> list[str]:
    """Near/far switches, checked inside each network: changing network is not a switch."""
    names = available_networks(data)
    if len(names) <= 1:
        return steering.report_lines(data["probes"], data["traces"])
    out = [
        "Checked within each network separately (moving to another network is not a switch).",
        "",
    ]
    for net in names:
        out += [
            f"### {net}",
            "",
            *steering.report_lines(
                [r for r in data["probes"] if r["network"] == net],
                [t for t in data["traces"] if t["network"] == net],
            ),
        ]
    return out


def _by_tuple(
    rows: list[dict[str, Any]], keys: tuple[str, ...]
) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    out: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        out[tuple(r[k] for k in keys)].append(r)
    return out


# --------------------------------------------------------------- charts


def _header(ax: Any, title: str, subtitle: str | None = None, legend_cols: int = 0) -> None:
    """Title on top, then an optional subtitle or legend row, then the plot.

    Fixed offsets in points (not figure fractions) keep the spacing the same
    whatever the chart's height, so title, legend and subtitle never collide.
    """
    has_row = bool(subtitle or legend_cols)
    ax.set_title(title, pad=30 if has_row else 10)
    if subtitle:
        ax.annotate(
            subtitle,
            xy=(0, 1),
            xycoords="axes fraction",
            xytext=(0, 8),
            textcoords="offset points",
            va="bottom",
            fontsize=8.5,
            color=INK_2,
        )
    if legend_cols:
        ax.legend(
            ncol=legend_cols,
            loc="lower left",
            bbox_to_anchor=(0, 1.0),
            borderaxespad=0.2,
            handletextpad=0.5,
            columnspacing=1.4,
        )


def _finish(fig: Any, path: Path, note: str, ax: Any) -> Path:
    """Source line under the x-axis label of the bottom plot, then save."""
    ax.annotate(
        note,
        xy=(0, 0),
        xycoords="axes fraction",
        xytext=(0, -46),
        textcoords="offset points",
        va="top",
        ha="left",
        fontsize=8,
        color=MUTED,
    )
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return path


def chart_phases(cfg: Config, probes: list[dict[str, Any]], out: Path, note: str) -> Path | None:
    wanted = [t.id for t in cfg.targets if t.group == "llm"] + ["local-google", "aws-af-south-1"]
    by_target = _by([r for r in probes if r["ok"]], "target_id")
    rows = []
    for tid in wanted:
        if tid in by_target:
            meds = [percentile([r[k] for r in by_target[tid]], 50) or 0 for k, _ in STACK]
            rows.append((tid, meds, len(by_target[tid])))
    if not rows:
        return None
    rows.sort(key=lambda r: sum(r[1]))
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(rows) + 1.6))
    left = [0.0] * len(rows)
    for i, (_, label) in enumerate(STACK):
        widths = [r[1][i] for r in rows]
        ax.barh(
            range(len(rows)),
            widths,
            left=left,
            height=0.6,
            color=SERIES[i],
            label=label,
            edgecolor=SURFACE,
            linewidth=1.5,
        )
        left = [a + b for a, b in zip(left, widths, strict=True)]
    for y, (_, meds, _n) in enumerate(rows):
        ax.text(sum(meds) + 8, y, f"{sum(meds):,.0f} ms", va="center", fontsize=9, color=INK_2)
    ax.set_yticks(range(len(rows)), [f"{r[0]}  (n={r[2]})" for r in rows])
    ax.set_xlabel("milliseconds (median of each phase, stacked)")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(sum(r[1]) for r in rows) * 1.15)
    _header(ax, "Where the time goes on a fresh connection, from Kenya", legend_cols=5)
    return _finish(fig, out / "phase_breakdown.png", note, ax)


def chart_distribution(
    cfg: Config, probes: list[dict[str, Any]], out: Path, note: str
) -> Path | None:
    llm = [t.id for t in cfg.targets if t.group == "llm"]
    by_target = _by([r for r in probes if r["ok"] and r["target_id"] in llm], "target_id")
    data = [
        (tid, [r["total_ms"] for r in rows if r["total_ms"]]) for tid, rows in by_target.items()
    ]
    data = [d for d in data if d[1]]
    if not data:
        return None
    data.sort(key=lambda d: percentile(d[1], 50) or 0)
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(data) + 1.4))
    ax.boxplot(
        [d[1] for d in data],
        orientation="horizontal",
        whis=(5, 95),
        showfliers=False,
        widths=0.5,
        patch_artist=True,
        boxprops={"facecolor": SERIES[0] + "26", "edgecolor": SERIES[0], "linewidth": 1.5},
        medianprops={"color": INK, "linewidth": 2},
        whiskerprops={"color": SERIES[0], "linewidth": 1.5},
        capprops={"color": SERIES[0], "linewidth": 1.5},
    )
    ax.set_yticks(range(1, len(data) + 1), [f"{d[0]}  (n={len(d[1])})" for d in data])
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("total time for one request on a fresh connection (ms)")
    _header(
        ax,
        "Spread of request times per LLM API",
        "box = middle 50% of requests · line = median · whiskers = 5th to 95th percentile",
    )
    return _finish(fig, out / "distribution_llm.png", note, ax)


def chart_hourly(
    probes: list[dict[str, Any]], runs: list[dict[str, Any]], out: Path, note: str
) -> Path | None:
    hours = list(range(24))

    def med(grp: str) -> list[float | None]:
        return [
            percentile(
                [
                    r["total_ms"]
                    for r in probes
                    if r["hour_eat"] == h and r["grp"] == grp and r["ok"]
                ],
                50,
            )
            for h in hours
        ]

    llm, loc = med("llm"), med("local")
    router = [
        percentile(
            [r["router_rtt_ms"] for r in runs if r["kind"] == "probe" and r["hour_eat"] == h], 50
        )
        for h in hours
    ]
    if not any(v is not None for v in llm):
        return None
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 6.2), sharex=True, height_ratios=[2.2, 1])
    for series, label, color in (
        (llm, "LLM APIs (all 9)", SERIES[0]),
        (loc, "Local Kenyan sites", SERIES[1]),
    ):
        xs = [h for h, v in zip(hours, series, strict=True) if v is not None]
        ys = [v for v in series if v is not None]
        ax1.plot(
            xs,
            ys,
            color=color,
            label=label,
            marker="o",
            markersize=5,
            markeredgecolor=SURFACE,
            markeredgewidth=1.5,
        )
        if xs:
            ax1.annotate(
                label,
                (xs[-1], ys[-1]),
                xytext=(6, 0),
                textcoords="offset points",
                va="center",
                fontsize=9,
                color=INK_2,
            )
    ax1.set_ylabel("median total (ms)")
    ax1.set_ylim(bottom=0)
    _header(ax1, "Time of day (EAT): LLM APIs vs local sites", legend_cols=2)
    xs = [h for h, v in zip(hours, router, strict=True) if v is not None]
    ax2.plot(
        xs,
        [v for v in router if v is not None],
        color=SERIES[2],
        marker="o",
        markersize=5,
        markeredgecolor=SURFACE,
        markeredgewidth=1.5,
    )
    ax2.set_ylabel("router ping (ms)")
    ax2.set_ylim(bottom=0)
    ax2.set_title(
        "Home Wi-Fi: ping to the router (if this stays flat, slowdowns are outside the home)",
        fontsize=10,
        fontweight="normal",
    )
    ax2.set_xticks(range(0, 24, 2), [f"{h:02d}" for h in range(0, 24, 2)])
    ax2.set_xlabel("hour of day, East Africa Time")
    ax2.set_xlim(-0.5, 23.5)
    return _finish(fig, out / "hourly_eat.png", note, ax2)


def chart_regions(probes: list[dict[str, Any]], out: Path, note: str) -> Path | None:
    cloud = [r for r in probes if r["grp"] == "cloud" and r["ok"]]
    if not cloud:
        return None
    clouds = sorted({r["provider"] for r in cloud})
    fig, ax = plt.subplots(figsize=(9, 0.8 * len(clouds) + 1.6))
    for y, prov in enumerate(clouds):
        meds = {}
        for geo in ("africa", "europe", "us"):
            vals = [r["tcp_ms"] for r in cloud if r["provider"] == prov and r["geo"] == geo]
            if vals:
                meds[geo] = percentile(vals, 50)
        if meds:
            ax.plot(
                [min(meds.values()), max(meds.values())], [y, y], color=GRID, linewidth=2, zorder=1
            )
        for geo, value in meds.items():
            ax.scatter(
                value,
                y,
                s=90,
                color=GEO_COLOR[geo],
                edgecolor=SURFACE,
                linewidth=2,
                zorder=3,
                label=GEO_LABEL[geo] if y == 0 else None,
            )
            region = next(r["region"] for r in cloud if r["provider"] == prov and r["geo"] == geo)
            ax.annotate(
                f"{region}\n{value:,.0f} ms",
                (value, y),
                xytext=(0, 10),
                textcoords="offset points",
                ha="center",
                fontsize=8,
                color=INK_2,
            )
    ax.set_yticks(range(len(clouds)), clouds)
    ax.set_ylim(-0.6, len(clouds) - 0.2)
    ax.set_xlim(left=0)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("TCP connect, median ms (≈ one round trip to the data centre)")
    _header(ax, "Is the nearest cloud region actually nearest?", legend_cols=3)
    return _finish(fig, out / "regions.png", note, ax)


def chart_conn(probes: list[dict[str, Any]], out: Path, note: str) -> Path | None:
    llm = [r for r in probes if r["grp"] == "llm" and r["ok"]]
    groups = _by(llm, "conn_type")
    if len(groups) < 2:
        return None
    names = sorted(groups, key=lambda k: percentile([r["total_ms"] for r in groups[k]], 50) or 0)
    fig, ax = plt.subplots(figsize=(9, 0.6 * len(names) + 1.4))
    for y, name in enumerate(names):
        vals = [r["total_ms"] for r in groups[name]]
        p50, p95 = percentile(vals, 50), percentile(vals, 95)
        ax.plot([p50, p95], [y, y], color=SERIES[0] + "55", linewidth=2)
        ax.scatter(p50, y, s=80, color=SERIES[0], edgecolor=SURFACE, linewidth=2, zorder=3)
        ax.annotate(
            f"median {p50:,.0f} · p95 {p95:,.0f} ms",
            (p95, y),
            xytext=(8, 0),
            textcoords="offset points",
            va="center",
            fontsize=8.5,
            color=INK_2,
        )
    ax.set_yticks(range(len(names)), [f"{n} (n={len(groups[n])})" for n in names])
    ax.grid(axis="y", visible=False)
    ax.set_xlim(left=0)
    ax.set_xlabel("total request time to LLM APIs (ms)")
    _header(ax, "Connection type: median (dot) to 95th percentile (line end)")
    return _finish(fig, out / "connection_type.png", note, ax)


# Up to tool version 0.1.0 the ping kept sending until it had 3 replies, so its
# stored `sent` and `loss_pct` overstate loss for slow or lossy hosts. For those
# runs loss is counted as replies missing out of the 3 that were meant.
PING_EXACT_SINCE = (0, 2, 0)
PING_MEANT = 3


def _version(text: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in str(text).split("."))
    except ValueError:
        return (0,)


def ping_loss(g: dict[str, Any]) -> tuple[int, int] | None:
    """(replies missing, packets meant) for a host that answered ping; never uses loss_pct.

    Hosts that block ping (`no_reply`) are missing data, not loss, so they give None.
    """
    if g.get("status") != "ok" or g.get("received") is None:
        return None
    exact = _version(g.get("tool_version")) >= PING_EXACT_SINCE
    meant = int(g["sent"]) if exact and g.get("sent") else PING_MEANT
    return max(meant - min(int(g["received"]), meant), 0), meant


def ping_loss_summary(pings: list[dict[str, Any]]) -> list[str]:
    counted = [x for x in (ping_loss(g) for g in pings) if x]
    if not counted:
        return []
    lost, meant = sum(x[0] for x in counted), sum(x[1] for x in counted)
    return [
        f"Ping replies missing, counting only hosts that answer ping: {lost} of {meant} "
        f"({lost / meant:.1%}). Pings saved before tool version 0.2.0 are counted as "
        "replies received out of 3 (their stored loss_pct is not used).",
        "",
    ]


def ping_pairs(
    probes: list[dict[str, Any]], pings: list[dict[str, Any]]
) -> dict[str, list[tuple[dict[str, Any], dict[str, Any]]]]:
    """(probe, ping) pairs per target: the same run, the same target, the same IP."""
    by_key = {(g["run_id"], g["target_id"]): g for g in pings}
    out: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for pr in probes:
        g = by_key.get((pr["run_id"], pr["target_id"]))
        if g is not None:
            out[pr["target_id"]].append((pr, g))
    return out


def ping_table(cfg: Config, probes: list[dict[str, Any]], pings: list[dict[str, Any]]) -> list[str]:
    """Ping (ICMP) vs a real TCP connection to the same IP, in the same run.

    If ping is ~10 ms but TCP connect is ~200 ms, something near us answers ping
    while the connection itself is handled far away.
    """
    pairs = ping_pairs(probes, pings)
    if not pairs:
        return ["No ping data yet (pings were added after collection started).", ""]
    out = [
        "| target | runs with ping | ping replies | ping p50 | TCP connect p50 | TCP − ping p50 "
        "| runs where TCP > ping + 50 ms | ping loss |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for tid in [t.id for t in cfg.targets if t.id in pairs]:
        rows = pairs[tid]
        answered = [(pr, g) for pr, g in rows if g["status"] == "ok" and g["rtt_median_ms"]]
        both = [(pr, g) for pr, g in answered if pr["ok"] and pr["tcp_ms"] is not None]
        tcp = [pr["tcp_ms"] for pr, _ in rows if pr["ok"] and pr["tcp_ms"] is not None]
        if not answered:
            out.append(
                f"| {tid} | {len(rows)} | 0 (blocks ping) | – "
                f"| {fmt(percentile(tcp, 50))} | – | – | – |"
            )
            continue
        diffs = [pr["tcp_ms"] - g["rtt_median_ms"] for pr, g in both]
        gap = sum(1 for d in diffs if d > 50)
        losses = [x for x in (ping_loss(g) for _, g in answered) if x]
        loss = sum(x[0] for x in losses) / sum(x[1] for x in losses) if losses else None
        out.append(
            f"| {tid} | {len(rows)} | {len(answered)} "
            f"| {fmt(percentile([g['rtt_median_ms'] for _, g in answered], 50), 1)} "
            f"| {fmt(percentile(tcp, 50), 1)} | {fmt(percentile(diffs, 50), 1)} "
            f"| {gap}/{len(both)} | {'–' if loss is None else f'{loss:.1%}'} |"
        )
    return [*out, "", *ping_loss_summary([g for rows in pairs.values() for _, g in rows])]


def chart_ping(
    cfg: Config, probes: list[dict[str, Any]], pings: list[dict[str, Any]], out: Path, note: str
) -> Path | None:
    pairs = ping_pairs(probes, pings)
    rows = []
    for tid in [t.id for t in cfg.targets if t.id in pairs]:
        ping = [g["rtt_median_ms"] for _, g in pairs[tid] if g["status"] == "ok"]
        tcp = [pr["tcp_ms"] for pr, _ in pairs[tid] if pr["ok"] and pr["tcp_ms"] is not None]
        if tcp:
            rows.append((tid, percentile(ping, 50), percentile(tcp, 50)))
    if not rows:
        return None
    rows.sort(key=lambda r: r[2] or 0)
    fig, ax = plt.subplots(figsize=(9, 0.38 * len(rows) + 1.6))
    # Ping sits slightly above and TCP slightly below the row line, so the two
    # stay visible even when they are equal.
    for y, (_, ping, tcp) in enumerate(rows):
        if ping is not None:
            ax.plot([ping, tcp], [y - 0.12, y + 0.12], color=GRID, linewidth=2, zorder=1)
            ax.scatter(
                ping,
                y - 0.12,
                s=60,
                color=SERIES[0],
                edgecolor=SURFACE,
                linewidth=2,
                zorder=3,
                label="Ping (ICMP)" if y == 0 else None,
            )
            if tcp - ping >= 20:
                ax.annotate(
                    f"+{tcp - ping:,.0f} ms",
                    (tcp, y + 0.12),
                    xytext=(8, 0),
                    textcoords="offset points",
                    va="center",
                    fontsize=8,
                    color=INK_2,
                )
        else:
            ax.annotate(
                "no ping reply",
                (tcp, y),
                xytext=(8, 0),
                textcoords="offset points",
                va="center",
                fontsize=8,
                color=MUTED,
            )
        ax.scatter(
            tcp,
            y + 0.12 if ping is not None else y,
            s=60,
            color=SERIES[1],
            edgecolor=SURFACE,
            linewidth=2,
            zorder=3,
            label="TCP connect" if y == 0 else None,
        )
    ax.set_yticks(range(len(rows)), [r[0] for r in rows])
    ax.set_ylim(-0.7, len(rows) - 0.3)
    ax.set_xlim(left=0)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("median round trip (ms), same IP, same run")
    handles, labels = ax.get_legend_handles_labels()
    if "Ping (ICMP)" not in labels:  # first row blocked ping: add the key by hand
        handles.insert(0, ax.scatter([], [], s=70, color=SERIES[0]))
        labels.insert(0, "Ping (ICMP)")
    ax.legend(
        handles,
        labels,
        ncol=2,
        loc="lower left",
        bbox_to_anchor=(0, 1.0),
        borderaxespad=0.2,
        handletextpad=0.5,
        columnspacing=1.4,
    )
    ax.set_title("Ping vs real connection: is the service as close as ping says?", pad=30)
    return _finish(fig, out / "ping_vs_tcp.png", note, ax)


def chart_ai(ai_rows: list[dict[str, Any]], out: Path, note: str) -> Path | None:
    ok = [r for r in ai_rows if r["ok"] and r["ttft_visible_ms"]]
    if not ok:
        return None
    groups = _by_tuple(ok, ("provider", "model", "mode"))
    keys = sorted(
        groups, key=lambda k: percentile([r["ttft_visible_ms"] for r in groups[k]], 50) or 0
    )
    fig, ax = plt.subplots(figsize=(9, 0.55 * len(keys) + 1.4))
    for y, key in enumerate(keys):
        vals = [r["ttft_visible_ms"] for r in groups[key]]
        p50, p95 = percentile(vals, 50), percentile(vals, 95)
        ax.plot([p50, p95], [y, y], color=SERIES[0] + "55", linewidth=2)
        ax.scatter(p50, y, s=80, color=SERIES[0], edgecolor=SURFACE, linewidth=2, zorder=3)
        ax.annotate(
            f"{p50:,.0f} ms",
            (p50, y),
            xytext=(0, 9),
            textcoords="offset points",
            ha="center",
            fontsize=8.5,
            color=INK_2,
        )
    ax.set_yticks(
        range(len(keys)), [f"{k[0]} · {k[1]} · {k[2]} (n={len(groups[k])})" for k in keys]
    )
    ax.grid(axis="y", visible=False)
    ax.set_xlim(left=0)
    ax.set_xlabel("time until the first visible word (ms)")
    _header(ax, "AI reply: median (dot) to 95th percentile (line end)")
    return _finish(fig, out / "ai_first_token.png", note, ax)


# ----------------------------------------------------------------- main


def run(
    cfg: Config,
    *,
    since_days: float | None = None,
    include_vpn: bool = False,
    include_mixed: bool = False,
    include_offline: bool = False,
    network: str | None = None,
    out_dir: Path | None = None,
    echo: Echo = print,
) -> Path:
    raw = load(cfg, since_days)
    flags = {
        "include_vpn": include_vpn,
        "include_mixed": include_mixed,
        "include_offline": include_offline,
    }
    compare = select(raw, **flags)
    if network:
        found = networks.match(network, available_networks(compare))
        if found is None:
            raise ValueError(
                f"no network called '{network}'. Networks with data: "
                + ", ".join(available_networks(compare))
            )
        network = found
    data = select(raw, network=network, **flags)
    out = out_dir or cfg.path("reports_dir") / "latest"
    out.mkdir(parents=True, exist_ok=True)
    _style()
    probes = data["probes"]
    probe_runs = [r for r in data["runs"] if r["kind"] == "probe"]
    period = (
        f"{probe_runs[0]['started_eat'][:10]} to {probe_runs[-1]['started_eat'][:10]}"
        if probe_runs
        else "no data"
    )
    note = (
        f"Source: kenya-llm-latency, home connection in Machakos, Kenya · {period} · "
        + (f"network: {network} · " if network else "")
        + f"{len(probe_runs)} probe runs · medians unless stated"
    )
    mixed_note = []
    if not network and len(available_networks(compare)) > 1:
        mixed_note = [
            f"> This report combines {len(available_networks(compare))} networks "
            f"({', '.join(available_networks(compare))}). Use `kla analyze --network NAME` "
            "or `--each-network` for one report per network.",
            "",
        ]
    charts = [
        c
        for c in (
            chart_phases(cfg, probes, out, note),
            chart_distribution(cfg, probes, out, note),
            chart_hourly(probes, data["runs"], out, note),
            chart_regions(probes, out, note),
            chart_conn(probes, out, note),
            chart_ai(data["ai"], out, note),
            chart_ping(cfg, probes, data["pings"], out, note),
        )
        if c
    ]

    lines = [
        "# kenya-llm-latency report" + (f": {network}" if network else ""),
        "",
        f"Generated {util.iso(util.to_eat(util.utc_now()))[:16]} EAT. All times in milliseconds.",
        "",
        *mixed_note,
        "## Data coverage",
        "",
        *coverage(cfg, data),
        "## Networks",
        "",
        *network_section(cfg, data, compare),
        "## Per target and phase",
        "",
        "Failure rate = requests that got no HTTP answer at all (401/403/404 count as answered).",
        "",
        *phase_tables(cfg, probes),
        "## Failures by type",
        "",
        *failure_table(probes),
        "## Likely packet loss (handshakes of 1 s or more)",
        "",
        "Inferred from timing: a lost packet is resent after about 1 s. Likely, not certain.",
        "",
        *retransmit_table(probes),
        *ping_loss_summary(data["pings"]),
        "## By hour of day (EAT)",
        "",
        *hourly_table(probes, data["runs"]),
        "## By connection type",
        "",
        *conn_table(probes, data["runs"]),
        "## Cloud regions: Africa vs Europe vs US",
        "",
        *region_table(probes),
        "## Which edge answered (from response headers)",
        "",
        *edge_table(probes),
        "## Ping vs real connection",
        "",
        "A 3-packet ping to the same IP right after each probe. Ping can be answered nearby "
        "while the real (TCP) connection is handled far away. Ping replies = runs where the "
        "host answered ping; hosts that block ping are missing data, not failures.",
        "",
        *ping_table(cfg, probes, data["pings"]),
        "## Near/far switches: DNS steering or anycast?",
        "",
        *steering_section(data),
        "## Routes (hourly mtr)",
        "",
        "City hints come from router names and are unverified guesses.",
        "",
        *route_table(data["traces"], probes),
        "## AI time to first token (Part 2/3)",
        "",
        *ai_table(data["ai"]),
        "## Charts",
        "",
        *[f"- `{c.name}`" for c in charts],
        "",
    ]
    report = out / "report.md"
    report.write_text("\n".join(lines))
    (out / "summary.json").write_text(
        json.dumps(
            {
                "network": network,
                "probe_runs": len(probe_runs),
                "probes": len(probes),
                "traces": len(data["traces"]),
                "ai_calls": len(data["ai"]),
                "charts": [c.name for c in charts],
            },
            indent=2,
        )
    )
    echo(f"report: {report}")
    for c in charts:
        echo(f"chart:  {c}")
    return report
