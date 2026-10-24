"""Which network was each run on, and did the network change while it ran?

A "network" is a router (plus whatever ISP is behind it). Each run gets a
network name from the strongest evidence available:

1. A time label: `kla label NAME --from ... --to ...` says "everything in this
   period was on NAME". Used to name the past or to correct a mistake.
2. A router label: `kla label NAME` (while connected) says "this router is NAME".
3. The router fingerprint alone (unnamed): "router 1a2b3c".
4. Runs from before fingerprints existed: the router's local address. Probe
   runs stored it as their DNS server (on these home routers the router is
   the DNS server, e.g. 192.168.0.1). Traceroute runs did not store it, so they
   borrow it from the nearest probe run within 20 minutes. If exactly one
   fingerprinted router was later seen at that address, the old runs join it.

When labels overlap, the newest label wins. Labels are never edited or
deleted; a newer label (or `--clear`) replaces an older one.

A run is flagged "changed mid-run" when its start and end disagree: a
different router or network name, or a VPN switching on or off. Such runs
measured two networks at once, so comparisons leave them out by default.
"""

from __future__ import annotations

import bisect
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from kla import context, db, netcheck, util

LEGACY_WINDOW_S = 20 * 60
UNKNOWN = "unknown"


@dataclass
class Label:
    id: int
    name: str | None  # None = remove the name
    router_fp: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    note: str | None = None


@dataclass
class RunNet:
    run_id: str
    network: str
    how: str
    vpn: bool
    changed: list[str] = field(default_factory=list)
    router_fp: str | None = None

    @property
    def mixed(self) -> bool:
        return bool(self.changed)


def labels_from_rows(rows: list[dict[str, Any]]) -> list[Label]:
    return [
        Label(
            r["id"],
            r.get("label"),
            r.get("router_fp"),
            util.parse_iso(r["from_utc"]) if r.get("from_utc") else None,
            util.parse_iso(r["to_utc"]) if r.get("to_utc") else None,
            r.get("note"),
        )
        for r in rows
    ]


def legacy_address(dns_servers: str | None) -> str | None:
    """The router's private IPv4 address from an old run's DNS server list."""
    for item in (dns_servers or "").split(","):
        try:
            addr = ipaddress.ip_address(item.strip())
        except ValueError:
            continue
        if addr.version == 4 and addr.is_private and not addr.is_loopback:
            return str(addr)
    return None


class Resolver:
    """Turns (time, fingerprint, old router address) into a network name."""

    def __init__(self, labels: list[Label], checks: list[dict[str, Any]]) -> None:
        self.time_labels = [lb for lb in labels if lb.start and lb.end]
        self.router_labels: dict[str, Label] = {}
        for lb in sorted(labels, key=lambda lb: lb.id):
            if lb.router_fp and not lb.start:
                self.router_labels[lb.router_fp] = lb  # newest wins
        by_addr: dict[str, set[str]] = defaultdict(set)
        for c in checks:
            if c.get("router_ip") and c.get("router_fp"):
                by_addr[c["router_ip"]].add(c["router_fp"])
        self.fp_by_address = {a: next(iter(fps)) for a, fps in by_addr.items() if len(fps) == 1}

    def time_label(self, t: datetime) -> Label | None:
        hits = [lb for lb in self.time_labels if lb.start <= t < lb.end]  # type: ignore[operator]
        return max(hits, key=lambda lb: lb.id) if hits else None

    def name(self, t: datetime, fp: str | None, address: str | None) -> tuple[str | None, str]:
        tl = self.time_label(t)
        if tl and tl.name:
            return tl.name, "label (time)"
        how = "fingerprint"
        if fp is None and address:
            fp = self.fp_by_address.get(address)
            how = "router address (before fingerprints)"
        if fp:
            rl = self.router_labels.get(fp)
            if rl and rl.name:
                return rl.name, "label (router)"
            return f"router {fp[:6]}", how
        if address:
            return f"router {address}", "router address (before fingerprints)"
        return None, UNKNOWN


def _legacy_addresses(runs: list[dict[str, Any]], checked: set[str]) -> dict[str, str | None]:
    """Old router address per run; runs without one borrow from the nearest probe run."""
    own = {
        r["run_id"]: legacy_address(r.get("dns_servers"))
        for r in runs
        if r["run_id"] not in checked
    }
    anchors = sorted(
        (util.parse_iso(r["started_utc"]).timestamp(), own[r["run_id"]])
        for r in runs
        if own.get(r["run_id"])
    )
    times = [a[0] for a in anchors]
    out: dict[str, str | None] = {}
    for r in runs:
        rid = r["run_id"]
        if rid in checked:
            continue
        if own.get(rid) or not anchors:
            out[rid] = own.get(rid)
            continue
        t = util.parse_iso(r["started_utc"]).timestamp()
        i = bisect.bisect_left(times, t)
        near = [anchors[j] for j in (i - 1, i) if 0 <= j < len(anchors)]
        best = min(near, key=lambda a: abs(a[0] - t))
        out[rid] = best[1] if abs(best[0] - t) <= LEGACY_WINDOW_S else None
    return out


def assign(
    runs: list[dict[str, Any]], checks: list[dict[str, Any]], label_rows: list[dict[str, Any]]
) -> dict[str, RunNet]:
    """Network name, VPN flag and mid-run changes for every run."""
    resolver = Resolver(labels_from_rows(label_rows), checks)
    by_run: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for c in checks:
        by_run[c["run_id"]][c["phase"]] = c
    legacy = _legacy_addresses(runs, set(by_run))
    out = {}
    for r in runs:
        rid = r["run_id"]
        start, end = by_run.get(rid, {}).get("start"), by_run.get(rid, {}).get("end")
        fp0 = (start or {}).get("router_fp") or (end or {}).get("router_fp")
        fp1 = (end or {}).get("router_fp") or fp0
        address = legacy.get(rid)
        t0 = util.parse_iso(r["started_utc"])
        t1 = util.parse_iso(r["finished_utc"])
        name0, how = resolver.name(t0, fp0, address)
        name1, _ = resolver.name(t1, fp1, address)
        changed = netcheck.changes(start, end)
        if name0 and name1 and name0 != name1:
            changed = [c for c in changed if c != "router changed"]
            changed.insert(0, f"network changed: {name0} → {name1}")
        vpn = bool(r.get("vpn_active")) or any(bool(c.get("vpn_active")) for c in (start, end) if c)
        out[rid] = RunNet(rid, name0 or UNKNOWN, how, vpn, changed, fp0)
    return out


def isp_names(runs: list[dict[str, Any]], nets: dict[str, RunNet]) -> dict[str, str]:
    """Most common ISP per network (outage runs have none; VPN runs show the VPN's)."""
    seen: dict[str, Counter[int]] = defaultdict(Counter)
    names: dict[int, str] = {}
    for r in runs:
        if r.get("asn") and r["run_id"] in nets and not nets[r["run_id"]].vpn:
            seen[nets[r["run_id"]].network][r["asn"]] += 1
            # Older runs stored the raw lookup spelling; show one name per ASN.
            names.setdefault(r["asn"], context.clean_as_name(r.get("as_name")) or "")
    return {
        net: ", ".join(f"AS{asn} {names[asn]}".strip() for asn, _ in c.most_common(2))
        for net, c in seen.items()
    }


def match(name: str, available: list[str]) -> str | None:
    """Find a network by exact name, ignoring case, or by a unique prefix."""
    low = name.lower()
    exact = [a for a in available if a.lower() == low]
    if exact:
        return exact[0]
    prefixed = [a for a in available if a.lower().startswith(low)]
    return prefixed[0] if len(prefixed) == 1 else None


def summary_rows(runs: list[dict[str, Any]], nets: dict[str, RunNet]) -> list[dict[str, Any]]:
    """One row per network: runs, period, ISP, how identified, VPN and mixed runs."""
    isps = isp_names(runs, nets)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in runs:
        if r["run_id"] in nets:
            groups[nets[r["run_id"]].network].append(r)
    out = []
    for net, rs in groups.items():
        rs.sort(key=lambda r: r["started_utc"])
        out.append(
            {
                "network": net,
                "runs": len(rs),
                "probe_runs": sum(r["kind"] == "probe" for r in rs),
                "first": rs[0]["started_utc"],
                "last": rs[-1]["started_utc"],
                "isp": isps.get(net, "-"),
                "how": ", ".join(sorted({nets[r["run_id"]].how for r in rs})),
                "vpn_runs": sum(nets[r["run_id"]].vpn for r in rs),
                "mixed_runs": sum(nets[r["run_id"]].mixed for r in rs),
            }
        )
    return sorted(out, key=lambda x: x["first"])


def describe_now(name: str | None, fp: str, router_ip: str | None, iface: str | None) -> str:
    """'Tawala (router 34d108, 192.168.0.1 via wlp61s0)' for the network the laptop is on."""
    where = f"{router_ip} via {iface}"
    if not name or name.startswith("router "):
        return f"router {fp[:6]} ({where}), no name yet: `kla label NAME` names it"
    return f"{name} (router {fp[:6]}, {where})"


def eat_short(iso_utc: str) -> str:
    return util.to_eat(util.parse_iso(iso_utc)).strftime("%d %b %H:%M")


# ------------------------------------------------------------ database


def load_all(
    conn: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """(runs, net_checks, net_labels) straight from the database."""
    return (
        db.fetch(conn, "SELECT * FROM runs ORDER BY started_utc"),
        db.fetch(conn, "SELECT * FROM net_checks ORDER BY id"),
        db.fetch(conn, "SELECT * FROM net_labels ORDER BY id"),
    )


def parse_eat(text: str) -> datetime:
    """'2026-10-22 10:06' (read as EAT) or a full ISO time with its own offset."""
    dt = datetime.fromisoformat(text.strip())
    return dt if dt.tzinfo else dt.replace(tzinfo=util.EAT)


def add_label(
    conn: Any,
    name: str | None,
    *,
    router_fp: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    note: str | None = None,
) -> None:
    """Append one label row. Nothing is ever overwritten: the newest row wins."""
    if router_fp is None and (start is None or end is None):
        raise ValueError("a label needs a router fingerprint or a --from/--to period")
    if start is not None and end is not None and end <= start:
        raise ValueError("--to must be after --from")
    with conn:
        db.insert(
            conn,
            "net_labels",
            {
                "created_utc": util.iso(util.utc_now()),
                "label": name,
                "router_fp": router_fp,
                "from_utc": util.iso(start) if start else None,
                "to_utc": util.iso(end) if end else None,
                "note": note,
            },
        )


# ------------------------------------------------------------- display


def table_lines(runs: list[dict[str, Any]], nets: dict[str, RunNet]) -> list[str]:
    out = [
        "| network | runs | probe runs | first (EAT) | last (EAT) | ISP | identified by "
        "| VPN runs | changed mid-run |",
        "|---|---:|---:|---|---|---|---|---:|---:|",
    ]
    for s in summary_rows(runs, nets):
        out.append(
            f"| {s['network']} | {s['runs']} | {s['probe_runs']} | {eat_short(s['first'])} "
            f"| {eat_short(s['last'])} | {s['isp']} | {s['how']} | {s['vpn_runs']} "
            f"| {s['mixed_runs']} |"
        )
    return out


def changed_lines(runs: list[dict[str, Any]], nets: dict[str, RunNet]) -> list[str]:
    return [
        f"- {eat_short(r['started_utc'])} EAT {r['kind']} {r['run_id'][:8]}: "
        + "; ".join(nets[r["run_id"]].changed)
        for r in runs
        if r["run_id"] in nets and nets[r["run_id"]].mixed
    ]


def label_lines(label_rows: list[dict[str, Any]]) -> list[str]:
    out = []
    for lb in labels_from_rows(label_rows):
        target = (
            f"period {util.to_eat(lb.start).strftime('%d %b %H:%M')} → "
            f"{util.to_eat(lb.end).strftime('%d %b %H:%M')} EAT"
            if lb.start and lb.end
            else f"router {lb.router_fp}"
        )
        name = f'"{lb.name}"' if lb.name else "(name removed)"
        out.append(f"- #{lb.id} {name}: {target}" + (f" — {lb.note}" if lb.note else ""))
    return out
