"""Far/near switches: was it DNS steering or anycast routing?

Sometimes a provider answers us from nearby (Mombasa, ~10 ms) and sometimes
from far away (Europe, ~200 ms). There are two ways that can happen:

- DNS steering: the provider's DNS hands out *different IP addresses*, and the
  far ones and the near ones are different machines.
- anycast: the *same IP address* is served from many cities, and something in
  the network decides which city we reach.

This module only reads data that the probes and traceroutes already stored:

1. Each probe is labelled "near" or "far" by its TCP connect time (one round
   trip). Handshakes of 1 s or more are skipped: they are lost packets being
   resent, not distance.
2. If an IP address was seen in both states, the switch cannot be DNS: the
   same address was near at one moment and far at another.
3. For same-IP switches, the hourly traceroute is paired with the probe made
   closest in time (preferring the same IP). If ping to that IP stayed local
   while TCP went far, the packets still entered the provider's network nearby
   and the extra time was added *inside* the provider's network (it moved the
   connection to a far data centre). If ping went far too, or the network path
   changed, the route itself changed.

These are inferences from timing, not packet captures, and are labelled so.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from kla import util
from kla.stats import percentile

NEAR_MS = 100.0  # TCP connect below this ≈ answered within Africa
LOSS_MS = 1000.0  # handshakes this slow are resent packets, not distance
PAIR_WINDOW_S = 600  # a traceroute is paired with a probe at most 10 min away
VISIBLE_SHARE = 0.5  # if ping sees >= half of the extra delay, call it a route change

VERDICTS = {
    "dns_steering": "DNS steering (different IPs for far and near)",
    "inside_provider": "anycast: same IP and route; shifted inside the provider's network",
    "route_change": "anycast: same IP; the route itself changed",
    "same_ip_no_trace": "anycast (same IP in both states); no traceroute to tell more",
    "inconclusive": "inconclusive (too few observations)",
}


@dataclass
class Obs:
    """One probe of one target."""

    ts: datetime
    ip: str | None
    tcp_ms: float | None
    tls_ms: float | None = None
    edge: str | None = None

    @property
    def state(self) -> str | None:
        return state_of(self.tcp_ms)


@dataclass
class Trace:
    """One traceroute of one target (ICMP round trip to the destination)."""

    ts: datetime
    dest_ip: str | None
    icmp_ms: float | None
    as_path: str = ""
    hop_count: int | None = None


@dataclass
class Switch:
    at: datetime
    direction: str  # "far→near" or "near→far"
    before: Obs
    after: Obs


@dataclass
class Pair:
    trace: Trace
    probe: Obs
    same_ip: bool


@dataclass
class Verdict:
    target_id: str
    verdict: str
    switches: list[Switch]
    n_far: int
    n_near: int
    ips_far: set[str]
    ips_near: set[str]
    evidence: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return VERDICTS[self.verdict]

    @property
    def shared_ips(self) -> set[str]:
        return self.ips_far & self.ips_near


def state_of(tcp_ms: float | None, near_ms: float = NEAR_MS) -> str | None:
    if tcp_ms is None or tcp_ms >= LOSS_MS:
        return None
    return "near" if tcp_ms < near_ms else "far"


def find_switches(obs: list[Obs]) -> list[Switch]:
    usable = sorted((o for o in obs if o.state), key=lambda o: o.ts)
    out = []
    for before, after in itertools.pairwise(usable):
        if before.state != after.state:
            out.append(Switch(after.ts, f"{before.state}→{after.state}", before, after))
    return out


def pair_traces(obs: list[Obs], traces: list[Trace], window_s: float = PAIR_WINDOW_S) -> list[Pair]:
    """Match each traceroute with the closest-in-time probe, preferring the same IP."""
    usable = [o for o in obs if o.state]
    pairs = []
    for tr in traces:
        if tr.icmp_ms is None:
            continue
        close = [o for o in usable if abs((o.ts - tr.ts).total_seconds()) <= window_s]
        if not close:
            continue
        same = [o for o in close if o.ip and o.ip == tr.dest_ip]
        pool = same or close
        best = min(pool, key=lambda o: abs((o.ts - tr.ts).total_seconds()))
        pairs.append(Pair(tr, best, bool(same)))
    return pairs


def _hm(ts: datetime) -> str:
    return util.to_eat(ts).strftime("%d %b %H:%M")


def _med(values: list[float | None]) -> float | None:
    return percentile(values, 50)


def classify(target_id: str, obs: list[Obs], traces: list[Trace]) -> Verdict | None:
    """Explain the far/near switches of one target. None if it never switched."""
    far = [o for o in obs if o.state == "far"]
    near = [o for o in obs if o.state == "near"]
    if not far or not near:
        return None
    switches = find_switches(obs)
    ips_far = {o.ip for o in far if o.ip}
    ips_near = {o.ip for o in near if o.ip}
    v = Verdict(target_id, "inconclusive", switches, len(far), len(near), ips_far, ips_near)

    v.evidence.append(
        f"{len(switches)} switch(es): "
        + ", ".join(
            f"{s.direction} at {_hm(s.at)} EAT"
            + (
                f" ({s.before.edge or '?'}→{s.after.edge or '?'})"
                if s.before.edge or s.after.edge
                else ""
            )
            for s in switches[:6]
        )
        + (" …" if len(switches) > 6 else "")
    )
    if len(switches) > 2:
        v.evidence.append(
            f"It flipped back and forth {len(switches)} times, so this is not a one-off change."
        )
    near_tls = _med([o.tls_ms for o in near])
    if near_tls is not None and near_tls >= NEAR_MS:
        v.evidence.append(
            f"Even when TCP was answered nearby, the TLS handshake still took ~{near_tls:.0f} ms "
            "(median): the encrypted session is set up far away."
        )
    if len(far) < 2 or len(near) < 2:
        return v

    if not ips_far or not ips_near:
        v.evidence.append(
            "No IP address was recorded for one of the states, so DNS and anycast "
            "cannot be told apart."
        )
        return v
    shared = ips_far & ips_near
    if not shared:
        v.verdict = "dns_steering"
        v.evidence.append(
            "No address was ever seen in both states: "
            f"far {sorted(ips_far)}, near {sorted(ips_near)}."
        )
        return v

    v.evidence.append(
        f"Same address seen both far and near: {', '.join(sorted(shared))}, "
        "so the provider's DNS did not cause the switch."
    )
    for ip in sorted(shared)[:2]:
        f_ex = next(o for o in far if o.ip == ip)
        n_ex = next(o for o in near if o.ip == ip)
        v.evidence.append(
            f"{ip}: TCP {f_ex.tcp_ms:.0f} ms at {_hm(f_ex.ts)}"
            + (f" (edge {f_ex.edge})" if f_ex.edge else "")
            + f" vs {n_ex.tcp_ms:.0f} ms at {_hm(n_ex.ts)}"
            + (f" (edge {n_ex.edge})" if n_ex.edge else "")
            + "."
        )

    pairs = pair_traces(obs, traces)
    far_pairs = [p for p in pairs if p.probe.state == "far"]
    near_pairs = [p for p in pairs if p.probe.state == "near"]
    if not far_pairs or not near_pairs:
        v.verdict = "same_ip_no_trace"
        v.evidence.append(
            "No traceroute ran close enough to a far and a near probe to compare routes."
        )
        return v

    for p in far_pairs[:2]:
        v.evidence.append(
            f"Traceroute {_hm(p.trace.ts)}: ping to {p.trace.dest_ip} = {p.trace.icmp_ms:.0f} ms, "
            f"while TCP to {'the same IP' if p.same_ip else p.probe.ip} at {_hm(p.probe.ts)} "
            f"took {p.probe.tcp_ms:.0f} ms."
        )
    icmp_far = _med([p.trace.icmp_ms for p in far_pairs]) or 0.0
    icmp_near = _med([p.trace.icmp_ms for p in near_pairs]) or 0.0
    tcp_far = _med([o.tcp_ms for o in far]) or 0.0
    tcp_near = _med([o.tcp_ms for o in near]) or 0.0
    extra_tcp = tcp_far - tcp_near
    extra_icmp = icmp_far - icmp_near
    visible = extra_icmp / extra_tcp if extra_tcp > 0 else None
    paths_far = {p.trace.as_path for p in far_pairs}
    paths_near = {p.trace.as_path for p in near_pairs}
    hops_far = {p.trace.hop_count for p in far_pairs}
    hops_near = {p.trace.hop_count for p in near_pairs}
    same_route = paths_far == paths_near and hops_far == hops_near
    v.evidence.append(
        f"Network path {'unchanged' if same_route else 'CHANGED'} between far and near traceroutes "
        f"({' | '.join(sorted(paths_far))} vs {' | '.join(sorted(paths_near))}; "
        f"hops {sorted(h for h in hops_far if h)} vs {sorted(h for h in hops_near if h)})."
    )
    if visible is not None:
        v.evidence.append(
            f"Extra delay when far: TCP {extra_tcp:+.0f} ms, ping {extra_icmp:+.0f} ms, so ping "
            f"saw {max(visible, 0):.0%} of it."
        )
    if not same_route or (visible is not None and visible >= VISIBLE_SHARE):
        v.verdict = "route_change"
    else:
        v.verdict = "inside_provider"
        v.evidence.append(
            "Packets entered the provider's network at the same place both times; the extra time "
            "was added after that, inside the provider's network (inference from timing)."
        )
    return v


def from_rows(probes: list[dict[str, Any]], traces: list[dict[str, Any]]) -> list[Verdict]:
    """Run the check on rows straight from the probes and traces tables."""
    verdicts = []
    for tid in dict.fromkeys(r["target_id"] for r in probes):
        obs = [
            Obs(
                util.parse_iso(r["ts_utc"]),
                r.get("remote_ip"),
                r.get("tcp_ms"),
                r.get("tls_ms"),
                r.get("edge_pop"),
            )
            for r in probes
            if r["target_id"] == tid and r.get("ok")
        ]
        trs = [
            Trace(
                util.parse_iso(t["ts_utc"]),
                t.get("dest_ip"),
                t.get("dest_rtt_ms"),
                t.get("as_path") or "",
                t.get("hop_count"),
            )
            for t in traces
            if t["target_id"] == tid and t.get("ok")
        ]
        verdict = classify(tid, obs, trs)
        if verdict:
            verdicts.append(verdict)
    return verdicts


def report_lines(probes: list[dict[str, Any]], traces: list[dict[str, Any]]) -> list[str]:
    verdicts = from_rows(probes, traces)
    if not verdicts:
        return [
            f"No target switched between near (< {NEAR_MS:.0f} ms) and far "
            f"(≥ {NEAR_MS:.0f} ms) in this period.",
            "",
        ]
    out = [
        f"Near = TCP connect < {NEAR_MS:.0f} ms (answered within Africa), "
        f"far = ≥ {NEAR_MS:.0f} ms. "
        f"Handshakes ≥ {LOSS_MS:.0f} ms are skipped (lost packets). Inference from timing, "
        "not a packet capture.",
        "",
        "| target | far probes | near probes | switches | IPs far | IPs near "
        "| same IP in both | verdict |",
        "|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for v in verdicts:
        out.append(
            f"| {v.target_id} | {v.n_far} | {v.n_near} | {len(v.switches)} | {len(v.ips_far)} "
            f"| {len(v.ips_near)} | {'yes' if v.shared_ips else 'no'} | {v.label} |"
        )
    out.append("")
    for v in verdicts:
        out.append(f"**{v.target_id}**: {v.label}")
        out += [f"- {e}" for e in v.evidence]
        out.append("")
    return out
