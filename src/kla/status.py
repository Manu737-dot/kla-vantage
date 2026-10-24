"""`kla status`: is collection healthy? Last runs, counts, failures, gaps, and setup checks."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

from kla import ai, context, db, gaps, netcheck, networks, systemd, util
from kla.config import Config


def _ago(iso_utc: str) -> str:
    minutes = (util.utc_now() - util.parse_iso(iso_utc)).total_seconds() / 60
    return f"{minutes:.0f} min ago" if minutes < 120 else f"{minutes / 60:.1f} h ago"


def setup_checks(cfg: Config) -> list[str]:
    out = []
    ntp = util.run_cmd(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    out.append(
        f"clock synced (NTP):    {ntp.stdout.strip() or 'unknown'}"
        + ("" if ntp.stdout.strip() == "yes" else "   <- timestamps may drift")
    )
    linger = util.run_cmd(
        [
            "loginctl",
            "show-user",
            util.run_cmd(["id", "-un"]).stdout.strip(),
            "-p",
            "Linger",
            "--value",
        ]
    )
    out.append(
        f"linger (run when logged out / after reboot): {linger.stdout.strip() or 'unknown'}"
        + ("" if linger.stdout.strip() == "yes" else "   <- see README: Keep it running")
    )
    lid = lid_setting()
    out.append(
        f"lid closed on AC:      {lid}"
        + ("   <- laptop sleeps when the lid closes" if lid == "suspend" else "")
    )
    from kla.context import on_ac_power  # local import keeps `kla status` fast to start

    ac = on_ac_power()
    out.append(f"on AC power now:       {'yes' if ac else 'no' if ac is False else 'unknown'}")
    keys = ai.load_keys(cfg.root)
    for name, p in ai.providers(cfg).items():
        env = str(p.get("env_key"))
        out.append(f"{env:<22} {'set' if keys.get(env) else 'not set'} ({name})")
        if ai.is_paid(p):
            out.append(paid_line(cfg, name, p))
    return out


def paid_line(cfg: Config, name: str, p: dict) -> str:
    if p.get("opt_in") is not True:
        return f"  {name} is PAID and opt_in is off: it is never called"
    spent = ai.spent_usd(cfg, name)
    conn = db.connect(cfg.spend_db_path)
    calls = conn.execute("SELECT COUNT(*) FROM ai_spend WHERE provider = ?", (name,)).fetchone()[0]
    conn.close()
    cap = float(p.get("spend_cap_usd") or 0)
    return (
        f"  {name} is PAID (opted in): ${spent:.6f} of ${cap:.2f} cap spent over {calls} "
        "call(s); calls stop automatically before the cap"
    )


def lid_setting(paths: list[Path] | None = None) -> str:
    """Effective HandleLidSwitchExternalPower from logind config (default: suspend)."""
    files = paths or [
        Path("/etc/systemd/logind.conf"),
        *sorted(Path("/etc/systemd/logind.conf.d").glob("*.conf")),
    ]
    value = None
    fallback = None
    for f in files:
        try:
            text = f.read_text()
        except OSError:
            continue
        if m := re.findall(r"^\s*HandleLidSwitchExternalPower\s*=\s*(\S+)", text, re.M):
            value = m[-1]
        if m := re.findall(r"^\s*HandleLidSwitch\s*=\s*(\S+)", text, re.M):
            fallback = m[-1]
    return value or fallback or "suspend"


def vpn_banner(check: context.NetCheck, recent_vpn_runs: int = 0) -> list[str]:
    """Impossible-to-miss warning: VPN runs measure the VPN, not the ISP."""
    if not check.vpn_active and not recent_vpn_runs:
        return []
    bar = "!" * 78
    out = [bar]
    if check.vpn_active:
        warp = check.vpn_kind == "cloudflare-warp"
        name = "Cloudflare WARP" if warp else check.vpn_kind
        out += [
            f"!! VPN IS ON NOW: {name} (internet traffic leaves via {check.egress_iface})",
            "!! Probes are measuring the VPN, not your ISP. Those runs are left out of",
            "!! the analysis, so the study is losing data while it stays on.",
            "!! Turn it off: "
            + ("warp-cli disconnect" if warp else "disconnect the VPN in its app"),
        ]
    if recent_vpn_runs:
        out.append(f"!! {recent_vpn_runs} run(s) in the last 24 h were made through a VPN.")
    return [*out, bar, ""]


def network_lines(
    conn: object, check: context.NetCheck, fp: str | None, day_ago: str
) -> tuple[list[str], int]:
    """Current network by name, plus last-24 h VPN and changed-mid-run counts."""
    runs, checks, labels = networks.load_all(conn)
    nets = networks.assign(runs, checks, labels)
    if fp:
        resolver = networks.Resolver(networks.labels_from_rows(labels), checks)
        name, _ = resolver.name(util.utc_now(), fp, None)
        out = ["now on:  " + networks.describe_now(name, fp, check.router_ip, check.router_iface)]
    else:
        out = ["now on:  no router found"]
    recent = [r for r in runs if r["started_utc"] >= day_ago and r["run_id"] in nets]
    vpn = sum(nets[r["run_id"]].vpn for r in recent)
    mixed = [r for r in recent if nets[r["run_id"]].mixed]
    seen = list(dict.fromkeys(nets[r["run_id"]].network for r in recent))
    out.append(f"last 24 h: {', '.join(seen) or 'no runs'}")
    out.append(f"  runs through a VPN: {vpn} (left out of the analysis)")
    out.append(f"  runs where the network changed mid-run: {len(mixed)} (left out by default)")
    out += [f"  {line[2:]}" for line in networks.changed_lines(mixed, nets)]
    return out, vpn


def report(cfg: Config) -> str:
    conn = db.connect(cfg.db_path)
    day_ago = util.iso(util.utc_now() - timedelta(hours=24))
    check, fp = netcheck.current(cfg.db_path)
    net_lines, recent_vpn = network_lines(conn, check, fp, day_ago)
    lines = [*vpn_banner(check, recent_vpn), "== timers ==", systemd.timers(), ""]
    lines += ["== network ==", *net_lines, ""]
    lines.append("== last runs ==")
    for kind in ("probe", "trace", "ai", "experiment"):
        last = db.fetch(
            conn,
            "SELECT started_utc, conn_type, asn, as_name, vpn_active FROM runs "
            "WHERE kind = ? ORDER BY started_utc DESC LIMIT 1",
            (kind,),
        )
        total = conn.execute("SELECT COUNT(*) FROM runs WHERE kind = ?", (kind,)).fetchone()[0]
        recent = conn.execute(
            "SELECT COUNT(*) FROM runs WHERE kind = ? AND started_utc >= ?", (kind, day_ago)
        ).fetchone()[0]
        if last:
            r = last[0]
            lines.append(
                f"{kind:<10} last {util.iso(util.to_eat(util.parse_iso(r['started_utc'])))[:16]} "
                "EAT "
                f"({_ago(r['started_utc'])}) | {total} total, {recent} in 24 h | "
                f"{r['conn_type']} AS{r['asn']} {r['as_name']}"
                + (" | VPN!" if r["vpn_active"] else "")
            )
        else:
            lines.append(f"{kind:<10} no runs yet")

    lines += ["", "== probes, last 24 h =="]
    stats = conn.execute(
        "SELECT COUNT(*), SUM(ok) FROM probes WHERE ts_utc >= ?", (day_ago,)
    ).fetchone()
    n, ok = stats[0] or 0, stats[1] or 0
    lines.append(
        f"{n} requests, {n - ok} failed ({(n - ok) / n:.1%})" if n else "no probes in 24 h"
    )
    for row in db.fetch(
        conn,
        "SELECT target_id, error_type, COUNT(*) AS c FROM probes "
        "WHERE ts_utc >= ? AND ok = 0 GROUP BY 1, 2 ORDER BY c DESC LIMIT 8",
        (day_ago,),
    ):
        lines.append(f"  {row['target_id']:<24} {row['error_type']:<20} x{row['c']}")
    asns = db.fetch(
        conn,
        "SELECT asn, MIN(as_name) AS as_name, COUNT(*) AS c FROM runs WHERE asn IS NOT NULL "
        "GROUP BY asn ORDER BY c DESC",
    )
    if len(asns) > 1:
        lines.append(
            "NOTE: more than one ISP seen: "
            + ", ".join(f"AS{a['asn']} {a['as_name']} ({a['c']})" for a in asns)
        )

    lines += ["", "== gaps =="]
    threshold = float(cfg.section("probe").get("gap_threshold_minutes", 25))
    logged = db.fetch(conn, "SELECT * FROM gaps ORDER BY this_run_utc DESC LIMIT 10")
    for g in logged:
        lines.append(
            f"  {util.iso(util.to_eat(util.parse_iso(g['prev_run_utc'])))[:16]} -> "
            f"{util.iso(util.to_eat(util.parse_iso(g['this_run_utc'])))[:16]} EAT  "
            f"{g['gap_minutes']:>6.0f} min  {g['cause']}: {g['detail']}"
        )
    if not logged:
        lines.append("  none logged")
    runs = [
        util.parse_iso(r["started_utc"])
        for r in db.fetch(conn, "SELECT started_utc FROM runs WHERE kind = 'probe'")
    ]
    total_gap = sum(g[2] for g in gaps.from_runs(runs, threshold))
    lines.append(f"  total time in gaps: {total_gap:.0f} min")
    last_probe = max(runs) if runs else None
    if last_probe and (util.utc_now() - last_probe).total_seconds() > threshold * 60:
        lines.append(f"  NOW: no probe for {_ago(util.iso(last_probe))} - is the timer running?")
    conn.close()

    lines += ["", "== setup checks ==", *setup_checks(cfg)]
    return "\n".join(lines)
