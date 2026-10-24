"""Command-line entry point: `kla <command>`."""

from __future__ import annotations

import argparse
import copy
import sys
import traceback
from pathlib import Path

from kla import __version__
from kla.config import Config, ConfigError, load_config


def _config(args: argparse.Namespace) -> Config:
    cfg = load_config(args.config)
    if args.db:
        raw = copy.deepcopy(cfg.raw)
        raw.setdefault("storage", {})["db_path"] = str(Path(args.db).resolve())
        cfg = Config(root=cfg.root, targets=cfg.targets, raw=raw)
    return cfg


def cmd_probe(cfg: Config, args: argparse.Namespace) -> int:
    from kla.probe import run_probe

    result = run_probe(cfg)
    if args.verbose:
        _print_probe_table(result["rows"], result.get("pings", []))
    return 0


def _print_probe_table(rows: list[dict], pings: list[dict] | None = None) -> None:
    def f(v: float | None) -> str:
        return "-" if v is None else f"{v:.0f}"

    ping_by_target = {g["target_id"]: g for g in pings or []}

    def ping_cell(target_id: str) -> str:
        g = ping_by_target.get(target_id)
        if g is None:
            return "-"
        return f(g.get("rtt_median_ms")) if g["status"] == "ok" else g["status"]

    print(
        f"\n{'target':<24}{'dns':>6}{'tcp':>6}{'tls':>6}{'wait':>6}{'total':>7}"
        f"{'ping':>10}  http  edge  status"
    )
    for r in sorted(rows, key=lambda r: (r["grp"], r["target_id"])):
        print(
            f"{r['target_id']:<24}{f(r.get('dns_direct_ms')):>6}{f(r.get('tcp_ms')):>6}"
            f"{f(r.get('tls_ms')):>6}{f(r.get('ttfb_ms')):>6}{f(r.get('total_ms')):>7}"
            f"{ping_cell(r['target_id']):>10}  "
            f"{r.get('http_version') or '-':<4}  {r.get('edge_pop') or '-':<4}  "
            f"{r.get('http_status') or r.get('error_type')}"
        )


def cmd_trace(cfg: Config, args: argparse.Namespace) -> int:
    from kla.trace import run_traces

    run_traces(cfg)
    return 0


def cmd_ai(cfg: Config, args: argparse.Namespace) -> int:
    from kla.ai import run_ai

    run_ai(cfg)
    return 0


def cmd_experiment(cfg: Config, args: argparse.Namespace) -> int:
    from kla import experiments

    if args.name == "reuse":
        ids = args.targets.split(",") if args.targets else None
        experiments.reuse(cfg, n=args.n or 20, target_ids=ids)
    elif args.name == "region":
        experiments.region(cfg)
    else:
        if not args.provider:
            print("this experiment needs --provider (gemini, openrouter or groq)", file=sys.stderr)
            return 2
        if args.name == "stream":
            experiments.stream(cfg, args.provider, n=args.n or 5, size=args.size)
        else:
            experiments.model_size(cfg, args.provider, n=args.n or 5)
    return 0


def cmd_analyze(cfg: Config, args: argparse.Namespace) -> int:
    from kla.analyze import run

    kwargs = {
        "since_days": args.since_days,
        "include_vpn": args.include_vpn,
        "include_mixed": args.include_mixed,
        "include_offline": args.include_offline,
    }
    if args.each_network:
        from kla.analyze import network_names

        base = Path(args.out) if args.out else cfg.path("reports_dir")
        for name in network_names(cfg, **kwargs):
            run(cfg, network=name, out_dir=base / "networks" / _slug(name), **kwargs)
        return 0
    try:
        run(cfg, network=args.network, out_dir=Path(args.out) if args.out else None, **kwargs)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-") or "network"


def cmd_label(cfg: Config, args: argparse.Namespace) -> int:
    from kla import db, netcheck, networks, util

    if bool(args.name) == bool(args.clear):
        print("give a NAME, or --clear to remove a name", file=sys.stderr)
        return 2
    name = None if args.clear else args.name.strip()
    conn = db.connect(cfg.db_path)
    if args.start or args.end:
        if not args.start:
            print("--to needs --from", file=sys.stderr)
            return 2
        start = networks.parse_eat(args.start)
        end = networks.parse_eat(args.end) if args.end else util.utc_now()
        what = (
            f"period {util.to_eat(start).strftime('%d %b %H:%M')} → "
            f"{util.to_eat(end).strftime('%d %b %H:%M')} EAT"
        )
        target = {"start": start, "end": end}
    else:
        if args.router:
            seen = sorted({r[0] for r in conn.execute("SELECT router_fp FROM net_checks") if r[0]})
            hits = [fp for fp in seen if fp.startswith(args.router.lower())]
            if len(hits) != 1:
                print(
                    f"no single router matches '{args.router}' (see `kla networks`)",
                    file=sys.stderr,
                )
                return 2
            fp = hits[0]
            what = f"router {fp[:6]}"
        else:
            check, fp = netcheck.current(cfg.db_path)
            if not fp:
                print("no router found: connect to the network first", file=sys.stderr)
                return 2
            what = f"router {fp[:6]} (the one you are on now: {check.router_ip} via "
            what += f"{check.router_iface})"
        target = {"router_fp": fp}
    try:
        networks.add_label(conn, name, note=args.note, **target)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    runs, checks, labels = networks.load_all(conn)
    conn.close()
    nets = networks.assign(runs, checks, labels)
    print(f"{what}: " + (f'labelled "{name}"' if name else "name removed"))
    if name:
        mine = [r for r in runs if nets[r["run_id"]].network == name]
        print(f'{len(mine)} runs are now on "{name}"')
    return 0


def cmd_networks(cfg: Config, args: argparse.Namespace) -> int:
    from kla import db, netcheck, networks, util

    conn = db.connect(cfg.db_path)
    runs, checks, labels = networks.load_all(conn)
    conn.close()
    nets = networks.assign(runs, checks, labels)
    check, fp = netcheck.current(cfg.db_path)
    if fp:
        resolver = networks.Resolver(networks.labels_from_rows(labels), checks)
        name, _ = resolver.name(util.utc_now(), fp, None)
        print("Now: " + networks.describe_now(name, fp, check.router_ip, check.router_iface))
    else:
        print("Now: no router found")
    if check.vpn_active:
        print(f"!! VPN ON: {check.vpn_kind} - runs made now are left out of the analysis")
    print("", *networks.table_lines(runs, nets), sep="\n")
    print("\nLabels:", *(networks.label_lines(labels) or ["- none yet"]), sep="\n")
    changed = networks.changed_lines(runs, nets)
    print(
        "\nRuns where the network changed mid-run (left out of comparisons by default):",
        *(changed or ["- none"]),
        sep="\n",
    )
    return 0


def cmd_export(cfg: Config, args: argparse.Namespace) -> int:
    from kla.export import export

    for path in export(
        cfg, Path(args.out) if args.out else None, args.tables.split(",") if args.tables else None
    ):
        print(f"wrote {path}")
    return 0


def _jobs(cfg: Config, args: argparse.Namespace) -> list[str]:
    if args.jobs:
        return args.jobs.split(",")
    from kla.ai import load_keys, providers

    keys = load_keys(cfg.root)
    has_key = any(keys.get(str(p.get("env_key"))) for p in providers(cfg).values())
    if not has_key:
        print("no API keys in .env: the AI timer (Part 2) is not installed")
    return ["probe", "trace", *(["ai"] if has_key else [])]


def cmd_start(cfg: Config, args: argparse.Namespace) -> int:
    from kla import systemd

    jobs = _jobs(cfg, args)
    if args.print:
        for job in jobs:
            service, timer = systemd.render(cfg, job)
            print(f"# ~/.config/systemd/user/kla-{job}.service\n{service}")
            print(f"# ~/.config/systemd/user/kla-{job}.timer\n{timer}")
        return 0
    for msg in systemd.start(cfg, jobs):
        print(msg)
    print("\n" + systemd.timers())
    return 0


def cmd_stop(cfg: Config, args: argparse.Namespace) -> int:
    from kla import systemd

    for msg in systemd.stop(args.jobs.split(",") if args.jobs else list(systemd.JOBS)):
        print(msg)
    return 0


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    from kla.status import report

    print(report(cfg))
    return 0


def cmd_vantage(cfg: Config, args: argparse.Namespace) -> int:
    from kla import vantage

    vcfg, v = vantage.load(cfg)
    try:
        if args.action == "run":
            if not args.data_dir:
                print("run needs --data-dir (a vantage-data branch checkout)", file=sys.stderr)
                return 2
            result = vantage.run(vcfg, v, Path(args.data_dir))
            _print_probe_table(result["rows"])
        else:
            vantage.pull(vcfg, v, remote=args.remote)
    except vantage.VantageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kla", description="Measure LLM API latency from Kenya.")
    p.add_argument("--version", action="version", version=f"kla {__version__}")
    p.add_argument("--config", help="path to config.yaml (default: config/config.yaml)")
    p.add_argument("--db", help="use a different SQLite file (e.g. for a dry run)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("probe", help="Part 1: one network probe run (what the 15-min timer runs)")
    s.add_argument("-v", "--verbose", action="store_true", help="print a per-target table")
    s.set_defaults(func=cmd_probe)
    sub.add_parser("trace", help="mtr route trace to each LLM host").set_defaults(func=cmd_trace)
    sub.add_parser("ai", help="Part 2: AI time to first token (needs keys)").set_defaults(
        func=cmd_ai
    )

    s = sub.add_parser("experiment", help="Part 3: on-demand fix experiments")
    s.add_argument("name", choices=["reuse", "stream", "model-size", "region"])
    s.add_argument("--n", type=int, help="samples per arm (default: 20 for reuse, 5 for AI)")
    s.add_argument("--targets", help="comma-separated target ids (reuse; default: all LLM hosts)")
    s.add_argument("--provider", help="gemini | openrouter | groq (stream, model-size)")
    s.add_argument("--size", default="small", choices=["small", "large"], help="model for stream")
    s.set_defaults(func=cmd_experiment)

    s = sub.add_parser("analyze", help="report.md + PNG charts")
    s.add_argument("--since-days", type=float, help="only the last N days")
    s.add_argument("--include-vpn", action="store_true", help="keep runs made through a VPN")
    s.add_argument(
        "--include-mixed",
        action="store_true",
        help="keep runs where the network changed mid-run",
    )
    s.add_argument(
        "--include-offline",
        action="store_true",
        help="keep runs made with no network connection at all",
    )
    s.add_argument("--network", help="only this network (name from `kla networks`)")
    s.add_argument(
        "--each-network",
        action="store_true",
        help="one report per network, in reports/networks/<name>/",
    )
    s.add_argument("--out", help="output folder (default: reports/latest)")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser(
        "label",
        help="name a network: the router you are on now, another router, or a period",
    )
    s.add_argument("name", nargs="?", help='e.g. "Safaricom 5G"')
    s.add_argument("--from", dest="start", help='start of a period, EAT, e.g. "2026-10-22 10:06"')
    s.add_argument("--to", dest="end", help="end of the period (default: now)")
    s.add_argument("--router", help="a router fingerprint from `kla networks`")
    s.add_argument("--clear", action="store_true", help="remove the name instead")
    s.add_argument("--note", help="free text kept with the label")
    s.set_defaults(func=cmd_label)
    sub.add_parser(
        "networks", help="networks seen, labels, and runs that changed network mid-run"
    ).set_defaults(func=cmd_networks)

    s = sub.add_parser("export", help="write every table to CSV")
    s.add_argument("--out", help="folder (default: data/export)")
    s.add_argument("--tables", help="comma-separated table names")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("start", help="install and start the systemd user timers")
    s.add_argument(
        "--jobs", help="comma list of probe,trace,ai (default: probe,trace + ai if keys)"
    )
    s.add_argument("--print", action="store_true", help="only print the unit files")
    s.set_defaults(func=cmd_start)
    s = sub.add_parser("stop", help="stop and disable the timers (data is kept)")
    s.add_argument("--jobs", help="comma list (default: all)")
    s.set_defaults(func=cmd_stop)
    sub.add_parser("status", help="last runs, counts, failures, gaps, setup checks").set_defaults(
        func=cmd_status
    )

    s = sub.add_parser("vantage", help="comparison vantage point (a GitHub runner): run, pull")
    s.add_argument(
        "action",
        choices=["run", "pull"],
        help="run: measure (on the runner only); pull: import its results on the laptop",
    )
    s.add_argument("--data-dir", help="run: a checkout of the vantage-data branch")
    s.add_argument(
        "--remote", help="pull: git remote or URL (default: repo_url in config/vantage.yaml)"
    )
    s.set_defaults(func=cmd_vantage)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = _config(args)
        return int(args.func(cfg, args) or 0)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
