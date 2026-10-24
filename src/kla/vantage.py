"""A second vantage point: the same measurements from a GitHub-hosted runner.

The laptop measures from Kenya. To separate network time from provider time, the
same probes and AI calls also run hourly on a GitHub Actions runner in an Azure
datacentre (.github/workflows/vantage.yml). From there the network part is small,
so what remains is mostly the provider's own time.

Nothing here changes how the laptop measures. The runner calls the laptop's own
functions (probe.probe_target, ai.call_model, ai.due, ai.assert_free) with the
laptop's config.yaml plus a small override file, config/vantage.yaml.

`kla vantage run` (on the runner only)
    Writes one SQLite file per run, runs/<UTC date>/<UTC time>Z-<id>.sqlite3, into a
    checkout of the vantage-data branch: the laptop's tables plus `vantage_context`
    (where the runner was). The workflow commits it to that branch.
`kla vantage pull` (on the laptop)
    Fetches the vantage-data branch and copies new runs into their own database,
    data/vantage.sqlite3, with every row labelled by its vantage (us-runner). The
    Kenya database is never written to.

Spend: OpenAI calls from the runner have their own ledger (ledger/spend.sqlite3 on
the vantage-data branch) and their own hard cap, HARD_CAP_USD. If the ledger is
missing, no paid call is made.
"""

from __future__ import annotations

import copy
import json
import os
import random
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from kla import __version__, ai, context, db, dnsprobe, probe, util
from kla.config import PROJECT_ROOT, Config

# The runner's OpenAI cap, over all runs. config/vantage.yaml may lower it, never raise it.
HARD_CAP_USD = 0.25
VANTAGE_CONFIG = PROJECT_ROOT / "config" / "vantage.yaml"
BRANCH = "vantage-data"
MARKER = "VANTAGE-DATA.md"  # marks a checkout of the vantage-data branch
RUNS = "runs"
LEDGER = Path("ledger") / "spend.sqlite3"
IMDS_URL = "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"

# Where the runner was, one row per run. Its public IP is GitHub's (an Azure
# address), not the laptop's, so it is kept.
CONTEXT_TABLE = """
    vantage_run_id TEXT PRIMARY KEY,
    vantage TEXT NOT NULL,              -- us-runner
    started_utc TEXT NOT NULL, started_eat TEXT NOT NULL, finished_utc TEXT NOT NULL,
    slot_hour_eat INTEGER,              -- the scheduled :45 slot (GitHub often starts late)
    probe_run_id TEXT, ai_run_id TEXT,  -- this run's rows in `runs`
    runner_ip TEXT, asn INTEGER, as_name TEXT, asn_source TEXT,
    geo_city TEXT, geo_country TEXT, geo_source TEXT,
    cf_colo TEXT,                       -- Cloudflare location that answered the runner
    azure_region TEXT, azure_vm_size TEXT, azure_error TEXT,
    event TEXT, gh_run_id TEXT, gh_run_attempt TEXT, git_sha TEXT, tool_version TEXT,
    runner_name TEXT, runner_os TEXT, image_os TEXT, image_version TEXT,
    ai_notes TEXT                       -- why each provider was or was not called
"""
# Tables copied into data/vantage.sqlite3 by `kla vantage pull`.
PULLED = ("runs", "probes", "ai_calls")


class VantageError(RuntimeError):
    pass


@dataclass(frozen=True)
class Vantage:
    name: str
    slot_minute: int
    odd_hours_only: tuple[str, ...]
    db_path: Path  # where `kla vantage pull` imports to
    repo_url: str | None = None  # the repo whose vantage-data branch holds the results


# ------------------------------------------------------------------ config


def merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load(cfg: Config, path: Path | None = None) -> tuple[Config, Vantage]:
    """The laptop's config with config/vantage.yaml on top, and the runner's settings."""
    data = yaml.safe_load((path or VANTAGE_CONFIG).read_text()) or {}
    v = dict(data.get("vantage") or {})
    raw = merge(cfg.raw, data.get("overrides") or {})
    for pcfg in (raw.get("ai") or {}).get("providers", {}).values():
        if ai.is_paid(pcfg):
            pcfg["spend_cap_usd"] = min(float(pcfg.get("spend_cap_usd") or 0), HARD_CAP_USD)
    groups = list(v.get("groups") or ["llm"])
    targets = [t for t in cfg.targets if t.group in groups]
    db_path = Path(str(v.get("db_path") or "data/vantage.sqlite3"))
    return Config(root=cfg.root, targets=targets, raw=raw), Vantage(
        name=str(v.get("name") or "us-runner"),
        slot_minute=int(v.get("slot_minute", 45)),
        odd_hours_only=tuple(v.get("odd_hours_only") or ()),
        db_path=db_path if db_path.is_absolute() else cfg.root / db_path,
        repo_url=str(v["repo_url"]) if v.get("repo_url") else None,
    )


def slot_hour_eat(now: datetime, slot_minute: int) -> int:
    """The EAT hour of the scheduled slot this run belongs to.

    GitHub often starts scheduled runs late: a run due at 21:45 that starts at
    22:10 still belongs to hour 21.
    """
    return util.to_eat(now - timedelta(minutes=slot_minute)).hour


# ------------------------------------------------------------ runner context


def _imds_compute(timeout: float = 2) -> dict[str, Any]:
    req = urllib.request.Request(IMDS_URL, headers={"Metadata": "true"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read(65536))


def azure_region() -> tuple[str | None, str | None, str | None]:
    """(region, VM size, error) from Azure's instance metadata service.

    Only these two fields are kept; the rest of the answer (subscription, VM name
    and so on) is dropped.
    """
    try:
        data = _imds_compute()
    except (OSError, ValueError) as exc:
        return None, None, f"imds_failed: {type(exc).__name__}"
    return data.get("location") or None, data.get("vmSize") or None, None


def ip_geo(ip: str) -> tuple[str | None, str | None, str | None]:
    """(city, country, error) for an IP, from RIPEstat's copy of MaxMind GeoLite."""
    try:
        data = json.loads(
            context._http_get_text(
                "https://stat.ripe.net/data/maxmind-geo-lite/data.json"
                f"?resource={ip}&sourceapp=kenya-llm-latency"
            )
        )
        loc = data["data"]["located_resources"][0]["locations"][0]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        return None, None, f"geo_failed: {type(exc).__name__}"
    return loc.get("city") or None, loc.get("country") or None, None


def _git_sha(root: Path) -> str | None:
    res = util.run_cmd(["git", "-C", str(root), "rev-parse", "HEAD"])
    return (res.stdout.strip() or None) if res.ok else None


def runner_context(root: Path = PROJECT_ROOT) -> tuple[dict[str, Any], context.PublicInfo]:
    """Where this runner is: its IP, ASN, location, Azure region and GitHub run."""
    pub = context.lookup_public_info()
    city, country, geo_error = (
        ip_geo(pub.public_ip) if pub.public_ip else (None, None, "no_public_ip")
    )
    region, vm_size, azure_error = azure_region()
    env = os.environ.get
    row = {
        "runner_ip": pub.public_ip,
        "asn": pub.asn,
        "as_name": pub.as_name,
        "asn_source": pub.source or pub.error,
        "geo_city": city,
        "geo_country": country,
        "geo_source": geo_error or "ripestat-maxmind",
        "cf_colo": pub.cf_colo,
        "azure_region": region,
        "azure_vm_size": vm_size,
        "azure_error": azure_error,
        "event": env("GITHUB_EVENT_NAME"),
        "gh_run_id": env("GITHUB_RUN_ID"),
        "gh_run_attempt": env("GITHUB_RUN_ATTEMPT"),
        "git_sha": env("GITHUB_SHA") or _git_sha(root),
        "runner_name": env("RUNNER_NAME"),
        "runner_os": env("RUNNER_OS"),
        "image_os": env("ImageOS"),
        "image_version": env("ImageVersion"),
    }
    return row, pub


# ------------------------------------------------------------------- files


def _append_only(conn: sqlite3.Connection, table: str) -> None:
    for action in ("UPDATE", "DELETE"):
        conn.execute(
            f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
            f"BEFORE {action} ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
        )


def init_data_dir(path: Path) -> None:
    """Lay out an empty vantage-data branch: the marker file and an empty ledger."""
    path.mkdir(parents=True, exist_ok=True)
    (path / MARKER).write_text(
        "# vantage-data\n\n"
        "Results from the comparison vantage point (`kla vantage run` on a GitHub-hosted\n"
        "runner). One SQLite file per run in `runs/<UTC date>/`, with the same tables as\n"
        "the laptop's database plus `vantage_context`. `ledger/spend.sqlite3` is the\n"
        f"runner's own OpenAI spend ledger (hard cap ${HARD_CAP_USD:.2f}). Import with\n"
        "`kla vantage pull`.\n"
    )
    (path / ".gitattributes").write_text("*.sqlite3 binary\n")
    conn = db.connect(path / LEDGER)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


def run_file(data_dir: Path, started: datetime, vantage_run_id: str) -> Path:
    return (
        data_dir
        / RUNS
        / started.strftime("%Y-%m-%d")
        / f"{started.strftime('%H%M%S')}Z-{vantage_run_id[:8]}.sqlite3"
    )


def open_run_file(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA page_size = 1024")  # most tables stay empty: keep the file small
    db.init_db(conn)
    conn.execute(f"CREATE TABLE IF NOT EXISTS vantage_context ({CONTEXT_TABLE})")
    _append_only(conn, "vantage_context")
    return conn


def _open_ro(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def history(data_dir: Path) -> sqlite3.Connection:
    """Every earlier runner AI call, from the committed run files, held in memory.

    ai.due() reads it for the daily budgets, minimum gaps and 429 cool-downs.
    Raises sqlite3.Error if a run file cannot be read.
    """
    mem = sqlite3.connect(":memory:")
    db.init_db(mem)
    cols = "run_id, ts_utc, experiment, provider, model, mode, ok, http_status"
    for path in sorted((data_dir / RUNS).glob("*/*.sqlite3")):
        src = _open_ro(path)
        try:
            rows = [tuple(r) for r in src.execute(f"SELECT {cols} FROM ai_calls")]
        finally:
            src.close()
        mem.executemany(f"INSERT INTO ai_calls ({cols}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return mem


# --------------------------------------------------------------------- run


def _probe_all(cfg: Config) -> tuple[list[dict[str, Any]], list[str]]:
    """The laptop's probe, target by target, without the ping (blocked on runners)."""
    p = cfg.section("probe")
    servers = dnsprobe.upstream_servers(cfg.section("dns").get("direct_servers", "auto"))
    targets = list(cfg.targets)
    if p.get("shuffle_targets", True):
        random.shuffle(targets)
    rows = []
    for seq, target in enumerate(targets):
        try:
            row = probe.probe_target(target, cfg, servers)
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
        time.sleep(float(p.get("pause_between_targets_s", 0.3)))
    return rows, servers


def _plan_ai(
    cfg: Config, v: Vantage, data_dir: Path, keys: dict[str, str], started: datetime
) -> tuple[list[ai.ModelChoice], list[str]]:
    """Which AI calls are due on this run, and a note per provider saying why (not)."""
    try:
        hist = history(data_dir)
    except sqlite3.Error as exc:
        return [], [f"all: no AI calls, earlier runs could not be read ({exc})"]
    ledger_ok = (data_dir / LEDGER).exists()  # checked before anything could create it
    slot = slot_hour_eat(started, v.slot_minute)
    plan: list[ai.ModelChoice] = []
    notes = []
    for name, pcfg in ai.providers(cfg).items():
        if not keys.get(str(pcfg.get("env_key"))):
            notes.append(f"{name}: no key")
            continue
        if name in v.odd_hours_only and slot % 2 == 0:
            notes.append(f"{name}: odd EAT hours only")
            continue
        if ai.is_paid(pcfg) and not ledger_ok:
            notes.append(f"{name}: REFUSED - no spend ledger at {LEDGER}")
            continue
        sizes = list(pcfg.get("scheduled") or ["small"])
        ok, why = ai.due(hist, cfg, name, started, scheduled=True, needed=len(sizes))
        if not ok:
            notes.append(f"{name}: not due ({why})")
            continue
        for size in sizes:
            choice = ai.model_choice(cfg, name, size)
            try:
                ai.assert_free(cfg, choice)
            except ai.PaidModelRefused as exc:
                notes.append(f"{name}: REFUSED - {exc}")
                continue
            plan.append(choice)
            notes.append(f"{name}: called")
    hist.close()
    return plan, notes


def run(
    cfg: Config, v: Vantage, data_dir: Path, *, echo: Callable[[str], None] = print
) -> dict[str, Any]:
    """One runner measurement: probes, then the AI calls that are due. One file per run."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise VantageError(
            f"kla vantage run only runs on a GitHub runner (its rows are labelled {v.name})"
        )
    data_dir = data_dir.resolve()
    if not (data_dir / MARKER).exists():
        raise VantageError(f"{data_dir} is not a checkout of the {BRANCH} branch (no {MARKER})")
    started = util.utc_now()
    vantage_run_id = uuid.uuid4().hex
    out = run_file(data_dir, started, vantage_run_id)
    raw = copy.deepcopy(cfg.raw)
    # db_path only names this run's file in spend rows (recorded_in); spend goes to the ledger.
    raw["storage"] = {
        **raw.get("storage", {}),
        "db_path": str(out),
        "spend_db_path": str(data_dir / LEDGER),
    }
    cfg = Config(root=cfg.root, targets=cfg.targets, raw=raw)

    ctx_row, pub = runner_context(cfg.root)
    ctx = context.NetContext(conn_type="datacenter", public=pub)
    rows, servers = _probe_all(cfg)
    probes_done = util.utc_now()

    keys = ai.load_keys(cfg.root)
    plan, notes = _plan_ai(cfg, v, data_dir, keys, started)
    ai_run_id = uuid.uuid4().hex if plan else None
    ai_started = util.utc_now()
    ai_rows = []
    for choice in plan:
        key = keys[str(ai.providers(cfg)[choice.provider]["env_key"])]
        try:
            ai_rows.append(ai.call_model(cfg, choice, key, stream=True, run_id=ai_run_id))
        except Exception as exc:  # keep the probes and the other calls
            notes.append(f"{choice.provider}: call failed ({type(exc).__name__})")
    finished = util.utc_now()

    probe_run_id = uuid.uuid4().hex
    note = f"vantage={v.name}"
    conn = open_run_file(out)
    with conn:  # the whole run is saved together or not at all
        db.insert(
            conn,
            "runs",
            probe.run_row(
                probe_run_id,
                "probe",
                started,
                probes_done,
                ctx,
                dns_servers=",".join(servers),
                notes=note,
            ),
        )
        for row in rows:
            db.insert(conn, "probes", {**row, "run_id": probe_run_id})
        if ai_run_id:
            db.insert(
                conn, "runs", probe.run_row(ai_run_id, "ai", ai_started, finished, ctx, notes=note)
            )
            for row in ai_rows:
                db.insert(conn, "ai_calls", {**row, "run_id": ai_run_id})
        db.insert(
            conn,
            "vantage_context",
            {
                "vantage_run_id": vantage_run_id,
                "vantage": v.name,
                "started_utc": util.iso(started),
                "started_eat": util.iso(util.to_eat(started)),
                "finished_utc": util.iso(finished),
                "slot_hour_eat": slot_hour_eat(started, v.slot_minute),
                "probe_run_id": probe_run_id,
                "ai_run_id": ai_run_id,
                "tool_version": __version__,
                "ai_notes": "; ".join(notes),
                **ctx_row,
            },
        )
    conn.close()
    if (data_dir / LEDGER).exists():  # fold the WAL into the file before git commits it
        ledger = sqlite3.connect(data_dir / LEDGER)
        ledger.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        ledger.close()

    ok = sum(r["ok"] for r in rows)
    echo(
        f"vantage run {vantage_run_id[:8]} saved to {out.relative_to(data_dir)}: "
        f"{ok}/{len(rows)} hosts answered | AS{pub.asn} {pub.as_name} | "
        f"Azure {ctx_row['azure_region'] or '?'} | Cloudflare {pub.cf_colo or '?'}"
    )
    for row in ai_rows:
        echo(
            f"  {row['provider']:<10} {row['model']:<34} first visible token "
            f"{row['ttft_visible_ms']} ms, total {row['total_ms']} ms"
            + (f"  [{row['error_type']}]" if row["error_type"] else "")
        )
    echo("  AI: " + "; ".join(notes))
    return {"file": out, "rows": rows, "ai_rows": ai_rows, "notes": notes, "context": ctx_row}


# -------------------------------------------------------------------- pull


def connect_vantage_db(path: Path) -> sqlite3.Connection:
    """data/vantage.sqlite3: the laptop's tables, each row labelled with its vantage."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    extra = "\n, vantage TEXT NOT NULL, source_file TEXT"
    tables = {name: db.TABLES[name] + extra for name in PULLED}
    tables["ai_spend"] = db.TABLES["ai_spend"] + extra + ", ledger_id INTEGER UNIQUE"
    tables["vantage_context"] = CONTEXT_TABLE + "\n, source_file TEXT"
    for name, columns in tables.items():
        conn.execute(f"CREATE TABLE IF NOT EXISTS {name} ({columns})")
        _append_only(conn, name)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS imported_files (path TEXT PRIMARY KEY, imported_utc TEXT)"
    )
    conn.commit()
    return conn


def _insert(conn: sqlite3.Connection, table: str, row: dict[str, Any]) -> None:
    known = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    unknown = set(row) - known
    if unknown:
        raise KeyError(f"unknown columns for {table}: {sorted(unknown)}")
    keys = list(row)
    conn.execute(
        f"INSERT INTO {table} ({', '.join(keys)}) VALUES ({', '.join('?' for _ in keys)})",
        [row[k] for k in keys],
    )


def import_run(conn: sqlite3.Connection, run_path: Path, name: str) -> None:
    """Copy one run file into the vantage database, unless it is already there."""
    if conn.execute("SELECT 1 FROM imported_files WHERE path = ?", (name,)).fetchone():
        return
    src = _open_ro(run_path)
    try:
        ctx = src.execute("SELECT * FROM vantage_context").fetchone()
        if ctx is None:
            raise VantageError(f"{name} has no vantage_context row")
        label = ctx["vantage"]
        with conn:
            for table in PULLED:
                for r in src.execute(f"SELECT * FROM {table} ORDER BY rowid"):
                    row = dict(r)
                    row.pop("id", None)
                    _insert(conn, table, {**row, "vantage": label, "source_file": name})
            _insert(conn, "vantage_context", {**dict(ctx), "source_file": name})
            conn.execute(
                "INSERT INTO imported_files (path, imported_utc) VALUES (?, ?)",
                (name, util.iso(util.utc_now())),
            )
    finally:
        src.close()


def import_ledger(conn: sqlite3.Connection, ledger_path: Path, label: str) -> int:
    """Copy spend rows not imported yet. The ledger is append-only, so ids only grow."""
    done = conn.execute("SELECT COALESCE(MAX(ledger_id), 0) FROM ai_spend").fetchone()[0]
    src = sqlite3.connect(ledger_path)  # a temp copy: WAL files need write access to open
    src.row_factory = sqlite3.Row
    try:
        rows = src.execute("SELECT * FROM ai_spend WHERE id > ? ORDER BY id", (done,)).fetchall()
    finally:
        src.close()
    with conn:
        for r in rows:
            row = dict(r)
            row.pop("id")
            _insert(
                conn,
                "ai_spend",
                {**row, "ledger_id": r["id"], "vantage": label, "source_file": str(LEDGER)},
            )
    return len(rows)


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, check=True, timeout=120
        ).stdout
    except subprocess.CalledProcessError as exc:
        msg = exc.stderr.decode("utf-8", "replace").strip()
        raise VantageError(f"git {args[0]} failed: {msg}") from None


def pull(
    cfg: Config, v: Vantage, *, remote: str | None = None, echo: Callable[[str], None] = print
) -> dict[str, int]:
    """Fetch the vantage-data branch and import new runs into the vantage database.

    `remote` is a git remote name or URL; by default, vantage.repo_url from config/vantage.yaml.
    """
    dest = v.db_path.resolve()
    if dest in {cfg.db_path.resolve(), cfg.spend_db_path.resolve()}:
        raise VantageError("refusing to import runner data into the Kenya database")
    source = remote or v.repo_url
    if not source:
        raise VantageError("no --remote given and no vantage.repo_url in config/vantage.yaml")
    ref = f"refs/vantage/{BRANCH}"  # its own namespace: never mixed with the code's branches
    _git(cfg.root, "fetch", "--quiet", source, f"+refs/heads/{BRANCH}:{ref}")
    listed = _git(cfg.root, "ls-tree", "-r", "--name-only", ref).decode().split()
    files = sorted(p for p in listed if p.startswith(f"{RUNS}/") and p.endswith(".sqlite3"))
    conn = connect_vantage_db(dest)
    done = {r[0] for r in conn.execute("SELECT path FROM imported_files")}
    new = [p for p in files if p not in done]
    spend = 0
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "file.sqlite3"
        for name in new:
            local.write_bytes(_git(cfg.root, "show", f"{ref}:{name}"))
            import_run(conn, local, name)
            local.unlink()
        if str(LEDGER) in listed:
            local.write_bytes(_git(cfg.root, "show", f"{ref}:{LEDGER}"))
            spend = import_ledger(conn, local, v.name)
    total = conn.execute("SELECT COALESCE(SUM(cost_usd), 0) FROM ai_spend").fetchone()[0]
    conn.close()
    echo(
        f"vantage pull: {len(new)} new run file(s) ({len(files)} on {BRANCH}), "
        f"{spend} new spend row(s); runner spend ${total:.6f} of ${HARD_CAP_USD:.2f} -> {dest}"
    )
    return {"new": len(new), "files": len(files), "spend_rows": spend}
