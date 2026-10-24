"""SQLite storage. Every measurement table is append-only (enforced by triggers)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

# One table per kind of measurement. `runs` holds the network context of each
# job (who is my ISP, Wi-Fi or hotspot, router ping, ...); the other tables hold
# one row per measured request and point back to their run.
TABLES: dict[str, str] = {
    "runs": """
        run_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,                 -- probe | trace | ai | experiment
        started_utc TEXT NOT NULL,
        started_eat TEXT NOT NULL,
        finished_utc TEXT NOT NULL,
        hour_eat INTEGER NOT NULL,
        weekday_eat INTEGER NOT NULL,       -- 0 = Monday
        tool_version TEXT NOT NULL,
        asn INTEGER, as_name TEXT, asn_source TEXT, cf_colo TEXT,
        conn_type TEXT, iface TEXT,
        wifi_signal_pct INTEGER, wifi_dbm REAL, wifi_freq_mhz INTEGER, wifi_band TEXT,
        wifi_bitrate_mbps REAL, wifi_powersave TEXT, metered TEXT,
        vpn_active INTEGER, nm_connectivity TEXT,
        router_rtt_ms REAL, router_rtt_mdev_ms REAL, router_loss_pct REAL,
        on_ac INTEGER, boot_id TEXT, suspended_total_s REAL,
        waited_for_network_s REAL, dns_servers TEXT, after_gap INTEGER,
        notes TEXT
    """,
    "probes": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        ts_utc TEXT NOT NULL, seq INTEGER,
        target_id TEXT NOT NULL, host TEXT, grp TEXT, provider TEXT, region TEXT, geo TEXT,
        ip_version INTEGER,
        dns_direct_ms REAL, dns_direct_server TEXT, dns_direct_ttl INTEGER, dns_direct_error TEXT,
        dns_system_ms REAL, dns_system_error TEXT, dns_used TEXT,
        curl_dns_ms REAL, tcp_ms REAL, tls_ms REAL, ttfb_ms REAL, transfer_ms REAL,
        curl_total_ms REAL, total_ms REAL,
        http_status INTEGER, http_version TEXT, tls_version TEXT, tls_cipher TEXT, alpn TEXT,
        remote_ip TEXT, edge_pop TEXT, edge_source TEXT, server_header TEXT, alt_svc_h3 INTEGER,
        size_bytes INTEGER,
        ok INTEGER NOT NULL, error_type TEXT, error_code INTEGER, error_msg TEXT
    """,
    "traces": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        ts_utc TEXT NOT NULL, target_id TEXT NOT NULL, host TEXT, dest_ip TEXT,
        ok INTEGER NOT NULL, error_type TEXT, error_msg TEXT,
        hop_count INTEGER, reached INTEGER, dest_rtt_ms REAL, dest_loss_pct REAL,
        biggest_jump_ms REAL, biggest_jump_from TEXT, biggest_jump_to TEXT,
        as_path TEXT, location_hints TEXT, hops_json TEXT, mtr_args TEXT
    """,
    "ai_calls": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        ts_utc TEXT NOT NULL, experiment TEXT, arm TEXT,
        provider TEXT NOT NULL, model TEXT NOT NULL, size TEXT, mode TEXT NOT NULL,
        ok INTEGER NOT NULL, http_status INTEGER, error_type TEXT, error_msg TEXT,
        dns_ms REAL, tcp_ms REAL, tls_ms REAL, ttfb_ms REAL,
        ttft_any_ms REAL, ttft_visible_ms REAL, total_ms REAL,
        output_chars INTEGER, output_tokens INTEGER, finish_reason TEXT,
        http_version TEXT, remote_ip TEXT, edge_pop TEXT
    """,
    "experiment_samples": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        ts_utc TEXT NOT NULL, experiment TEXT NOT NULL, arm TEXT NOT NULL,
        target_id TEXT, host TEXT, seq INTEGER, reused INTEGER,
        dns_ms REAL, tcp_ms REAL, tls_ms REAL, ttfb_ms REAL, total_ms REAL,
        http_status INTEGER, http_version TEXT, ok INTEGER NOT NULL, error_type TEXT
    """,
    "pings": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        ts_utc TEXT NOT NULL, target_id TEXT NOT NULL, seq INTEGER,
        ip TEXT, status TEXT NOT NULL,      -- ok | no_reply (blocked) | skipped (no IP) | error
        sent INTEGER, received INTEGER, loss_pct REAL,
        rtt_min_ms REAL, rtt_avg_ms REAL, rtt_max_ms REAL, rtt_mdev_ms REAL, rtt_median_ms REAL,
        error_msg TEXT
    """,
    "gaps": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detected_utc TEXT NOT NULL, prev_run_utc TEXT NOT NULL, this_run_utc TEXT NOT NULL,
        gap_minutes REAL NOT NULL, cause TEXT NOT NULL, detail TEXT
    """,
    # Which network a run was on, checked at its start and at its end.
    "net_checks": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        phase TEXT NOT NULL,                -- start | end (of the run)
        ts_utc TEXT NOT NULL,
        egress_iface TEXT,                  -- where internet traffic left (a VPN shows here)
        router_iface TEXT, router_ip TEXT,  -- the physical network underneath (private IP only)
        router_fp TEXT, fp_source TEXT,     -- salted hash of the router's MAC | of its address
        vpn_active INTEGER, vpn_kind TEXT, warp_cli TEXT, warp_trace TEXT
    """,
    # Names for networks, added with `kla label`. A later row wins over an
    # earlier one; label NULL removes a name. Rows are never edited.
    "net_labels": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_utc TEXT NOT NULL,
        label TEXT,
        router_fp TEXT,                     -- name one router ...
        from_utc TEXT, to_utc TEXT,         -- ... or one period of time
        note TEXT,
        CHECK (router_fp IS NOT NULL OR (from_utc IS NOT NULL AND to_utc IS NOT NULL))
    """,
    # Money spent on paid AI calls, one row per call, written right after the call
    # (before the run is saved). ai.due() refuses a call that could push the total
    # past the provider's spend_cap_usd. No foreign key: a dry run writes its real
    # spend here even though its measurements go to another database.
    "ai_spend": """
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
        run_id TEXT, experiment TEXT, recorded_in TEXT,  -- database that holds the measurement
        http_status INTEGER, input_tokens INTEGER, output_tokens INTEGER,
        basis TEXT NOT NULL,  -- usage | not_sent | rejected (HTTP 4xx) | worst_case
        usd_per_mtok_in REAL NOT NULL, usd_per_mtok_out REAL NOT NULL,
        cost_usd REAL NOT NULL
    """,
}


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    for name, columns in TABLES.items():
        conn.execute(f"CREATE TABLE IF NOT EXISTS {name} ({columns})")
        # Append-only: once a measurement is written it can never be edited or
        # deleted, so the raw data cannot be quietly "cleaned" after the fact.
        for action in ("UPDATE", "DELETE"):
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS {name}_no_{action.lower()} "
                f"BEFORE {action} ON {name} "
                f"BEGIN SELECT RAISE(ABORT, '{name} is append-only'); END"
            )
    conn.commit()


_columns_cache: dict[str, set[str]] = {}


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if table not in _columns_cache:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        _columns_cache[table] = {r["name"] for r in rows}
    return _columns_cache[table]


def insert(conn: sqlite3.Connection, table: str, row: dict[str, Any]) -> None:
    unknown = set(row) - columns(conn, table)
    if unknown:
        raise KeyError(f"unknown columns for {table}: {sorted(unknown)}")
    keys = list(row)
    placeholders = ", ".join("?" for _ in keys)
    conn.execute(
        f"INSERT INTO {table} ({', '.join(keys)}) VALUES ({placeholders})",
        [row[k] for k in keys],
    )


def insert_many(conn: sqlite3.Connection, table: str, rows: Iterable[dict[str, Any]]) -> None:
    for row in rows:
        insert(conn, table, row)


def fetch(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]
