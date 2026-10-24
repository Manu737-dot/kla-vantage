"""Which network was each run on? A router fingerprint and a VPN check, twice per run.

Every run checks its network twice: once at the start (inside context.gather)
and once at the end, just before saving. Each check records:

- the router's fingerprint: a salted hash of the router's hardware (MAC)
  address. Every router has its own MAC, so the Tawala router, the Safaricom
  5G router and a fibre router get different fingerprints even when they hand
  out the same 192.168.x.x addresses or belong to the same ISP. The MAC itself
  is never stored: a MAC can be looked up in public Wi-Fi maps to find where a
  router is. The salt is a random secret kept in a file next to the database,
  so the database alone cannot be used to recover the MAC.
- whether a VPN carried the traffic (and which one, e.g. Cloudflare WARP).

If the two checks disagree, the network changed while the run was measuring
(a router switch, or a VPN turning on or off). networks.py flags such runs.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from typing import Any

from kla import context, db, privacy, util

SALT_FILE = "router-salt"


def salt_path(db_path: Path) -> Path:
    return db_path.parent / SALT_FILE


def load_salt(db_path: Path) -> str:
    """Read the secret salt next to the database, creating it on first use."""
    path = salt_path(db_path)
    try:
        value = path.read_text().strip()
        if value:
            return value
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(16)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value + "\n")
    return value


def fingerprint(check: context.NetCheck, salt: str) -> tuple[str | None, str | None]:
    """(fingerprint, source). Falls back to the router's address when no MAC is visible."""
    if check.router_mac:
        material, source = f"mac|{check.router_mac}", "mac"
    elif check.router_ip:
        material, source = f"gw|{check.router_ip}|{check.router_iface}", "gateway"
    else:
        return None, None
    return hashlib.sha256(f"{salt}|{material}".encode()).hexdigest()[:12], source


def to_row(
    check: context.NetCheck, phase: str, salt: str, warp_trace: str | None = None
) -> dict[str, Any]:
    fp, source = fingerprint(check, salt)
    ip = check.router_ip if check.router_ip and privacy.is_private(check.router_ip) else None
    return {
        "phase": phase,
        "ts_utc": util.iso(check.ts),
        "egress_iface": check.egress_iface,
        "router_iface": check.router_iface,
        "router_ip": ip,
        "router_fp": fp,
        "fp_source": source,
        "vpn_active": int(check.vpn_active),
        "vpn_kind": check.vpn_kind,
        "warp_cli": check.warp_cli,
        "warp_trace": warp_trace,
    }


def changes(start: dict[str, Any] | None, end: dict[str, Any] | None) -> list[str]:
    """What differs between a run's start and end checks. Empty = same network throughout.

    A side that saw no network at all (Wi-Fi down) is not a change of network:
    that run is outage data and stays in.
    """
    if not start or not end:
        return []
    out = []
    if start["router_fp"] and end["router_fp"] and start["router_fp"] != end["router_fp"]:
        out.append("router changed")
    if (start["vpn_active"] or 0) != (end["vpn_active"] or 0):
        out.append("VPN turned on" if end["vpn_active"] else "VPN turned off")
    elif (
        start["egress_iface"]
        and end["egress_iface"]
        and start["egress_iface"] != end["egress_iface"]
    ):
        out.append(f"interface changed ({start['egress_iface']} → {end['egress_iface']})")
    return out


def save(conn: Any, run_id: str, ctx: context.NetContext, db_path: Path) -> list[str]:
    """Store the start check and a fresh end check for this run (inside its transaction).

    Returns what changed during the run. Never raises: a failed check must
    not cost the run its measurements.
    """
    try:
        salt = load_salt(db_path)
        rows = []
        if ctx.start_check is not None:
            rows.append(to_row(ctx.start_check, "start", salt, ctx.public.warp))
        rows.append(to_row(context.check_network(), "end", salt))
    except Exception:
        return []
    for row in rows:
        try:
            db.insert(conn, "net_checks", {**row, "run_id": run_id})
        except Exception:
            return []
    return changes(rows[0], rows[-1]) if len(rows) == 2 else []


def current(db_path: Path) -> tuple[context.NetCheck, str | None]:
    """The network the laptop is on right now and its fingerprint (for `kla label`)."""
    check = context.check_network()
    fp, _ = fingerprint(check, load_salt(db_path))
    return check, fp
