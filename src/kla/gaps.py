"""Detect and explain gaps between runs (power cuts, sleep, stopped timers)."""

from __future__ import annotations

import itertools
import sqlite3
from datetime import datetime
from typing import Any

from kla import db, util


def classify(
    prev_boot_id: str | None,
    prev_suspended_s: float | None,
    boot_id: str | None,
    suspended_s: float | None,
    gap_s: float,
) -> tuple[str, str]:
    """Why was there no run for `gap_s` seconds?

    - restart: the boot id changed, so the laptop was switched off or lost
      power (a power cut and a normal shutdown look the same from here).
    - sleep: same boot, and the "time spent asleep" counter grew by at least
      half the gap.
    - missed: the laptop was awake but nothing ran (timer stopped, a run was
      still waiting for the lock, or it failed before saving).
    """
    if prev_boot_id and boot_id and prev_boot_id != boot_id:
        return "restart", "laptop restarted (power cut, shutdown or crash)"
    if prev_suspended_s is not None and suspended_s is not None:
        slept = suspended_s - prev_suspended_s
        if slept >= 0.5 * gap_s:
            return "sleep", f"laptop was asleep for about {slept / 60:.0f} min"
    return "missed", "laptop was awake but no run was recorded"


def detect(
    conn: sqlite3.Connection,
    now: datetime,
    boot_id: str | None,
    suspended_s: float | None,
    threshold_minutes: float,
    kind: str = "probe",
) -> dict[str, Any] | None:
    """Compare this run with the previous one of the same kind; return a gap row or None."""
    prev = db.fetch(
        conn,
        "SELECT started_utc, boot_id, suspended_total_s FROM runs "
        "WHERE kind = ? ORDER BY started_utc DESC LIMIT 1",
        (kind,),
    )
    if not prev:
        return None
    prev_time = util.parse_iso(prev[0]["started_utc"])
    gap_s = (now - prev_time).total_seconds()
    if gap_s <= threshold_minutes * 60:
        return None
    cause, detail = classify(
        prev[0]["boot_id"], prev[0]["suspended_total_s"], boot_id, suspended_s, gap_s
    )
    return {
        "detected_utc": util.iso(now),
        "prev_run_utc": prev[0]["started_utc"],
        "this_run_utc": util.iso(now),
        "gap_minutes": round(gap_s / 60, 1),
        "cause": cause,
        "detail": detail,
    }


def from_runs(
    run_times: list[datetime], threshold_minutes: float
) -> list[tuple[datetime, datetime, float]]:
    """Gaps recomputed from run timestamps alone (used by status/analysis)."""
    times = sorted(run_times)
    out = []
    for a, b in itertools.pairwise(times):
        minutes = (b - a).total_seconds() / 60
        if minutes > threshold_minutes:
            out.append((a, b, round(minutes, 1)))
    return out
