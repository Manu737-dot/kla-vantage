"""A light ping (3 packets) to the IP address a probe has just connected to.

Ping uses ICMP, which is handled differently from a real (TCP) connection: an
edge server or router can answer ping in Mombasa while the actual connection is
handled in Europe. Putting the two side by side shows when "the server is
close" (ping) and "the service is close" (TCP connect) are not the same thing.

Many hosts drop ping on purpose. That is recorded as `no_reply` with empty
round-trip times: missing data, not a failed probe.
"""

from __future__ import annotations

import re
from typing import Any

from kla import util

_TX = re.compile(r"(\d+) packets transmitted, (\d+) received")
_LOSS = re.compile(r"([\d.]+)% packet loss")
_SUMMARY = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")
_TIME = re.compile(r"time=([\d.]+) ms")


def parse(text: str) -> dict[str, Any]:
    """Read iputils `ping` output (works for full, partial and zero replies)."""
    times = sorted(float(t) for t in _TIME.findall(text))
    tx = _TX.search(text)
    loss = _LOSS.search(text)
    summary = _SUMMARY.search(text)
    out: dict[str, Any] = {
        "sent": int(tx.group(1)) if tx else None,
        "received": int(tx.group(2)) if tx else None,
        "loss_pct": float(loss.group(1)) if loss else None,
        "rtt_min_ms": None,
        "rtt_avg_ms": None,
        "rtt_max_ms": None,
        "rtt_mdev_ms": None,
        "rtt_median_ms": times[len(times) // 2] if times else None,
    }
    if summary:
        out["rtt_min_ms"], out["rtt_avg_ms"], out["rtt_max_ms"], out["rtt_mdev_ms"] = (
            float(g) for g in summary.groups()
        )
    return out


def ping_ip(
    ip: str | None, count: int = 3, interval_s: float = 0.2, deadline_s: float = 3
) -> dict[str, Any]:
    """Ping one IP with exactly `count` packets. Never raises; a blocked ping is `no_reply`.

    `-c 3` without a `-w` deadline sends exactly 3 packets, so "sent" and
    "loss" mean what they say. (Up to tool version 0.1.0 a `-w` deadline was
    also given; with it, ping keeps sending until it has 3 *replies*, so slow
    or lossy hosts got 4-15 packets and the stored loss was too high.) With
    `-W 1`, a host that never answers costs about 1.4 s; `deadline_s` is only
    a safety cap on the whole command.
    """
    if not ip:
        return {"ip": None, "status": "skipped", "error_msg": "no IP (the probe got no address)"}
    res = util.run_cmd(
        [
            "ping",
            "-n",
            "-c",
            str(count),
            "-i",
            str(interval_s),
            "-W",
            "1",
            ip,
        ],
        timeout=deadline_s + 5,
    )
    row: dict[str, Any] = {"ip": ip, **parse(res.stdout)}
    if res.returncode == 0 and row["received"]:
        row["status"] = "ok"
    elif res.returncode == 1 or row["received"] == 0:
        row["status"] = "no_reply"  # filtered or blocked: missing, not failed
    else:
        row["status"] = "error"
        row["error_msg"] = (res.stderr or res.stdout).strip()[:200] or f"exit {res.returncode}"
    return row
