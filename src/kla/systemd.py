"""systemd *user* timers: run the probes on a schedule without root.

Each job is a pair of files in ~/.config/systemd/user/:
  kla-probe.service  what to run (one-shot)
  kla-probe.timer    when to run it

`Persistent=true` means: if the laptop was asleep or off when a run was due,
run once as soon as it is back. `RandomizedDelaySec` spreads the start time a
little so we never hit providers on the exact same second every time.
"""

from __future__ import annotations

import sys
from pathlib import Path

from kla import util
from kla.config import Config

UNIT_DIR = Path.home() / ".config" / "systemd" / "user"

JOBS = {
    "probe": ("Part 1 network probe (every 15 min)", "probe"),
    "trace": ("Hourly traceroute (mtr) to LLM hosts", "trace"),
    "ai": ("Part 2 AI time-to-first-token (free tiers, if keys exist)", "ai"),
}


def kla_executable() -> Path:
    """The `kla` script inside this project's virtualenv."""
    return Path(sys.executable).parent / "kla"


def render(cfg: Config, job: str) -> tuple[str, str]:
    desc, sub = JOBS[job]
    sched = cfg.section("schedule")
    service = f"""[Unit]
Description=kenya-llm-latency: {desc}

[Service]
Type=oneshot
WorkingDirectory={cfg.root}
ExecStart={kla_executable()} {sub}
Nice=5
TimeoutStartSec=900
"""
    timer = f"""[Unit]
Description=Schedule for kenya-llm-latency {job}

[Timer]
OnCalendar={sched.get(f"{job}_on_calendar")}
RandomizedDelaySec={int(sched.get(f"{job}_random_delay_s", 60))}
Persistent=true
AccuracySec=1s

[Install]
WantedBy=timers.target
"""
    return service, timer


def write_units(cfg: Config, jobs: list[str], unit_dir: Path = UNIT_DIR) -> list[Path]:
    unit_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for job in jobs:
        service, timer = render(cfg, job)
        for suffix, text in (("service", service), ("timer", timer)):
            path = unit_dir / f"kla-{job}.{suffix}"
            path.write_text(text)
            written.append(path)
    return written


def systemctl(*args: str) -> util.CmdResult:
    return util.run_cmd(["systemctl", "--user", *args], timeout=30)


def start(cfg: Config, jobs: list[str]) -> list[str]:
    msgs = [f"wrote {p}" for p in write_units(cfg, jobs)]
    systemctl("daemon-reload")
    for job in jobs:
        res = systemctl("enable", "--now", f"kla-{job}.timer")
        msgs.append(f"kla-{job}.timer: {'enabled' if res.ok else 'FAILED ' + res.stderr.strip()}")
    return msgs


def stop(jobs: list[str]) -> list[str]:
    msgs = []
    for job in jobs:
        res = systemctl("disable", "--now", f"kla-{job}.timer")
        msgs.append(
            f"kla-{job}.timer: {'stopped' if res.ok else res.stderr.strip() or 'not installed'}"
        )
    return msgs


def timers() -> str:
    res = systemctl("list-timers", "--all", "--no-pager", "kla-*")
    return res.stdout.strip() if res.ok else "(could not query systemd user timers)"
