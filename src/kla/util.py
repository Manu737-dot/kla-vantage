"""Small shared helpers: running commands, timestamps, and a cross-process lock."""

from __future__ import annotations

import fcntl
import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

EAT = ZoneInfo("Africa/Nairobi")


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_cmd(args: list[str], timeout: float = 30) -> CmdResult:
    """Run a command and capture its output. Never raises.

    A missing program returns code 127 and a timeout returns 124, so callers can
    treat "tool not installed" like any other failure and keep going.
    """
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return CmdResult(127, "", f"{args[0]}: not found")
    except subprocess.TimeoutExpired:
        return CmdResult(124, "", f"{args[0]}: timed out after {timeout:g}s")
    return CmdResult(proc.returncode, proc.stdout, proc.stderr)


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text)


def to_eat(dt: datetime) -> datetime:
    return dt.astimezone(EAT)


def ms(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds * 1000, 3)


class LockTimeout(RuntimeError):
    pass


@contextmanager
def file_lock(path: Path, timeout_s: float = 600) -> Iterator[None]:
    """Hold an exclusive lock so two measurement jobs never run at the same time.

    The 15-minute probe and the hourly traceroute can be scheduled for the same
    minute. Running them together would let traceroute traffic slow down the
    probe, so the second job waits here until the first is done.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise LockTimeout(f"another kla job held {path} for {timeout_s:g}s") from None
                time.sleep(1)
        yield
    finally:
        os.close(fd)
