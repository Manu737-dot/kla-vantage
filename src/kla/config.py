"""Load and validate config/config.yaml."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "config.yaml"

# ai-cloud: AI endpoints of cloud platforms, probed for the network only (added
# 23 Oct 2026). A group of their own keeps the llm/cloud/local medians comparable.
GROUPS = ("llm", "cloud", "local", "ai-cloud")
GEOS = ("africa", "europe", "us", "kenya", "anycast")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    id: str
    url: str
    group: str
    provider: str
    geo: str
    source: str
    region: str | None = None
    note: str = ""
    added: str | None = None  # "YYYY-MM-DD" for targets added after collection began

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        return urlsplit(self.url).port or 443


@dataclass(frozen=True)
class Config:
    root: Path
    targets: list[Target]
    raw: dict[str, Any] = field(repr=False)

    def section(self, name: str) -> dict[str, Any]:
        return dict(self.raw.get(name) or {})

    def path(self, key: str) -> Path:
        """Resolve a storage path (relative paths are relative to the repo root)."""
        value = Path(self.section("storage")[key])
        return value if value.is_absolute() else self.root / value

    @property
    def db_path(self) -> Path:
        return self.path("db_path")

    @property
    def spend_db_path(self) -> Path:
        """Where paid AI calls are logged. Set apart from db_path in config.yaml so a
        dry run into another database still counts against the same spend cap."""
        if self.section("storage").get("spend_db_path"):
            return self.path("spend_db_path")
        return self.db_path

    def targets_in(self, groups: list[str]) -> list[Target]:
        return [t for t in self.targets if t.group in groups]


def _target(item: dict[str, Any], index: int) -> Target:
    where = f"targets[{index}] ({item.get('id', '?')})"
    for key in ("id", "url", "group", "provider", "geo", "source"):
        if not item.get(key):
            raise ConfigError(f"{where}: missing '{key}'")
    if not str(item["url"]).startswith("https://"):
        raise ConfigError(f"{where}: url must start with https://")
    if item["group"] not in GROUPS:
        raise ConfigError(f"{where}: group must be one of {GROUPS}")
    if item["geo"] not in GEOS:
        raise ConfigError(f"{where}: geo must be one of {GEOS}")
    if item["group"] == "cloud" and not item.get("region"):
        raise ConfigError(f"{where}: cloud targets need a 'region'")
    added = str(item["added"]) if item.get("added") else None  # YAML may give a date
    if added:
        try:
            date.fromisoformat(added)
        except ValueError:
            raise ConfigError(f"{where}: added must be a date like 2026-10-23") from None
    return Target(
        id=str(item["id"]),
        url=str(item["url"]),
        group=str(item["group"]),
        provider=str(item["provider"]),
        geo=str(item["geo"]),
        source=str(item["source"]),
        region=item.get("region"),
        note=str(item.get("note", "")),
        added=added,
    )


def load_config(path: Path | str | None = None) -> Config:
    """Read the YAML config. `KLA_CONFIG` overrides the default location."""
    cfg_path = Path(path or os.environ.get("KLA_CONFIG") or DEFAULT_CONFIG).resolve()
    if not cfg_path.exists():
        raise ConfigError(f"config file not found: {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text()) or {}
    targets = [_target(item, i) for i, item in enumerate(raw.get("targets") or [])]
    if not targets:
        raise ConfigError("no targets configured")
    ids = [t.id for t in targets]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ConfigError(f"duplicate target ids: {dupes}")
    # The repo root is the folder that contains config/.
    return Config(root=cfg_path.parent.parent, targets=targets, raw=raw)
