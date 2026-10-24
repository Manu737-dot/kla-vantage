"""Export every table to CSV (one file per table)."""

from __future__ import annotations

import csv
from pathlib import Path

from kla import db
from kla.config import Config


def export(cfg: Config, out_dir: Path | None = None, tables: list[str] | None = None) -> list[Path]:
    out = out_dir or cfg.path("export_dir")
    out.mkdir(parents=True, exist_ok=True)
    conn = db.connect(cfg.db_path)
    written = []
    for table in tables or list(db.TABLES):
        cursor = conn.execute(f"SELECT * FROM {table} ORDER BY rowid")
        path = out / f"{table}.csv"
        with path.open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow([c[0] for c in cursor.description])
            writer.writerows(cursor)
        written.append(path)
    conn.close()
    return written
