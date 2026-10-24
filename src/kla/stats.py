"""Percentiles and before/after comparisons (no numpy needed)."""

from __future__ import annotations

import math
from collections.abc import Iterable


def clean(values: Iterable[float | None]) -> list[float]:
    return sorted(float(v) for v in values if v is not None and not math.isnan(float(v)))


def percentile(values: Iterable[float | None], q: float) -> float | None:
    """Percentile with linear interpolation (same method as numpy's default).

    p50 is the median: half the requests were faster. p95: 1 in 20 requests
    was slower than this. p99: 1 in 100 was slower.
    """
    data = clean(values)
    if not data:
        return None
    if len(data) == 1:
        return data[0]
    pos = (len(data) - 1) * q / 100
    lo, hi = math.floor(pos), math.ceil(pos)
    return data[lo] + (data[hi] - data[lo]) * (pos - lo)


def summary(values: Iterable[float | None]) -> dict[str, float | int | None]:
    data = clean(values)
    return {
        "n": len(data),
        "p50": percentile(data, 50),
        "p95": percentile(data, 95),
        "p99": percentile(data, 99),
    }


def pct_change(before: float | None, after: float | None) -> float | None:
    if before in (None, 0) or after is None:
        return None
    return (after - before) / before * 100


def reliability_note(n: int, q: float) -> str:
    """Flag percentiles that rest on too few samples to mean much.

    To say anything about the slowest 1 in 20 (p95) you need well over 20
    samples; for p99 well over 100. Below these, the value is just "the
    slowest one or two requests" and is marked as uncertain.
    """
    need = {50: 5, 95: 40, 99: 200}.get(int(q), 20)
    return "" if n >= need else "*"


def fmt(value: float | None, digits: int = 0) -> str:
    if value is None:
        return "–"
    return f"{value:,.{digits}f}"


def fmt_pct(value: float | None) -> str:
    return "–" if value is None else f"{value:+.0f}%"
