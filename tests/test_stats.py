import pytest

from kla import stats


def test_percentile_matches_numpy_linear_method():
    data = [10, 20, 30, 40, 50]
    assert stats.percentile(data, 50) == 30
    assert stats.percentile(data, 95) == pytest.approx(48.0)
    assert stats.percentile([5], 99) == 5
    assert stats.percentile([], 50) is None
    assert stats.percentile([None, 3.0, None, 1.0], 50) == 2.0


def test_summary_and_change():
    s = stats.summary(range(1, 101))
    assert s["n"] == 100 and s["p50"] == pytest.approx(50.5)
    assert stats.pct_change(200, 100) == -50
    assert stats.pct_change(0, 100) is None
    assert stats.fmt_pct(-50) == "-50%" and stats.fmt(None) == "–"


def test_reliability_note_flags_small_samples():
    assert stats.reliability_note(10, 95) == "*"
    assert stats.reliability_note(500, 99) == ""
