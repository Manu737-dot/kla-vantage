import sqlite3
from datetime import timedelta

import pytest

from kla import db, gaps, privacy, util


def _run(run_id, started, **kw):
    return {
        "run_id": run_id,
        "kind": "probe",
        "started_utc": util.iso(started),
        "started_eat": util.iso(util.to_eat(started)),
        "finished_utc": util.iso(started),
        "hour_eat": 0,
        "weekday_eat": 0,
        "tool_version": "test",
        **kw,
    }


def test_tables_are_append_only(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    with conn:
        db.insert(conn, "runs", _run("r1", util.utc_now()))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE runs SET kind = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM runs")
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1


def test_insert_rejects_unknown_columns(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    with pytest.raises(KeyError):
        db.insert(conn, "runs", {"run_id": "x", "public_ip": "1.2.3.4"})


def test_gap_classification():
    assert gaps.classify("aaa", 10, "bbb", 0, 3600)[0] == "restart"
    assert gaps.classify("aaa", 10, "aaa", 10 + 3000, 3600)[0] == "sleep"
    assert gaps.classify("aaa", 10, "aaa", 20, 3600)[0] == "missed"


def test_gap_detect_against_previous_run(tmp_path):
    conn = db.connect(tmp_path / "t.sqlite3")
    now = util.utc_now()
    assert gaps.detect(conn, now, "boot1", 0, 25) is None  # first run ever
    with conn:
        db.insert(
            conn,
            "runs",
            _run("r1", now - timedelta(minutes=95), boot_id="boot1", suspended_total_s=0),
        )
    gap = gaps.detect(conn, now, "boot1", 80 * 60, 25)
    assert gap["cause"] == "sleep" and gap["gap_minutes"] == 95.0
    assert gaps.detect(conn, now - timedelta(minutes=80), "boot1", 0, 25) is None


def test_gaps_from_run_times():
    t0 = util.utc_now()
    times = [t0 + timedelta(minutes=m) for m in (0, 15, 30, 120, 135)]
    assert [g[2] for g in gaps.from_runs(times, 25)] == [90.0]


@pytest.mark.parametrize(
    ("ip", "private"),
    [
        ("192.168.0.1", True),
        ("10.249.3.5", True),
        ("172.16.3.234", True),
        ("100.64.1.1", True),
        ("169.254.1.1", True),
        ("8.8.8.8", False),
        ("105.16.18.1", False),
        ("not-an-ip", False),
    ],
)
def test_is_private(ip, private):
    assert privacy.is_private(ip) is private


def test_scrub_masks_ip_in_all_hostname_forms_and_keys():
    ip = "41.90.12.34"
    text = "hop 41-90-12-34.isp.ke, rev 34.12.90.41.in-addr, key sk-SECRET"
    out = privacy.scrub({"a": [text], "n": 5}, [ip, "sk-SECRET"])
    assert ip not in out["a"][0]
    assert "41-90-12-34" not in out["a"][0] and "34.12.90.41" not in out["a"][0]
    assert "sk-SECRET" not in out["a"][0] and out["n"] == 5
