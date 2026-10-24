"""The light ping after each probe. Never touches the network (run_cmd is faked)."""

from kla import analyze, pinger, util

FULL = """PING 104.18.2.115 (104.18.2.115) 56(84) bytes of data.
64 bytes from 104.18.2.115: icmp_seq=1 ttl=57 time=12.1 ms
64 bytes from 104.18.2.115: icmp_seq=2 ttl=57 time=10.4 ms
64 bytes from 104.18.2.115: icmp_seq=3 ttl=57 time=11.0 ms

--- 104.18.2.115 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 402ms
rtt min/avg/max/mdev = 10.400/11.167/12.100/0.700 ms
"""

PARTIAL = """64 bytes from 1.2.3.4: icmp_seq=1 ttl=57 time=220 ms

--- 1.2.3.4 ping statistics ---
3 packets transmitted, 1 received, 66.6667% packet loss, time 2003ms
rtt min/avg/max/mdev = 220.000/220.000/220.000/0.000 ms
"""

BLOCKED = """PING 20.61.103.89 (20.61.103.89) 56(84) bytes of data.

--- 20.61.103.89 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2046ms
"""


def fake(code, out="", err=""):
    calls = []

    def run(args, timeout=30):
        calls.append(args)
        return util.CmdResult(code, out, err)

    return run, calls


def test_parse_full_partial_and_blocked():
    full = pinger.parse(FULL)
    assert (full["sent"], full["received"], full["loss_pct"]) == (3, 3, 0.0)
    assert full["rtt_median_ms"] == 11.0 and full["rtt_avg_ms"] == 11.167
    assert full["rtt_mdev_ms"] == 0.7
    part = pinger.parse(PARTIAL)
    assert part["received"] == 1 and part["rtt_median_ms"] == 220.0
    blocked = pinger.parse(BLOCKED)
    assert blocked["received"] == 0 and blocked["loss_pct"] == 100.0
    assert blocked["rtt_median_ms"] is None and blocked["rtt_avg_ms"] is None
    assert pinger.parse("garbage")["sent"] is None


def test_ping_ok_uses_light_bounded_command(monkeypatch):
    run, calls = fake(0, FULL)
    monkeypatch.setattr(util, "run_cmd", run)
    row = pinger.ping_ip("104.18.2.115")
    assert row["status"] == "ok" and row["rtt_median_ms"] == 11.0
    args = calls[0]
    assert args[:2] == ["ping", "-n"] and args[-1] == "104.18.2.115"
    assert args[args.index("-c") + 1] == "3"  # three packets
    # No -w deadline: with one, ping keeps sending until it has 3 *replies*.
    assert "-w" not in args


def test_blocked_ping_is_missing_not_failed(monkeypatch):
    run, _ = fake(1, BLOCKED)
    monkeypatch.setattr(util, "run_cmd", run)
    row = pinger.ping_ip("20.61.103.89")
    assert row["status"] == "no_reply"
    assert row["rtt_median_ms"] is None and "error_msg" not in row


def test_no_ip_is_skipped_without_running_ping(monkeypatch):
    run, calls = fake(0, FULL)
    monkeypatch.setattr(util, "run_cmd", run)
    assert pinger.ping_ip(None)["status"] == "skipped"
    assert calls == []


def test_ping_tool_problem_is_an_error_row_not_an_exception(monkeypatch):
    run, _ = fake(127, "", "ping: not found")
    monkeypatch.setattr(util, "run_cmd", run)
    row = pinger.ping_ip("1.2.3.4")
    assert row["status"] == "error" and "not found" in row["error_msg"]


def _ping(version, status, sent, received, loss_pct):
    return {
        "tool_version": version,
        "status": status,
        "sent": sent,
        "received": received,
        "loss_pct": loss_pct,
    }


def test_ping_loss_counts_replies_and_never_reads_stored_loss_pct():
    # Before 0.2.0: 5 packets went out to get 3 replies; the stored 40% is wrong.
    assert analyze.ping_loss(_ping("0.1.0", "ok", 5, 3, 40.0)) == (0, 3)
    assert analyze.ping_loss(_ping("0.1.0", "ok", 9, 2, 77.8)) == (1, 3)
    # From 0.2.0 exactly `count` packets are sent, so sent is the base.
    assert analyze.ping_loss(_ping("0.2.0", "ok", 3, 2, 99.0)) == (1, 3)
    assert analyze.ping_loss(_ping("0.2.0", "ok", 5, 5, 0.0)) == (0, 5)
    # A host that blocks ping is missing data, not packet loss.
    assert analyze.ping_loss(_ping("0.1.0", "no_reply", 15, 0, 100.0)) is None
    assert analyze.ping_loss(_ping("0.2.0", "skipped", None, None, None)) is None
    lines = analyze.ping_loss_summary(
        [_ping("0.1.0", "ok", 5, 3, 40.0), _ping("0.2.0", "ok", 3, 2, 33.3)]
    )
    assert lines[0].startswith("Ping replies missing, counting only hosts that answer ping: 1 of 6")
