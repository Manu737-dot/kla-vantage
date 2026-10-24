import json

from kla import trace

PUBLIC_IP = "198.51.100.77"

MTR = {
    "report": {
        "mtr": {"src": "my-laptop", "dst": "172.64.149.20", "tests": 5},
        "hubs": [
            {
                "count": 1,
                "host": "_gateway (192.168.0.1)",
                "ASN": "AS???",
                "Loss%": 0.0,
                "Snt": 5,
                "Last": 2.0,
                "Avg": 3.0,
                "Best": 1.5,
                "Wrst": 5.6,
                "StDev": 2.1,
            },
            {
                "count": 2,
                "host": "198-51-100-77.cust.isp.ke (198.51.100.1)",
                "ASN": "AS329367",
                "Loss%": 0.0,
                "Snt": 5,
                "Last": 4.0,
                "Avg": 6.2,
                "Best": 4.0,
                "Wrst": 9.6,
                "StDev": 3.0,
            },
            {
                "count": 3,
                "host": "10.249.3.5",
                "ASN": "AS???",
                "Loss%": 0.0,
                "Snt": 5,
                "Last": 4.2,
                "Avg": 5.5,
                "Best": 4.2,
                "Wrst": 6.9,
                "StDev": 1.3,
            },
            {
                "count": 4,
                "host": "ae-1.cr-01-nbo.ke.seacomnet.com (105.16.18.1)",
                "ASN": "AS37100",
                "Loss%": 0.0,
                "Snt": 5,
                "Last": 11.8,
                "Avg": 12.3,
                "Best": 11.8,
                "Wrst": 12.9,
                "StDev": 0.5,
            },
            {
                "count": 5,
                "host": "???",
                "ASN": "AS???",
                "Loss%": 100.0,
                "Snt": 5,
                "Last": 0.0,
                "Avg": 0.0,
                "Best": 0.0,
                "Wrst": 0.0,
                "StDev": 0.0,
            },
            {
                "count": 6,
                "host": "ae-3.r20.mrslfr02.fr.bb.gin.ntt.net (129.250.2.1)",
                "ASN": "AS2914",
                "Loss%": 0.0,
                "Snt": 5,
                "Last": 140.0,
                "Avg": 141.0,
                "Best": 139.0,
                "Wrst": 150.0,
                "StDev": 3.0,
            },
            {
                "count": 7,
                "host": "172.64.149.20",
                "ASN": "AS13335",
                "Loss%": 20.0,
                "Snt": 5,
                "Last": 150.0,
                "Avg": 151.0,
                "Best": 149.5,
                "Wrst": 155.0,
                "StDev": 2.0,
            },
        ],
    }
}


def test_split_host():
    assert trace.split_host("ae-1.cr-01-nbo.ke.seacomnet.com (105.16.18.1)") == (
        "ae-1.cr-01-nbo.ke.seacomnet.com",
        "105.16.18.1",
    )
    assert trace.split_host("8.8.4.4") == (None, "8.8.4.4")
    assert trace.split_host("???") == (None, None)


def test_location_hints():
    assert trace.location_hint("ae-1.cr-01-nbo.ke.seacomnet.com") == "Nairobi, KE"
    assert trace.location_hint("ae-0.dr-01-mba.ke.seacomnet.com") == "Mombasa, KE"
    assert trace.location_hint("ae-3.r20.mrslfr02.fr.bb.gin.ntt.net") == "Marseille, FR"
    assert trace.location_hint("be3463.ccr41.jnb01.atlas.cogentco.com") == "Johannesburg, ZA"
    assert trace.location_hint("router.teams.example.com") is None  # no partial-word matches
    assert trace.location_hint(None) is None


def test_mask_and_summarize():
    hops = trace.mask_hops(trace.parse_mtr_json(json.dumps(MTR)), PUBLIC_IP)
    assert hops[0].hostname == "private-hop" and hops[0].ip == "private"
    assert hops[1].hostname == "your-connection" and hops[1].ip == "masked"  # IP inside the name
    assert hops[2].ip == "private"
    assert hops[3].hint == "Nairobi, KE"
    dumped = json.dumps([h.__dict__ for h in hops])
    assert PUBLIC_IP not in dumped and "198-51-100-77" not in dumped
    assert "192.168.0.1" not in dumped and "my-laptop" not in dumped

    s = trace.summarize(hops, "172.64.149.20")
    assert s["hop_count"] == 7 and s["reached"] == 1
    assert s["dest_rtt_ms"] == 149.5 and s["dest_loss_pct"] == 20.0
    assert s["as_path"] == "AS329367 > AS37100 > AS2914 > AS13335"
    assert s["location_hints"] == "Nairobi, KE > Marseille, FR"
    # The long-haul hop: Nairobi -> Marseille (submarine cable), +127 ms.
    assert s["biggest_jump_ms"] == 127.2
    assert "nbo" in s["biggest_jump_from"] and "Marseille" in s["biggest_jump_to"]


def test_named_as_path(monkeypatch):
    names = {329367: "TAWALA-AS, KE", 37100: "SEACOM-AS - SEACOM Limited, MU"}
    monkeypatch.setattr(trace.context, "asn_name_from_cymru", lambda n: names.get(n))
    cache = {}
    assert trace.named_as_path("AS329367 > AS37100 > AS1", cache) == (
        "AS329367 TAWALA-AS > AS37100 SEACOM-AS > AS1"
    )
