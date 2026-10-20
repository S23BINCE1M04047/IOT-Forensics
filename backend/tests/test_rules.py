from app.rules import (r_beacon, r_dest_new, r_dns_long, r_dns_new, r_ext_dest, r_multi_ind,
                       r_pattern_dev, r_spike, r_ti_match, r_whitelist)
from app.rules.base import RuleHit
from app.services.baseline import build_profile
from app.services.prioritizer import run_rules
from tests.helpers import BROKER, EXT, ESP, HOST, NTP, GW, Cap, baseline, dnsq, make_ctx, mqtt, tcp, ti, udp


# ---------- R-TI-MATCH-01 ----------
def test_ti_ip_match() -> None:
    rows = Cap().add(tcp(ESP, EXT, 8443), 0).add(tcp(ESP, EXT, 8443), 1).add(tcp(ESP, BROKER, 1883), 2).rows()
    hits = r_ti_match.evaluate(make_ctx(rows, intel=ti(ips={EXT: "test C2"})))
    assert len(hits) == 1 and hits[0].priority == "P1" and hits[0].packet_refs == [1, 2]


def test_ti_domain_match_includes_subdomains() -> None:
    rows = Cap().add(dnsq("bad.test"), 0).add(dnsq("x.bad.test"), 1).add(dnsq("good.test"), 2).rows()
    hits = r_ti_match.evaluate(make_ctx(rows, intel=ti(domains={"bad.test": "c2"})))
    assert len(hits) == 1 and hits[0].packet_refs == [1, 2]


def test_ti_no_match() -> None:
    rows = Cap().add(tcp(ESP, EXT, 8443), 0).rows()
    assert r_ti_match.evaluate(make_ctx(rows, intel=ti(ips={"203.0.113.66": "other"}))) == []


# ---------- R-BEACON-01 ----------
def _beacon(offsets: list[float], dst: str = EXT, dport: int = 8443) -> list[RuleHit]:
    cap = Cap()
    for t in offsets:
        cap.add(tcp(ESP, dst, dport, sport=50200), t)
    return r_beacon.evaluate(make_ctx(cap.rows()))


def test_beacon_regular() -> None:
    hits = _beacon([0, 30, 60, 90, 120, 150])
    assert len(hits) == 1 and hits[0].priority == "P2" and hits[0].packet_refs == [1, 2, 3, 4, 5, 6]


def test_beacon_jittery_not_flagged() -> None:
    assert _beacon([0, 5, 55, 58, 138, 147]) == []


def test_beacon_too_few_repetitions() -> None:
    assert _beacon([0, 30, 60, 90]) == []


def test_beacon_bursts_collapse_into_events() -> None:
    offsets = [k * 30 + d for k in range(6) for d in (0, 0.1, 0.2)]
    hits = _beacon(offsets)
    assert len(hits) == 1 and len(hits[0].packet_refs) == 18 and hits[0].details["events"] == 6


def test_beacon_whitelisted_endpoint_exempt() -> None:
    assert _beacon([k * 5 for k in range(12)], dst=BROKER, dport=1883) == []


# ---------- R-EXT-DEST-01 ----------
def test_ext_dest_without_baseline_has_reduced_confidence() -> None:
    rows = Cap().add(tcp(ESP, EXT, 80), 0).rows()
    hits = r_ext_dest.evaluate(make_ctx(rows))
    assert len(hits) == 1 and hits[0].priority == "P2" and hits[0].confidence == 0.55


def test_ext_dest_with_baseline_full_confidence_and_known_dest_exempt() -> None:
    rows = Cap().add(tcp(ESP, EXT, 80), 0).rows()
    assert r_ext_dest.evaluate(make_ctx(rows, baseline()))[0].confidence == 0.8
    assert r_ext_dest.evaluate(make_ctx(rows, baseline(dst_ips=[EXT]))) == []


def test_ext_dest_ignores_internal_whitelisted_and_multicast() -> None:
    rows = (Cap().add(tcp(ESP, BROKER, 1883), 0).add(udp(ESP, NTP, 123), 1)
            .add(udp(ESP, "224.0.0.251", 5353), 2).rows())
    assert r_ext_dest.evaluate(make_ctx(rows)) == []


# ---------- R-PATTERN-DEV-01 ----------
def _mqtt_rows() -> list:
    return mqtt(Cap(), [0, 10, 20, 30]).rows()


def test_pattern_dev_fires_on_novel_peers_and_protocols() -> None:
    cur = Cap().add(tcp(ESP, EXT, 8443), 0).add(tcp(ESP, EXT, 8443), 1).add(tcp(ESP, EXT, 8443), 2).rows()
    hits = r_pattern_dev.evaluate(make_ctx(cur, build_profile(_mqtt_rows())))
    assert len(hits) == 1 and hits[0].priority == "P2"
    assert set(hits[0].details["metrics_exceeded"]) == {"protocol_mix", "peer_set"}


def test_pattern_dev_silent_when_identical_or_no_baseline() -> None:
    rows = _mqtt_rows()
    assert r_pattern_dev.evaluate(make_ctx(rows, build_profile(rows))) == []
    assert r_pattern_dev.evaluate(make_ctx(rows)) == []


# ---------- R-DNS-NEW-01 ----------
def test_dns_new() -> None:
    rows = Cap().add(dnsq("pool.ntp.org"), 0).add(dnsq("new.example.test"), 1).add(dnsq("old.example.test"), 2).rows()
    hits = r_dns_new.evaluate(make_ctx(rows, baseline(domains=["old.example.test"])))
    assert [h.details["domain"] for h in hits] == ["new.example.test"]  # whitelisted + known are exempt


def test_dns_new_requires_baseline() -> None:
    assert r_dns_new.evaluate(make_ctx(Cap().add(dnsq("new.example.test"), 0).rows())) == []


# ---------- R-DNS-LONG-01 ----------
def test_dns_long_by_length_and_entropy() -> None:
    rows = (Cap().add(dnsq("a" * 30 + "." + "b" * 30 + ".test"), 0)
            .add(dnsq("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.test"), 1).rows())
    hits = r_dns_long.evaluate(make_ctx(rows))
    assert len(hits) == 2 and all(h.priority == "P3" for h in hits)


def test_dns_long_benign_and_whitelisted_not_flagged() -> None:
    rows = Cap().add(dnsq("update.example-cdn.test"), 0).add(dnsq("pool.ntp.org"), 1).rows()
    assert r_dns_long.evaluate(make_ctx(rows)) == []


# ---------- R-DEST-NEW-01 ----------
def test_dest_new_internal_only() -> None:
    rows = Cap().add(tcp(ESP, HOST, 8080), 0).add(tcp(ESP, GW, 8080), 1).add(tcp(ESP, EXT, 80), 2).rows()
    hits = r_dest_new.evaluate(make_ctx(rows, baseline(dst_ips=[GW])))
    assert [h.details["dst_ip"] for h in hits] == [HOST]
    assert r_dest_new.evaluate(make_ctx(rows)) == []


# ---------- R-SPIKE-01 ----------
def _spike_rows(minute_counts: dict[int, int]) -> list:
    cap = Cap()
    for minute, count in minute_counts.items():
        for i in range(count):
            cap.add(udp(ESP, EXT, 9999), minute * 60 + i * 5)
    return cap.rows()


def test_spike_two_consecutive_minutes() -> None:
    hits = r_spike.evaluate(make_ctx(_spike_rows({0: 8, 1: 8}), baseline(mean_ppm=2.0)))
    assert len(hits) == 1 and hits[0].details["minutes"] == 2 and len(hits[0].packet_refs) == 16


def test_spike_single_or_non_consecutive_minutes_ignored() -> None:
    assert r_spike.evaluate(make_ctx(_spike_rows({0: 8}), baseline(mean_ppm=2.0))) == []
    assert r_spike.evaluate(make_ctx(_spike_rows({0: 8, 1: 1, 2: 8}), baseline(mean_ppm=2.0))) == []


# ---------- R-MULTI-IND-01 ----------
def test_multi_ind() -> None:
    rows = Cap().add(tcp(ESP, EXT, 8443), 0).add(tcp(ESP, EXT, 8443), 1).add(tcp(ESP, EXT, 8443), 2).rows()
    ctx = make_ctx(rows)
    three = [RuleHit("R-BEACON-01", "P2", "r", {"a": 0.5}, [1]), RuleHit("R-EXT-DEST-01", "P2", "r", {"a": 0.5}, [2]),
             RuleHit("R-PATTERN-DEV-01", "P2", "r", {"a": 0.5}, [3])]
    hits = r_multi_ind.evaluate(ctx, three)
    assert len(hits) == 1 and hits[0].priority == "P1" and hits[0].packet_refs == [1, 2, 3]
    assert r_multi_ind.evaluate(ctx, three[:2]) == []


# ---------- R-WHITELIST-01 / R-DEFAULT-01 ----------
def test_whitelist_and_default_partition_remaining_traffic() -> None:
    rows = mqtt(Cap(), [0, 5, 10]).add(tcp(ESP, HOST, 8080), 15).rows()
    ctx = make_ctx(rows)
    wl = r_whitelist.evaluate_whitelist(ctx, set())
    df = r_whitelist.evaluate_default(ctx, {n for h in wl for n in h.packet_refs})
    assert [h.packet_refs for h in wl] == [[1, 2, 3]] and [h.packet_refs for h in df] == [[4]]
    assert wl[0].priority == df[0].priority == "P4"


# ---------- engine ----------
def _engine_rows() -> list:
    cap = mqtt(Cap(), [k * 5 for k in range(12)])
    cap.add(udp(ESP, NTP, 123, sport=123), 1).add(tcp(ESP, EXT, 80, payload=b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"), 2)
    for k in range(6):
        cap.add(tcp(ESP, EXT, 8443, sport=50200), 100 + k * 30)
    cap.add(dnsq("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.tunnel.test"), 300)
    return cap.rows()


def test_engine_covers_every_packet_and_is_deterministic() -> None:
    rows = _engine_rows()
    first = run_rules(make_ctx(rows))
    second = run_rules(make_ctx(_engine_rows()))
    assert {n for h in first for n in h.packet_refs} == {r["packet_number"] for r in rows}  # traceability
    assert [(h.rule_id, h.packet_refs, h.confidence) for h in first] == [(h.rule_id, h.packet_refs, h.confidence) for h in second]
    assert {"R-BEACON-01", "R-EXT-DEST-01", "R-DNS-LONG-01", "R-WHITELIST-01"} <= {h.rule_id for h in first}
    assert all(h.packet_refs and 0.0 <= h.confidence <= 1.0 for h in first)