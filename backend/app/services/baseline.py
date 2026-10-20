"""Baseline communication profile plus helpers shared by rules and the baseline endpoints."""
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

ParsedRow = dict[str, Any]
DNS_PORTS = (53, 5353, 5355)


def is_dns_query(row: ParsedRow) -> bool:
    """A DNS packet addressed to a resolver port (responses are excluded)."""
    return bool(row.get("dns_query")) and row.get("dst_port") in DNS_PORTS


@dataclass(frozen=True)
class BaselineProfile:
    dst_ips: frozenset[str]
    dns_domains: frozenset[str]
    protocol_share: dict[str, float]
    peers: frozenset[str]  # "src>dst"
    mean_ppm: float        # mean packets per minute bucket over the baseline capture
    packet_count: int

    def to_json(self) -> str:
        return json.dumps({
            "dst_ips": sorted(self.dst_ips),
            "dns_domains": sorted(self.dns_domains),
            "protocol_share": self.protocol_share,
            "peers": sorted(self.peers),
            "mean_ppm": self.mean_ppm,
            "packet_count": self.packet_count,
        })

    @classmethod
    def from_json(cls, raw: str) -> "BaselineProfile":
        d = json.loads(raw)
        return cls(frozenset(d["dst_ips"]), frozenset(d["dns_domains"]), dict(d["protocol_share"]),
                   frozenset(d["peers"]), float(d["mean_ppm"]), int(d["packet_count"]))


def build_profile(rows: Iterable[ParsedRow]) -> BaselineProfile:
    dst_ips: set[str] = set()
    domains: set[str] = set()
    peers: set[str] = set()
    protos: Counter[str] = Counter()
    buckets: Counter[int] = Counter()
    n = 0
    for r in rows:
        n += 1
        protos[r["protocol"]] += 1
        buckets[int(r["ts"] // 60)] += 1
        s, d = r.get("src_ip"), r.get("dst_ip")
        if s and d:
            dst_ips.add(d)
            peers.add(f"{s}>{d}")
        if is_dns_query(r):
            domains.add(str(r["dns_query"]).lower())
    span = (max(buckets) - min(buckets) + 1) if buckets else 1
    share = {k: v / n for k, v in protos.items()} if n else {}
    return BaselineProfile(frozenset(dst_ips), frozenset(domains), share, frozenset(peers),
                           (n / span) if n else 0.0, n)