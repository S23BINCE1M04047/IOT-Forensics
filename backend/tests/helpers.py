"""Synthetic-PCAP builders: packets are written with Scapy, re-parsed by the real parser."""
import tempfile
from collections.abc import Iterable
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

from app.rules.base import RuleContext, ThreatIntel, Whitelist
from app.services.baseline import BaselineProfile, ParsedRow
from app.services.pcap_parser import iter_packets
from app.services.prioritizer_config import CONFIG
from tests.conftest import TMP

T0 = 1_760_000_040.0  # aligned to a UTC minute boundary (divisible by 60)
ESP, GW, BROKER, EXT, NTP, HOST = "192.168.1.50", "192.168.1.1", "192.168.1.10", "203.0.113.77", "198.51.100.123", "192.168.1.77"

WHITELIST = Whitelist.from_dict({
    "internal_subnets": ["192.168.0.0/16", "10.0.0.0/8"],
    "endpoints": [{"ip": BROKER, "port": 1883, "label": "MQTT broker"},
                  {"ip": GW, "port": 53, "label": "Gateway DNS"},
                  {"ip": NTP, "port": 123, "label": "NTP"}],
    "domains": [{"name": "pool.ntp.org", "label": "NTP pool"}],
})


class Cap:
    def __init__(self) -> None:
        self.pkts: list = []

    def add(self, layer: object, at: float) -> "Cap":
        p = Ether() / layer
        p.time = T0 + at
        self.pkts.append(p)
        return self

    def write(self, path: Path) -> Path:
        wrpcap(str(path), self.pkts)
        return path

    def rows(self) -> list[ParsedRow]:
        path = Path(tempfile.mkdtemp(dir=TMP)) / "t.pcap"
        return list(iter_packets(self.write(path)))


def tcp(src: str, dst: str, dport: int, sport: int = 50000, payload: bytes = b"x") -> object:
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(payload)


def udp(src: str, dst: str, dport: int, sport: int = 4000) -> object:
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"x")


def dnsq(name: str, src: str = ESP, dst: str = GW) -> object:
    return IP(src=src, dst=dst) / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))


def mqtt(at_cap: Cap, offsets: Iterable[float]) -> Cap:
    for t in offsets:
        at_cap.add(tcp(ESP, BROKER, 1883, payload=b"\x30\x1a\x00\x0bsensor/temp"), t)
    return at_cap


def ti(ips: dict[str, str] | None = None, domains: dict[str, str] | None = None) -> ThreatIntel:
    return ThreatIntel(ips=ips or {}, domains=domains or {})


def baseline(dst_ips: Iterable[str] = (), domains: Iterable[str] = (), mean_ppm: float = 1.0) -> BaselineProfile:
    return BaselineProfile(frozenset(dst_ips), frozenset(domains), {}, frozenset(), mean_ppm, 1)


def make_ctx(rows: list[ParsedRow], base: BaselineProfile | None = None, intel: ThreatIntel | None = None) -> RuleContext:
    return RuleContext(packets=rows, cfg=CONFIG, whitelist=WHITELIST, ti=intel or ti(), baseline=base)