"""Shared rule types: context, hit, whitelist, threat intel, IP helpers."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

from app.services.baseline import BaselineProfile, ParsedRow
from app.services.prioritizer_config import PrioritizerConfig

Priority = Literal["P1", "P2", "P3", "P4"]
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=65536)
def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


@lru_cache(maxsize=65536)
def is_unicast_target(ip: str) -> bool:
    """False for multicast, loopback, link-local, unspecified and reserved (incl. 255.255.255.255)."""
    a = parse_ip(ip)
    return a is not None and not (a.is_multicast or a.is_loopback or a.is_link_local
                                  or a.is_unspecified or a.is_reserved)


def suffix_match(name: str, mapping: dict[str, str]) -> str | None:
    """Return the key of `mapping` equal to `name` or a parent domain of it."""
    parts = name.lower().rstrip(".").split(".")
    for i in range(len(parts)):
        cand = ".".join(parts[i:])
        if cand in mapping:
            return cand
    return None


@dataclass(frozen=True)
class Whitelist:
    internal_subnets: tuple[IPNetwork, ...]
    endpoints: dict[tuple[str, int | None], str]  # (ip, port|None=any) -> label
    domains: dict[str, str]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Whitelist:
        nets = tuple(ipaddress.ip_network(n, strict=False) for n in raw.get("internal_subnets", []))
        eps = {(e["ip"], e.get("port")): e.get("label", "whitelisted endpoint") for e in raw.get("endpoints", [])}
        doms = {d["name"].lower().rstrip("."): d.get("label", "whitelisted domain") for d in raw.get("domains", [])}
        return cls(nets, eps, doms)

    def is_internal(self, ip: str) -> bool:
        a = parse_ip(ip)
        return a is not None and any(a in n for n in self.internal_subnets)

    def domain_label(self, name: str) -> str | None:
        key = suffix_match(name, self.domains)
        return self.domains[key] if key else None

    def packet_match_label(self, row: ParsedRow) -> str | None:
        """Label of the whitelist entry this packet matches (either direction), else None."""
        for ip, port in ((row.get("dst_ip"), row.get("dst_port")), (row.get("src_ip"), row.get("src_port"))):
            if ip is None:
                continue
            label = self.endpoints.get((ip, port)) or self.endpoints.get((ip, None))
            if label:
                return label
        q = row.get("dns_query")
        return self.domain_label(q) if q else None


@dataclass(frozen=True)
class ThreatIntel:
    ips: dict[str, str]
    domains: dict[str, str]


@dataclass
class RuleContext:
    packets: list[ParsedRow]
    cfg: PrioritizerConfig
    whitelist: Whitelist
    ti: ThreatIntel
    baseline: BaselineProfile | None = None
    stream_of: dict[int, str] = field(init=False)
    by_number: dict[int, ParsedRow] = field(init=False)

    def __post_init__(self) -> None:
        self.by_number = {p["packet_number"]: p for p in self.packets}
        self.stream_of = {p["packet_number"]: (p["stream_id"] or f"none-{p['protocol']}") for p in self.packets}


@dataclass
class RuleHit:
    rule_id: str
    priority: Priority
    reason: str
    breakdown: dict[str, float]  # confidence = clamp(sum(components), 0, 1)
    packet_refs: list[int]
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.packet_refs = sorted(set(self.packet_refs))

    @property
    def confidence(self) -> float:
        return round(min(1.0, max(0.0, sum(self.breakdown.values()))), 3)