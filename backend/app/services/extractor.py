"""Loads the engine's inputs: whitelist, threat intel, and parsed packets from the DB."""
import csv
import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Packet
from app.rules.base import ThreatIntel, Whitelist
from app.services.baseline import ParsedRow
from app.services.hasher import sha256_file

_DEFAULT_SUBNETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10", "fc00::/7"]


def load_whitelist(path: Path) -> Whitelist:
    if not path.exists():
        return Whitelist.from_dict({"internal_subnets": _DEFAULT_SUBNETS})
    return Whitelist.from_dict(json.loads(path.read_text(encoding="utf-8")))


def load_threat_intel(path: Path) -> ThreatIntel:
    ips: dict[str, str] = {}
    domains: dict[str, str] = {}
    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ind = (row.get("indicator") or "").strip().lower()
                kind = (row.get("type") or "").strip().lower()
                desc = (row.get("description") or "").strip() or "threat-intel entry"
                if not ind:
                    continue
                if kind == "ip":
                    ips[ind] = desc
                elif kind == "domain":
                    domains[ind.rstrip(".")] = desc
    return ThreatIntel(ips=ips, domains=domains)


def file_fingerprint(path: Path) -> str:
    return sha256_file(path) if path.exists() else "missing"


def load_packet_rows(db: Session, capture_id: str) -> list[ParsedRow]:
    """Load the columns the rules need, ordered by packet number (Wireshark frame number)."""
    stmt = (
        select(Packet.packet_number, Packet.ts, Packet.src_ip, Packet.dst_ip, Packet.src_port, Packet.dst_port,
               Packet.protocol, Packet.length, Packet.flags, Packet.dns_query, Packet.dns_answers,
               Packet.http_host, Packet.stream_id)
        .where(Packet.capture_id == capture_id)
        .order_by(Packet.packet_number)
    )
    return [dict(m) for m in db.execute(stmt).mappings()]