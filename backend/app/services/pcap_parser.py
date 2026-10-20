"""Low-level PCAP parsing with Scapy. Read-only: the original file is never modified."""
import hashlib
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR, dnsqtypes
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet as ScapyPacket
from scapy.packet import Padding
from scapy.utils import PcapReader

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
L3_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPV6"}
PREVIEW_LIMIT = 200

ParsedRow = dict[str, Any]


def sniff_format(head: bytes) -> str | None:
    """Identify capture format from the first 4 bytes. Returns 'pcap', 'pcapng' or None."""
    magic = head[:4]
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return None


def printable_preview(data: bytes, limit: int = PREVIEW_LIMIT) -> str | None:
    """Printable-ASCII preview of up to `limit` bytes, or None if the data is binary/empty."""
    if not data:
        return None
    chunk = data[:limit]
    if all(32 <= b < 127 or b in (9, 10, 13) for b in chunk):
        return chunk.decode("ascii")
    return None


def make_stream_id(l4: str, src: str | None, sport: int | None, dst: str | None, dport: int | None) -> str | None:
    """Bidirectional 5-tuple hash: both directions of a flow share one stream id."""
    if src is None or dst is None:
        return None
    a, b = sorted([(src, sport or 0), (dst, dport or 0)])
    return hashlib.sha256(f"{l4}|{a}|{b}".encode()).hexdigest()[:16]


def _first_dnsqr(qd: Any) -> Any | None:
    if qd is None:
        return None
    if isinstance(qd, DNSQR):
        return qd
    try:
        return qd[0] if len(qd) else None
    except Exception:  # noqa: BLE001 - scapy version differences
        return None


def _iter_rr(rr: Any) -> Iterator[Any]:
    """Iterate DNS resource records across scapy versions (list or payload chain)."""
    if rr is None:
        return
    if isinstance(rr, (list, tuple)):
        yield from rr
        return
    cur: Any = rr
    while isinstance(cur, DNSRR):
        yield cur
        cur = cur.payload


def _parse_dns(dns: Any) -> tuple[str | None, str | None, str | None]:
    qr = _first_dnsqr(dns.qd)
    name: str | None = None
    qtype: str | None = None
    if qr is not None:
        raw = qr.qname
        name = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)).rstrip(".")
        qtype = str(dnsqtypes.get(qr.qtype, qr.qtype))
    answers: list[str] = []
    for rr in _iter_rr(dns.an):
        if getattr(rr, "type", None) in (1, 28):  # A, AAAA
            answers.append(str(rr.rdata))
    return name, qtype, ",".join(answers) or None


def _parse_http_request(data: bytes) -> tuple[str, str | None, str | None, str | None] | None:
    if not data.startswith(HTTP_METHODS):
        return None
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    method = parts[0]
    uri = parts[1] if len(parts) > 1 else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, headers.get("host"), uri, headers.get("user-agent")


def parse_packet(number: int, pkt: ScapyPacket) -> ParsedRow:
    """Extract the Phase-1 evidence fields from one Scapy packet."""
    src = dst = None
    sport = dport = ttl = None
    flags: str | None = None
    l4: str | None = None
    l3_proto: int | None = None

    if IP in pkt:
        ip = pkt[IP]
        src, dst, ttl, l3_proto = ip.src, ip.dst, int(ip.ttl), int(ip.proto)
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        src, dst, ttl, l3_proto = ip6.src, ip6.dst, int(ip6.hlim), int(ip6.nh)
    elif ARP in pkt:
        src, dst, l4 = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"

    payload = b""
    if TCP in pkt:
        t = pkt[TCP]
        l4, sport, dport, flags = "TCP", int(t.sport), int(t.dport), str(t.flags)
        payload = bytes(t.payload)
    elif UDP in pkt:
        u = pkt[UDP]
        l4, sport, dport = "UDP", int(u.sport), int(u.dport)
        payload = bytes(u.payload)
    elif ICMP in pkt:
        ic = pkt[ICMP]
        l4, flags = "ICMP", f"type={ic.type},code={ic.code}"
    if Padding in pkt and payload:  # strip Ethernet trailer padding
        pad = len(pkt[Padding].load)
        payload = payload[: max(len(payload) - pad, 0)]
    if l4 is None:
        if l3_proto is not None:
            l4 = L3_PROTO_NAMES.get(l3_proto, f"IP-{l3_proto}")
        elif Ether in pkt:
            l4 = f"ETH-{pkt[Ether].type:#06x}"
        else:
            l4 = "OTHER"

    protocol = l4
    dns_query = dns_qtype = dns_answers = None
    http_method = http_host = http_uri = http_ua = None

    if DNS in pkt:
        protocol = "DNS"
        dns_query, dns_qtype, dns_answers = _parse_dns(pkt[DNS])
    elif l4 == "TCP":
        http = _parse_http_request(payload)
        if http:
            protocol = "HTTP"
            http_method, http_host, http_uri, http_ua = http
        elif payload.startswith(b"HTTP/"):
            protocol = "HTTP"
        elif 1883 in (sport, dport):
            protocol = "MQTT"
        elif payload[:2] in (b"\x16\x03", b"\x17\x03", b"\x15\x03", b"\x14\x03"):
            protocol = "TLS"
    elif l4 == "UDP" and 123 in (sport, dport):
        protocol = "NTP"

    return {
        "packet_number": number,
        "ts": float(pkt.time),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": protocol,
        "length": len(pkt),
        "ttl": ttl,
        "flags": flags,
        "dns_query": dns_query,
        "dns_qtype": dns_qtype,
        "dns_answers": dns_answers,
        "http_method": http_method,
        "http_host": http_host,
        "http_uri": http_uri,
        "http_user_agent": http_ua,
        "payload_preview": printable_preview(payload),
        "stream_id": make_stream_id(l4, src, sport, dst, dport),
    }


def iter_packets(path: Path) -> Iterator[ParsedRow]:
    """Stream parsed packets. packet_number is 1-based (matches Wireshark frame.number)."""
    with PcapReader(str(path)) as reader:  # auto-detects pcap vs pcapng; opened read-only
        for number, pkt in enumerate(reader, start=1):
            yield parse_packet(number, pkt)


class ConnectionAggregator:
    """Aggregate packets into connections keyed by bidirectional stream_id."""

    def __init__(self) -> None:
        self._c: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def add(self, row: ParsedRow) -> None:
        sid = row["stream_id"]
        if sid is None:
            return
        c = self._c.get(sid)
        if c is None:
            self._c[sid] = {
                "stream_id": sid,
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": row["src_port"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "first_seen": row["ts"],
                "last_seen": row["ts"],
                "packet_count": 1,
                "byte_count": row["length"],
            }
            return
        c["packet_count"] += 1
        c["byte_count"] += row["length"]
        c["first_seen"] = min(c["first_seen"], row["ts"])
        c["last_seen"] = max(c["last_seen"], row["ts"])
        if c["protocol"] in ("TCP", "UDP") and row["protocol"] not in ("TCP", "UDP"):
            c["protocol"] = row["protocol"]  # upgrade to the application-level label

    def rows(self, capture_id: str) -> Iterable[dict[str, Any]]:
        for c in self._c.values():
            yield {**c, "capture_id": capture_id,
                   "connection_id": f"{c['stream_id']}-{int(c['first_seen'] * 1000)}"}