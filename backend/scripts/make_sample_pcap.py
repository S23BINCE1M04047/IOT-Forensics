"""Generate a small synthetic ESP32-style capture: python scripts/make_sample_pcap.py"""
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

OUT = Path(__file__).resolve().parent.parent / "uploads" / "sample" / "sample.pcap"
ESP, GW, BROKER, NTP, EXT = "192.168.1.50", "192.168.1.1", "192.168.1.10", "198.51.100.123", "203.0.113.77"
t = 1_760_000_000.0
pkts: list = []


def add(p, dt: float = 0.5) -> None:
    global t
    t += dt
    pkt = Ether() / p
    pkt.time = t
    pkts.append(pkt)


add(IP(src=ESP, dst=GW) / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname="pool.ntp.org")))
add(IP(src=GW, dst=ESP) / UDP(sport=53, dport=40000) /
    DNS(qr=1, qd=DNSQR(qname="pool.ntp.org"), an=DNSRR(rrname="pool.ntp.org", rdata=NTP)))
add(IP(src=ESP, dst=NTP) / UDP(sport=123, dport=123) / Raw(b"\x1b" + b"\x00" * 47))
for i in range(12):  # routine MQTT telemetry
    add(IP(src=ESP, dst=BROKER) / TCP(sport=50000, dport=1883, flags="PA") /
        Raw(b"\x30\x1a\x00\x0bsensor/temp22.5C"), dt=5)
add(IP(src=ESP, dst=GW) / UDP(sport=40001, dport=53) / DNS(rd=1, qd=DNSQR(qname="update.example-cdn.test")))
add(IP(src=ESP, dst=EXT) / TCP(sport=50100, dport=80, flags="PA") /
    Raw(b"GET /fw/check HTTP/1.1\r\nHost: update.example-cdn.test\r\nUser-Agent: ESP32-HTTP\r\n\r\n"))
for _ in range(6):  # regular-interval external contact (Phase 2 beacon test material)
    add(IP(src=ESP, dst=EXT) / TCP(sport=50200, dport=8443, flags="PA") / Raw(b"\x17\x03\x03\x00\x10" + b"\xaa" * 16), dt=30)
add(IP(src=ESP, dst=GW) / UDP(sport=40002, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6.tunnel.test")))

OUT.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(OUT), pkts)
print(f"Wrote {len(pkts)} packets to {OUT}")