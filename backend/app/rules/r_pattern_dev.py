"""R-PATTERN-DEV-01 (P2)."""
from app.rules.base import RuleContext, RuleHit
from app.services.baseline import build_profile

RULE_ID = "R-PATTERN-DEV-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """Significant deviation from the baseline communication pattern. Requires a baseline.

    Metrics (any one exceeding its threshold fires the rule):
      - protocol mix: total-variation distance of protocol shares > pattern_proto_tvd
      - peer set: share of (src>dst) peers absent from baseline > pattern_peer_novel_ratio
      - packet rate: capture mean pkts/min / max(baseline mean, floor) > pattern_rate_ratio
    Refs: packets of novel peers or novel protocols; if none, packets of the protocol whose share grew most.
    """
    base = ctx.baseline
    if base is None or not ctx.packets:
        return []
    cfg = ctx.cfg
    cur = build_profile(ctx.packets)
    keys = set(cur.protocol_share) | set(base.protocol_share)
    tvd = 0.5 * sum(abs(cur.protocol_share.get(k, 0.0) - base.protocol_share.get(k, 0.0)) for k in keys)
    novel_peers = cur.peers - base.peers
    peer_ratio = len(novel_peers) / len(cur.peers) if cur.peers else 0.0
    rate_ratio = cur.mean_ppm / max(base.mean_ppm, cfg.spike_min_baseline_ppm)

    exceeded: list[str] = []
    if tvd > cfg.pattern_proto_tvd:
        exceeded.append("protocol_mix")
    if peer_ratio > cfg.pattern_peer_novel_ratio:
        exceeded.append("peer_set")
    if rate_ratio > cfg.pattern_rate_ratio:
        exceeded.append("packet_rate")
    if not exceeded:
        return []

    novel_protos = set(cur.protocol_share) - set(base.protocol_share)
    refs = [p["packet_number"] for p in ctx.packets
            if (p["src_ip"] and p["dst_ip"] and f"{p['src_ip']}>{p['dst_ip']}" in novel_peers)
            or p["protocol"] in novel_protos]
    if not refs:
        top = max(cur.protocol_share, key=lambda k: cur.protocol_share[k] - base.protocol_share.get(k, 0.0))
        refs = [p["packet_number"] for p in ctx.packets if p["protocol"] == top]

    return [RuleHit(
        RULE_ID, "P2",
        f"Communication pattern deviates from baseline ({', '.join(exceeded)}): protocol-mix distance {tvd:.2f}, "
        f"{peer_ratio:.0%} novel peers, packet rate x{rate_ratio:.1f}.",
        {"baseline_deviation": 0.5, **{f"{m}_exceeded": 0.15 for m in exceeded}},
        refs,
        {"protocol_tvd": round(tvd, 4), "novel_peer_ratio": round(peer_ratio, 4),
         "rate_ratio": round(rate_ratio, 3), "metrics_exceeded": exceeded},
    )]