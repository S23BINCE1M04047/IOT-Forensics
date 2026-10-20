"""R-EXT-DEST-01 (P2)."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit, is_unicast_target

RULE_ID = "R-EXT-DEST-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """Internal device contacts an external destination not seen in the baseline.

    Reasoning: a sensor-class device normally talks to a small, stable peer set.
    Inputs: packets with an internal source and a unicast destination outside the internal subnets.
    Exempt: packets matching the whitelist, and destinations present in the baseline.
    Without a baseline every non-whitelisted external destination qualifies, at reduced confidence.
    """
    wl = ctx.whitelist
    known = ctx.baseline.dst_ips if ctx.baseline else frozenset()
    by_dst: dict[str, list[int]] = defaultdict(list)
    for p in ctx.packets:
        src, dst = p["src_ip"], p["dst_ip"]
        if not src or not dst or not wl.is_internal(src):
            continue
        if wl.is_internal(dst) or not is_unicast_target(dst):
            continue
        if dst in known or wl.packet_match_label(p) is not None:
            continue
        by_dst[dst].append(p["packet_number"])

    hits: list[RuleHit] = []
    for dst, refs in by_dst.items():
        if ctx.baseline:
            reason = (f"Internal device contacted external address {dst}, which is outside the internal "
                      "subnets and absent from the baseline.")
            breakdown = {"outside_internal_subnets": 0.4, "not_in_baseline": 0.4}
        else:
            reason = (f"Internal device contacted external address {dst}, outside the internal subnets. "
                      "No baseline loaded, so novelty could not be assessed.")
            breakdown = {"outside_internal_subnets": 0.4, "no_baseline_loaded": 0.15}
        hits.append(RuleHit(RULE_ID, "P2", reason, breakdown, refs,
                            {"dst_ip": dst, "baseline_used": ctx.baseline is not None}))
    return hits