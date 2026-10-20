"""R-DEST-NEW-01 (P3)."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit, is_unicast_target

RULE_ID = "R-DEST-NEW-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """First-ever contact with an internal destination absent from the baseline. Requires a baseline.

    Scope note: external first contacts are escalated to P2 by R-EXT-DEST-01, so this rule covers
    internal-to-internal contacts only, to avoid two findings for one destination.
    Whitelisted endpoints are exempt.
    """
    base, wl = ctx.baseline, ctx.whitelist
    if base is None:
        return []
    by_dst: dict[str, list[int]] = defaultdict(list)
    for p in ctx.packets:
        src, dst = p["src_ip"], p["dst_ip"]
        if not src or not dst or src == dst or not is_unicast_target(dst):
            continue
        if not (wl.is_internal(src) and wl.is_internal(dst)):
            continue
        if dst in base.dst_ips or wl.packet_match_label(p) is not None:
            continue
        by_dst[dst].append(p["packet_number"])
    return [RuleHit(RULE_ID, "P3", f"First contact with internal host {dst}; it was not seen in the baseline.",
                    {"not_in_baseline": 0.5}, refs, {"dst_ip": dst})
            for dst, refs in by_dst.items()]