"""R-WHITELIST-01 and R-DEFAULT-01 (both P4). One finding per connection."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit

RULE_ID_WHITELIST = "R-WHITELIST-01"
RULE_ID_DEFAULT = "R-DEFAULT-01"


def evaluate_whitelist(ctx: RuleContext, flagged: set[int]) -> list[RuleHit]:
    """Routine traffic matching a configured whitelist entry (ESP32 endpoints, NTP, known MQTT broker).

    Only packets not already flagged by a P1-P3 rule are considered, so a whitelisted endpoint
    can still surface in a higher-priority finding. Grouped per connection (stream).
    """
    refs: dict[str, list[int]] = defaultdict(list)
    labels: dict[str, set[str]] = defaultdict(set)
    for p in ctx.packets:
        n = p["packet_number"]
        if n in flagged:
            continue
        label = ctx.whitelist.packet_match_label(p)
        if label:
            refs[ctx.stream_of[n]].append(n)
            labels[ctx.stream_of[n]].add(label)
    return [RuleHit(RULE_ID_WHITELIST, "P4",
                    f"Matches configured whitelist ({', '.join(sorted(labels[sid]))}); routine traffic.",
                    {"whitelist_match": 0.9}, nums, {"stream_id": sid, "labels": sorted(labels[sid])})
            for sid, nums in refs.items()]


def evaluate_default(ctx: RuleContext, covered: set[int]) -> list[RuleHit]:
    """Fallback for everything no other rule claimed. Guarantees every packet is covered by a finding."""
    refs: dict[str, list[int]] = defaultdict(list)
    for p in ctx.packets:
        if p["packet_number"] not in covered:
            refs[ctx.stream_of[p["packet_number"]]].append(p["packet_number"])
    return [RuleHit(RULE_ID_DEFAULT, "P4", "No rule flagged this traffic; routine by default.",
                    {"fallback": 0.5}, nums, {"stream_id": sid})
            for sid, nums in refs.items()]