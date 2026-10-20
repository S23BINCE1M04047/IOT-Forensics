"""R-MULTI-IND-01 (P1)."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit

RULE_ID = "R-MULTI-IND-01"


def evaluate(ctx: RuleContext, hits: list[RuleHit]) -> list[RuleHit]:
    """A single connection triggers >= multi_indicator_min distinct P2 rules.

    Reasoning: independent weak-to-moderate signals converging on one connection are stronger
    than any one alone. A hit is attributed to a connection when any of its packet refs belong to
    that stream. v1 has exactly three P2 rules, so firing needs all three on the same stream.
    """
    cfg = ctx.cfg
    per_stream: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    for h in hits:
        if h.rule_id not in cfg.p2_rule_ids:
            continue
        for n in h.packet_refs:
            per_stream[ctx.stream_of[n]][h.rule_id].add(n)
    out: list[RuleHit] = []
    for sid, by_rule in per_stream.items():
        if len(by_rule) < cfg.multi_indicator_min:
            continue
        refs = sorted(set().union(*by_rule.values()))
        n_ind = len(by_rule)
        out.append(RuleHit(
            RULE_ID, "P1",
            f"One connection triggered {n_ind} independent P2 indicators ({', '.join(sorted(by_rule))}).",
            {"combined_p2_indicators": min(0.95, 0.65 + 0.1 * (n_ind - cfg.multi_indicator_min))},
            refs, {"stream_id": sid, "rule_ids": sorted(by_rule)},
        ))
    return out