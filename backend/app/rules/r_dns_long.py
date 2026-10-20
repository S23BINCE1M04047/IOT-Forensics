"""R-DNS-LONG-01 (P3)."""
import math
from collections import Counter, defaultdict

from app.rules.base import RuleContext, RuleHit
from app.services.baseline import is_dns_query

RULE_ID = "R-DNS-LONG-01"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """DNS name that is unusually long or contains a high-entropy label (tunnelling / DGA hint).

    Thresholds: name length > dns_max_name_len, or a label of at least dns_entropy_min_label_len
    characters with Shannon entropy >= dns_entropy_threshold bits/char. Does not need a baseline.
    Whitelisted domains are exempt.
    """
    cfg = ctx.cfg
    by_name: dict[str, list[int]] = defaultdict(list)
    for p in ctx.packets:
        if is_dns_query(p):
            by_name[str(p["dns_query"]).lower().rstrip(".")].append(p["packet_number"])
    hits: list[RuleHit] = []
    for name, refs in by_name.items():
        if ctx.whitelist.domain_label(name):
            continue
        long_name = len(name) > cfg.dns_max_name_len
        ents = [shannon_entropy(lb) for lb in name.split(".") if len(lb) >= cfg.dns_entropy_min_label_len]
        top = max(ents, default=0.0)
        high_entropy = top >= cfg.dns_entropy_threshold
        if not (long_name or high_entropy):
            continue
        why = []
        breakdown = {"base": 0.5}
        if long_name:
            why.append(f"name length {len(name)} > {cfg.dns_max_name_len}")
            breakdown["long_name"] = 0.2
        if high_entropy:
            why.append(f"label entropy {top:.2f} >= {cfg.dns_entropy_threshold}")
            breakdown["high_entropy_label"] = 0.2
        hits.append(RuleHit(RULE_ID, "P3", f'DNS query "{name}" looks unusual ({"; ".join(why)}); possible tunnelling or generated name.',
                            breakdown, refs,
                            {"domain": name, "length": len(name), "max_label_entropy": round(top, 3)}))
    return hits