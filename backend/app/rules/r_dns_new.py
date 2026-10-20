"""R-DNS-NEW-01 (P3)."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit
from app.services.baseline import is_dns_query

RULE_ID = "R-DNS-NEW-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """DNS query for a domain never seen in the baseline. Requires a baseline.

    Reasoning: IoT devices resolve a small fixed set of names; a new name can mean new
    behaviour, new firmware, or a covert channel. Exact (case-insensitive) match against the
    baseline's query set; domains on the whitelist are exempt.
    """
    if ctx.baseline is None:
        return []
    by_name: dict[str, list[int]] = defaultdict(list)
    for p in ctx.packets:
        if not is_dns_query(p):
            continue
        name = str(p["dns_query"]).lower().rstrip(".")
        if name in ctx.baseline.dns_domains or ctx.whitelist.domain_label(name):
            continue
        by_name[name].append(p["packet_number"])
    return [RuleHit(RULE_ID, "P3", f'DNS query for "{name}", never seen in the baseline.',
                    {"not_in_baseline": 0.6}, refs, {"domain": name})
            for name, refs in by_name.items()]