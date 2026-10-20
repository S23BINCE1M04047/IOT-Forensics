"""R-TI-MATCH-01 (P1)."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit, suffix_match

RULE_ID = "R-TI-MATCH-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """Traffic involving an indicator from the local threat-intel list.

    Reasoning: a match against curated indicators is the strongest single signal available offline.
    Inputs: packets (src/dst IP, DNS query, DNS answers, HTTP host) and ctx.ti (ip/domain indicators).
    Thresholds: none (exact IP match; domain match includes subdomains).
    Output: one finding per matching indicator; refs are every packet involving it.
    Priority is a reason to investigate, not proof of compromise.
    """
    ti = ctx.ti
    if not ti.ips and not ti.domains:
        return []
    refs: dict[tuple[str, str], list[int]] = defaultdict(list)
    for p in ctx.packets:
        n = p["packet_number"]
        candidates = [p["src_ip"], p["dst_ip"]]
        if p["dns_answers"]:
            candidates.extend(a.strip() for a in p["dns_answers"].split(","))
        for ip in candidates:
            if ip and ip in ti.ips:
                refs[("ip", ip)].append(n)
        for name in (p["dns_query"], p["http_host"]):
            if name:
                dom = suffix_match(name.split(":")[0], ti.domains)
                if dom:
                    refs[("domain", dom)].append(n)
    hits: list[RuleHit] = []
    for (kind, ind), nums in refs.items():
        desc = ti.ips[ind] if kind == "ip" else ti.domains[ind]
        hits.append(RuleHit(
            RULE_ID, "P1",
            f"Traffic involves threat-intel {kind} indicator {ind} ({desc}). Investigate; a list match is not proof of compromise.",
            {"ti_list_match": 0.85, f"indicator_type_{kind}": 0.10 if kind == "ip" else 0.05},
            nums, {"indicator": ind, "indicator_type": kind, "description": desc},
        ))
    return hits