"""R-BEACON-01 (P2)."""
import statistics
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit, is_unicast_target

RULE_ID = "R-BEACON-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """Repeated contact with the same destination at near-regular intervals.

    Reasoning: implants and misbehaving firmware often "phone home" on a timer; human or
    event-driven traffic has high jitter.
    Inputs: packets from internal sources, grouped by (src_ip, dst_ip, dst_port).
    Method: packets closer than beacon_burst_gap_s form one event; intervals are gaps between event starts.
    Thresholds: >= beacon_min_repetitions events AND population stdev/mean of intervals < beacon_max_cv.
    Whitelisted endpoints are exempt so routine MQTT/NTP/DNS cadence does not trip it.
    """
    cfg = ctx.cfg
    groups: dict[tuple[str, str, int], list[tuple[float, int]]] = defaultdict(list)
    for p in ctx.packets:
        src, dst = p["src_ip"], p["dst_ip"]
        if not src or not dst or p["protocol"] in cfg.beacon_ignore_protocols:
            continue
        if not is_unicast_target(dst) or not ctx.whitelist.is_internal(src):
            continue
        if ctx.whitelist.packet_match_label(p) is not None:
            continue
        groups[(src, dst, p["dst_port"] or 0)].append((p["ts"], p["packet_number"]))

    hits: list[RuleHit] = []
    for (src, dst, dport), items in groups.items():
        items.sort()
        starts = [items[0][0]]
        for (prev_t, _), (t, _) in zip(items, items[1:]):
            if t - prev_t > cfg.beacon_burst_gap_s:
                starts.append(t)
        if len(starts) < cfg.beacon_min_repetitions:
            continue
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        mean = statistics.fmean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv >= cfg.beacon_max_cv:
            continue
        n = len(starts)
        hits.append(RuleHit(
            RULE_ID, "P2",
            f"{src} contacted {dst}:{dport} {n} times at near-regular intervals "
            f"(mean {mean:.1f}s, jitter {cv:.2f} < {cfg.beacon_max_cv}); possible beaconing, not proof of compromise.",
            {"base": 0.5,
             "low_jitter": round(0.3 * (1 - cv / cfg.beacon_max_cv), 3),
             "repetitions": round(0.2 * min(1.0, (n - cfg.beacon_min_repetitions) / (2 * cfg.beacon_min_repetitions)), 3)},
            [num for _, num in items],
            {"src_ip": src, "dst_ip": dst, "dst_port": dport, "events": n,
             "mean_interval_s": round(mean, 3), "jitter_cv": round(cv, 4)},
        ))
    return hits