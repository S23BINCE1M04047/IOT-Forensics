"""R-SPIKE-01 (P3)."""
from collections import defaultdict

from app.rules.base import RuleContext, RuleHit

RULE_ID = "R-SPIKE-01"


def evaluate(ctx: RuleContext) -> list[RuleHit]:
    """Traffic above spike_multiplier x baseline packets/minute for >= spike_min_minutes consecutive minutes.

    Inputs: per-minute packet counts (UTC minute buckets) and the baseline's mean packets/minute,
    floored at spike_min_baseline_ppm. Requires a baseline. Partial first/last minute buckets
    undercount, which errs on the side of not flagging.
    """
    base, cfg = ctx.baseline, ctx.cfg
    if base is None or base.mean_ppm <= 0:
        return []
    eff_base = max(base.mean_ppm, cfg.spike_min_baseline_ppm)
    threshold = cfg.spike_multiplier * eff_base
    buckets: dict[int, list[int]] = defaultdict(list)
    for p in ctx.packets:
        buckets[int(p["ts"] // 60)].append(p["packet_number"])
    runs: list[list[int]] = []
    for b in sorted(b for b, refs in buckets.items() if len(refs) > threshold):
        if runs and b == runs[-1][-1] + 1:
            runs[-1].append(b)
        else:
            runs.append([b])
    hits: list[RuleHit] = []
    for run in runs:
        if len(run) < cfg.spike_min_minutes:
            continue
        peak = max(len(buckets[b]) for b in run)
        ratio = peak / eff_base
        hits.append(RuleHit(
            RULE_ID, "P3",
            f"Packet rate peaked at {peak}/min ({ratio:.1f}x baseline {eff_base:.1f}/min) "
            f"for {len(run)} consecutive minutes.",
            {"base": 0.55,
             "magnitude": round(max(0.0, min(0.25, 0.05 * (ratio - cfg.spike_multiplier))), 3),
             "duration": round(min(0.15, 0.05 * (len(run) - cfg.spike_min_minutes + 1)), 3)},
            [n for b in run for n in buckets[b]],
            {"minutes": len(run), "peak_ppm": peak, "baseline_ppm": round(eff_base, 3), "ratio": round(ratio, 3)},
        ))
    return hits