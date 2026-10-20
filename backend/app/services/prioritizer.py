"""Deterministic rule engine. Priority = investigation priority, NOT proof of attack."""
import json
from types import ModuleType

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import AnalysisRun, Baseline, Finding, utcnow
from app.rules import (r_beacon, r_dest_new, r_dns_long, r_dns_new, r_ext_dest, r_multi_ind,
                       r_pattern_dev, r_spike, r_ti_match, r_whitelist)
from app.rules.base import RuleContext, RuleHit
from app.services.baseline import BaselineProfile
from app.services.extractor import file_fingerprint, load_packet_rows, load_threat_intel, load_whitelist
from app.services.prioritizer_config import CONFIG, RULESET_VERSION

DETECTION_RULES: tuple[ModuleType, ...] = (
    r_ti_match, r_beacon, r_ext_dest, r_pattern_dev, r_dns_new, r_dns_long, r_dest_new, r_spike,
)
PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _validate(hit: RuleHit) -> None:
    if not hit.packet_refs:
        raise ValueError(f"{hit.rule_id} produced a finding without packet refs (traceability violated).")
    if hit.priority not in PRIORITY_ORDER or not 0.0 <= hit.confidence <= 1.0:
        raise ValueError(f"{hit.rule_id} produced an invalid priority/confidence.")


def run_rules(ctx: RuleContext) -> list[RuleHit]:
    """Pure function of the context: same input, same output, same order."""
    hits: list[RuleHit] = []
    for module in DETECTION_RULES:
        hits.extend(module.evaluate(ctx))
    hits.extend(r_multi_ind.evaluate(ctx, hits))  # composite rule runs after the P2 rules

    flagged = {n for h in hits for n in h.packet_refs}
    wl_hits = r_whitelist.evaluate_whitelist(ctx, flagged)
    hits.extend(wl_hits)
    flagged |= {n for h in wl_hits for n in h.packet_refs}
    hits.extend(r_whitelist.evaluate_default(ctx, flagged))

    for h in hits:
        _validate(h)
    hits.sort(key=lambda h: (PRIORITY_ORDER[h.priority], h.packet_refs[0], h.rule_id, h.reason))
    return hits


def prioritize_capture(db: Session, capture_id: str, baseline_id: int | None) -> int:
    """Run the engine over a parsed capture and persist findings + a reproducibility record."""
    cfg = CONFIG
    started = utcnow()
    whitelist = load_whitelist(cfg.whitelist_path)
    ti = load_threat_intel(cfg.threat_intel_path)

    baseline: BaselineProfile | None = None
    baseline_name: str | None = None
    if baseline_id is not None:
        b = db.get(Baseline, baseline_id)
        if b is None:
            raise ValueError(f"Baseline {baseline_id} not found.")
        baseline, baseline_name = BaselineProfile.from_json(b.config_json), b.name

    rows = load_packet_rows(db, capture_id)
    ctx = RuleContext(packets=rows, cfg=cfg, whitelist=whitelist, ti=ti, baseline=baseline)
    hits = run_rules(ctx) if rows else []

    # Carry analyst overrides across re-analysis when the same rule fires on the same packets.
    kept = {
        (f.rule_id, f.packet_refs_json): (f.overridden_priority, f.analyst_note, f.overridden_at, f.overridden_by)
        for f in db.scalars(select(Finding).where(Finding.capture_id == capture_id, Finding.overridden_at.is_not(None)))
    }
    db.execute(delete(Finding).where(Finding.capture_id == capture_id))

    for hit in hits:
        total = len(hit.packet_refs)
        refs = hit.packet_refs[: cfg.max_packet_refs]
        pkts = [ctx.by_number[n] for n in refs]
        first = pkts[0]
        details = {**hit.details, "packet_ref_total": total}
        refs_json = json.dumps(refs)
        f = Finding(
            capture_id=capture_id, priority=hit.priority, rule_id=hit.rule_id, reason=hit.reason,
            confidence=hit.confidence, confidence_breakdown_json=json.dumps(hit.breakdown),
            packet_refs_json=refs_json, packet_ref_count=total,
            ts_first=min(p["ts"] for p in pkts), ts_last=max(p["ts"] for p in pkts),
            src_ip=hit.details.get("src_ip", first["src_ip"]), dst_ip=hit.details.get("dst_ip", first["dst_ip"]),
            protocol=first["protocol"], stream_id=ctx.stream_of[refs[0]],
            details_json=json.dumps(details), created_at=utcnow(),
        )
        prev = kept.get((hit.rule_id, refs_json))
        if prev:
            f.overridden_priority, f.analyst_note, f.overridden_at, f.overridden_by = prev
        db.add(f)

    snapshot = {
        "thresholds": cfg.snapshot(),
        "whitelist_sha256": file_fingerprint(cfg.whitelist_path),
        "threat_intel_sha256": file_fingerprint(cfg.threat_intel_path),
        "baseline": {"id": baseline_id, "name": baseline_name},
    }
    db.add(AnalysisRun(capture_id=capture_id, baseline_id=baseline_id, ruleset_version=RULESET_VERSION,
                       config_json=json.dumps(snapshot), started_at=started, finished_at=utcnow(),
                       finding_count=len(hits)))
    db.commit()
    return len(hits)