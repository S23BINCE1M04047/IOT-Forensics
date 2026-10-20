"""Findings: paginated/filterable list, detail with evidence, analyst override."""
import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Capture, Finding, Packet, utcnow
from app.schemas import ApiException, Envelope, OverrideIn, _utc_iso, epoch_to_iso, ok

router = APIRouter(prefix="/api", tags=["findings"])

PRIORITIES = ("P1", "P2", "P3", "P4")
EFFECTIVE = func.coalesce(Finding.overridden_priority, Finding.priority)
SORTABLE: dict[str, Any] = {
    "timestamp": Finding.ts_first, "src": Finding.src_ip, "dst": Finding.dst_ip, "protocol": Finding.protocol,
    "priority": EFFECTIVE, "reason": Finding.reason, "confidence": Finding.confidence,
    "packet_refs": Finding.packet_ref_count,
}
DETAIL_PACKET_LIMIT = 200


def _iso(d: datetime | None) -> str | None:
    return _utc_iso(d) if d else None


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "finding_id": f.id, "capture_id": f.capture_id,
        "priority": f.overridden_priority or f.priority, "original_priority": f.priority,
        "overridden": f.overridden_priority is not None,
        "rule_id": f.rule_id, "reason": f.reason, "confidence": f.confidence,
        "confidence_breakdown": json.loads(f.confidence_breakdown_json),
        "packet_refs": json.loads(f.packet_refs_json), "packet_ref_count": f.packet_ref_count,
        "ts_first": f.ts_first, "ts_first_utc": epoch_to_iso(f.ts_first), "ts_last": f.ts_last,
        "src_ip": f.src_ip, "dst_ip": f.dst_ip, "protocol": f.protocol, "stream_id": f.stream_id,
        "details": json.loads(f.details_json),
        "analyst_note": f.analyst_note, "overridden_at": _iso(f.overridden_at), "overridden_by": f.overridden_by,
        "created_at": _iso(f.created_at),
    }


def wireshark_filter(refs: list[int]) -> str:
    """Compress packet numbers into a Wireshark display filter, e.g. frame.number in {3 7 10..15}."""
    parts: list[str] = []
    start = prev = refs[0]
    for n in refs[1:] + [-1]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(str(start) if start == prev else f"{start}..{prev}")
        start = prev = n
    return "frame.number in {" + " ".join(parts) + "}"


@router.get("/findings/{finding_id:int}", response_model=Envelope)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> Envelope:
    f = db.get(Finding, finding_id)
    if f is None:
        raise ApiException(404, "not_found", f"No finding with id {finding_id}.")
    out = finding_dict(f)
    shown = out["packet_refs"][:DETAIL_PACKET_LIMIT]
    rows = db.scalars(select(Packet).where(Packet.capture_id == f.capture_id, Packet.packet_number.in_(shown))
                      .order_by(Packet.packet_number)).all()
    out["packets"] = [{
        "packet_number": r.packet_number, "ts": r.ts, "ts_utc": epoch_to_iso(r.ts),
        "src_ip": r.src_ip, "dst_ip": r.dst_ip, "src_port": r.src_port, "dst_port": r.dst_port,
        "protocol": r.protocol, "length": r.length, "ttl": r.ttl, "flags": r.flags,
        "dns_query": r.dns_query, "dns_qtype": r.dns_qtype, "dns_answers": r.dns_answers,
        "http_method": r.http_method, "http_host": r.http_host, "http_uri": r.http_uri,
        "http_user_agent": r.http_user_agent, "payload_preview": r.payload_preview, "stream_id": r.stream_id,
    } for r in rows]
    out["packets_shown"] = len(rows)
    out["wireshark_filter"] = wireshark_filter(out["packet_refs"])
    return ok(out)


@router.patch("/findings/{finding_id:int}", response_model=Envelope)
def override_finding(finding_id: int, body: OverrideIn, db: Session = Depends(get_db)) -> Envelope:
    f = db.get(Finding, finding_id)
    if f is None:
        raise ApiException(404, "not_found", f"No finding with id {finding_id}.")
    f.overridden_priority = body.priority  # None clears the override
    f.analyst_note = body.analyst_note
    f.overridden_by = body.analyst
    f.overridden_at = utcnow()
    db.commit()
    return ok(finding_dict(f))


@router.get("/findings/{file_id}", response_model=Envelope)
def list_findings(
    file_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    priority: str | None = Query(None, description="comma list, e.g. P1,P2 (effective priority)"),
    protocol: str | None = Query(None, max_length=16),
    ip: str | None = Query(None, max_length=64),
    rule_id: str | None = Query(None, max_length=32),
    ts_from: float | None = Query(None),
    ts_to: float | None = Query(None),
    sort_by: str = Query("priority"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
) -> Envelope:
    if db.get(Capture, file_id) is None:
        raise ApiException(404, "not_found", f"No capture with id {file_id}.")
    if sort_by not in SORTABLE:
        raise ApiException(400, "bad_sort", f"sort_by must be one of {sorted(SORTABLE)}.")

    stmt = select(Finding).where(Finding.capture_id == file_id)
    if priority:
        wanted = [p for p in priority.split(",") if p in PRIORITIES]
        stmt = stmt.where(EFFECTIVE.in_(wanted))
    if protocol:
        stmt = stmt.where(Finding.protocol == protocol.upper())
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if ip:
        like = f"%{ip.strip()}%"
        stmt = stmt.where(or_(Finding.src_ip.like(like), Finding.dst_ip.like(like)))
    if ts_from is not None:
        stmt = stmt.where(Finding.ts_last >= ts_from)
    if ts_to is not None:
        stmt = stmt.where(Finding.ts_first <= ts_to)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    col = SORTABLE[sort_by]
    primary = col.desc() if sort_dir == "desc" else col.asc()
    rows = db.scalars(stmt.order_by(primary, Finding.ts_first.asc(), Finding.id.asc())
                      .offset((page - 1) * page_size).limit(page_size)).all()
    return ok({"items": [finding_dict(r) for r in rows], "total": total, "page": page, "page_size": page_size})