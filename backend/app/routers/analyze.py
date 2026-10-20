"""Analysis trigger, status, summary and raw packet listing."""
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy import Integer, cast, delete, func, or_, select
from sqlalchemy.orm import Session

from app.models import AnalysisRun, Baseline, Capture, Connection, Finding, Packet, utcnow
from app.services.prioritizer import prioritize_capture

from app.config import settings
from app.db import SessionLocal, get_db
from app.schemas import ApiException, CaptureOut, Envelope, StatusOut, epoch_to_iso, ok
from app.services.hasher import sha256_file
from app.services.pcap_parser import ConnectionAggregator, iter_packets

router = APIRouter(prefix="/api", tags=["analyze"])



def _get_capture(db: Session, file_id: str) -> Capture:
    cap = db.get(Capture, file_id)
    if cap is None:
        raise ApiException(404, "not_found", f"No capture with id {file_id}.")
    return cap


def run_analysis(capture_id: str, baseline_id: int | None = None) -> None:
    """Background job: parse packets, aggregate connections, prioritize, re-verify SHA-256."""
    db = SessionLocal()
    try:
        cap = db.get(Capture, capture_id)
        if cap is None:
            return
        cap.status, cap.error_message = "running", None
        db.commit()

        path = Path(cap.stored_path)
        db.execute(delete(Packet).where(Packet.capture_id == capture_id))  # re-analysis is idempotent
        db.execute(delete(Connection).where(Connection.capture_id == capture_id))
        db.commit()

        agg = ConnectionAggregator()
        batch: list[dict[str, Any]] = []
        for row in iter_packets(path):
            row["capture_id"] = capture_id
            batch.append(row)
            agg.add(row)
            if len(batch) >= settings.insert_batch_size:
                db.bulk_insert_mappings(Packet, batch)  # type: ignore[arg-type]
                db.commit()
                batch = []
        if batch:
            db.bulk_insert_mappings(Packet, batch)  # type: ignore[arg-type]
        db.bulk_insert_mappings(Connection, list(agg.rows(capture_id)))  # type: ignore[arg-type]
        db.commit()

        prioritize_capture(db, capture_id, baseline_id)  # Phase 2: rule engine

        digest = sha256_file(path)  # chain of custody: re-hash after analysis
        cap.analyzed_sha256 = digest
        cap.integrity_ok = digest == cap.sha256
        cap.analyzed_at = utcnow()
        cap.status = "done"
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        cap = db.get(Capture, capture_id)
        if cap is not None:
            cap.status, cap.error_message = "error", str(exc)[:500]
            db.commit()
    finally:
        db.close()


def _status_out(db: Session, cap: Capture) -> StatusOut:
    parsed = 0
    if cap.status in ("queued", "running", "done"):
        parsed = db.scalar(select(func.count()).select_from(Packet).where(Packet.capture_id == cap.id)) or 0
    warning = None
    if cap.integrity_ok is False:
        warning = "INTEGRITY WARNING: SHA-256 after analysis does not match the hash recorded at upload."
    return StatusOut(file_id=cap.id, status=cap.status, packets_parsed=parsed,
                     error_message=cap.error_message, integrity_ok=cap.integrity_ok, integrity_warning=warning)


@router.post("/analyze/{file_id}", response_model=Envelope)
def analyze(
    file_id: str,
    background: BackgroundTasks,
    baseline_id: int | None = Query(None, ge=1),
    db: Session = Depends(get_db),
) -> Envelope:
    cap = _get_capture(db, file_id)
    if cap.status in ("queued", "running"):
        raise ApiException(409, "already_running", "Analysis is already queued or running.")
    if baseline_id is not None and db.get(Baseline, baseline_id) is None:
        raise ApiException(404, "baseline_not_found", f"No baseline with id {baseline_id}.")
    cap.status = "queued"
    db.commit()
    background.add_task(run_analysis, file_id, baseline_id)
    return ok(_status_out(db, cap))


@router.get("/status/{file_id}", response_model=Envelope)
def status(file_id: str, db: Session = Depends(get_db)) -> Envelope:
    return ok(_status_out(db, _get_capture(db, file_id)))


@router.get("/summary/{file_id}", response_model=Envelope)
def summary(file_id: str, db: Session = Depends(get_db)) -> Envelope:
    cap = _get_capture(db, file_id)
    if cap.status != "done":
        raise ApiException(409, "not_ready", f"Analysis not complete (status: {cap.status}).")
    pk = Packet.capture_id == file_id

    total_packets = db.scalar(select(func.count()).select_from(Packet).where(pk)) or 0
    total_connections = db.scalar(select(func.count()).select_from(Connection).where(Connection.capture_id == file_id)) or 0
    unique_src = db.scalar(select(func.count(func.distinct(Packet.src_ip))).where(pk, Packet.src_ip.is_not(None))) or 0
    unique_dst = db.scalar(select(func.count(func.distinct(Packet.dst_ip))).where(pk, Packet.dst_ip.is_not(None))) or 0

    protocols = [
        {"protocol": p, "packets": n}
        for p, n in db.execute(
            select(Packet.protocol, func.count()).where(pk).group_by(Packet.protocol).order_by(func.count().desc())
        )
    ]
    bucket = cast(Packet.ts / 60, Integer)
    per_minute = [
        {"ts": int(b) * 60, "minute": epoch_to_iso(int(b) * 60), "packets": n}
        for b, n in db.execute(select(bucket, func.count()).where(pk).group_by(bucket).order_by(bucket))
    ]
    talkers = [
        {"src_ip": s, "dst_ip": d, "packets": n, "bytes": int(b or 0)}
        for s, d, n, b in db.execute(
            select(Packet.src_ip, Packet.dst_ip, func.count(), func.sum(Packet.length))
            .where(pk, Packet.src_ip.is_not(None), Packet.dst_ip.is_not(None))
            .group_by(Packet.src_ip, Packet.dst_ip)
            .order_by(func.sum(Packet.length).desc())
            .limit(10)
        )
    ]
    t_min, t_max = db.execute(select(func.min(Packet.ts), func.max(Packet.ts)).where(pk)).one()
    eff = func.coalesce(Finding.overridden_priority, Finding.priority)
    priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for pr, n in db.execute(select(eff, func.count()).where(Finding.capture_id == file_id).group_by(eff)):
        priority_counts[str(pr)] = int(n)
    run = db.scalars(
        select(AnalysisRun).where(AnalysisRun.capture_id == file_id).order_by(AnalysisRun.id.desc()).limit(1)
    ).first()
    analysis_run = None
    if run is not None:
        base = db.get(Baseline, run.baseline_id) if run.baseline_id else None
        analysis_run = {
            "ruleset_version": run.ruleset_version,
            "baseline_id": run.baseline_id,
            "baseline_name": base.name if base else None,
            "finding_count": run.finding_count,
        }
     
    return ok({
        "capture": CaptureOut.model_validate(cap),
        "total_packets": total_packets,
        "total_connections": total_connections,
        "unique_src_ips": unique_src,
        "unique_dst_ips": unique_dst,
        "first_packet_utc": epoch_to_iso(t_min) if t_min is not None else None,
        "last_packet_utc": epoch_to_iso(t_max) if t_max is not None else None,
        "protocols": protocols,
        "packets_per_minute": per_minute,
        "top_talkers": talkers,
        "priority_counts": priority_counts,
        "findings_total": sum(priority_counts.values()),
        "analysis_run": analysis_run,
    })


@router.get("/packets/{file_id}", response_model=Envelope)
def list_packets(
    file_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    q: str | None = Query(None, max_length=200),
    protocol: str | None = Query(None, max_length=16),
    db: Session = Depends(get_db),
) -> Envelope:
    _get_capture(db, file_id)
    stmt = select(Packet).where(Packet.capture_id == file_id)
    if protocol:
        stmt = stmt.where(Packet.protocol == protocol.upper())
    if q and q.strip():
        term = q.strip()
        like = f"%{term}%"
        conds = [Packet.src_ip.like(like), Packet.dst_ip.like(like), Packet.dns_query.like(like),
                 Packet.http_host.like(like), Packet.protocol.like(like)]
        if term.isdigit():
            conds.append(Packet.packet_number == int(term))
        stmt = stmt.where(or_(*conds))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Packet.packet_number).offset((page - 1) * page_size).limit(page_size)).all()

    items = [
        {
            "packet_number": r.packet_number, "ts": r.ts, "ts_utc": epoch_to_iso(r.ts),
            "src_ip": r.src_ip, "dst_ip": r.dst_ip, "src_port": r.src_port, "dst_port": r.dst_port,
            "protocol": r.protocol, "length": r.length, "ttl": r.ttl, "flags": r.flags,
            "dns_query": r.dns_query, "dns_qtype": r.dns_qtype, "dns_answers": r.dns_answers,
            "http_method": r.http_method, "http_host": r.http_host, "http_uri": r.http_uri,
            "http_user_agent": r.http_user_agent, "payload_preview": r.payload_preview,
            "stream_id": r.stream_id,
        }
        for r in rows
    ]
    return ok({"items": items, "total": total, "page": page, "page_size": page_size})