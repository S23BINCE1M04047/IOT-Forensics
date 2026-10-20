"""Baselines: stored communication profiles of known-good captures."""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Baseline, Capture, utcnow
from app.schemas import ApiException, BaselineIn, Envelope, ok
from app.services.baseline import BaselineProfile, build_profile
from app.services.extractor import load_packet_rows

router = APIRouter(prefix="/api", tags=["baselines"])


def _iso(d: object) -> str:
    from app.schemas import _utc_iso  # noqa: PLC0415
    return _utc_iso(d)  # type: ignore[arg-type]


@router.post("/baselines", response_model=Envelope)
def create_baseline(body: BaselineIn, db: Session = Depends(get_db)) -> Envelope:
    cap = db.get(Capture, body.capture_id)
    if cap is None:
        raise ApiException(404, "not_found", f"No capture with id {body.capture_id}.")
    if cap.status != "done":
        raise ApiException(409, "not_ready", "Analyze the capture before using it as a baseline.")
    rows = load_packet_rows(db, body.capture_id)
    if not rows:
        raise ApiException(400, "empty_capture", "Capture has no packets.")
    profile = build_profile(rows)
    b = Baseline(name=body.name, capture_id=body.capture_id, created_at=utcnow(), config_json=profile.to_json())
    db.add(b)
    db.commit()
    return ok({"id": b.id, "name": b.name, "capture_id": b.capture_id, "created_at": _iso(b.created_at),
               "packet_count": profile.packet_count})


@router.get("/baselines", response_model=Envelope)
def list_baselines(db: Session = Depends(get_db)) -> Envelope:
    items = []
    for b in db.scalars(select(Baseline).order_by(Baseline.id.desc())):
        items.append({"id": b.id, "name": b.name, "capture_id": b.capture_id, "created_at": _iso(b.created_at),
                      "packet_count": BaselineProfile.from_json(b.config_json).packet_count})
    return ok(items)