"""POST /api/upload: validate, hash and store the original PCAP unchanged."""
import os
from pathlib import Path
from uuid import uuid4
import hashlib

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Capture, utcnow
from app.schemas import ApiException, CaptureOut, Envelope, ok
from app.services.pcap_parser import sniff_format

router = APIRouter(prefix="/api", tags=["upload"])
ALLOWED_SUFFIXES = {".pcap", ".pcapng"}
CHUNK = 1024 * 1024


@router.post("/upload", response_model=Envelope)
async def upload_pcap(
    file: UploadFile = File(...),
    analyst_note: str | None = Form(default=None),
    db: Session = Depends(get_db),
) -> Envelope:
    original_name = Path(file.filename or "").name
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise ApiException(400, "invalid_extension", "Only .pcap and .pcapng files are accepted.")

    file_id = str(uuid4())
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    dest = settings.upload_dir / f"{file_id}{suffix}"
    digest = hashlib.sha256()
    size = 0

    try:
        with dest.open("xb") as out:
            first = True
            while chunk := await file.read(CHUNK):
                if first:
                    if sniff_format(chunk) is None:
                        raise ApiException(400, "invalid_magic", "File is not a valid PCAP/PCAPNG (magic bytes mismatch).")
                    first = False
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise ApiException(413, "file_too_large", f"File exceeds {settings.max_upload_mb} MB limit.")
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ApiException(400, "empty_file", "Uploaded file is empty.")
    except BaseException:
        dest.unlink(missing_ok=True)  # never leave partial evidence behind
        raise

    os.chmod(dest, 0o444)  # read-only: the original must never be modified

    cap = Capture(
        id=file_id,
        original_filename=original_name,
        stored_path=str(dest),
        size_bytes=size,
        sha256=digest.hexdigest(),
        uploaded_at=utcnow(),
        tool_version=settings.tool_version,
        status="uploaded",
        analyst_note=(analyst_note or None),
    )
    db.add(cap)
    db.commit()
    return ok(CaptureOut.model_validate(cap))