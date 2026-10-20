"""Pydantic schemas, the { ok, data, error } envelope, and the API exception type."""
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, PlainSerializer


def _utc_iso(d: datetime) -> str:
    # SQLite returns naive datetimes; everything we store is UTC.
    return d.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


UtcDatetime = Annotated[datetime, PlainSerializer(_utc_iso, return_type=str)]


def epoch_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ErrorBody(BaseModel):
    code: str
    message: str


class Envelope(BaseModel):
    ok: bool
    data: Any | None = None
    error: ErrorBody | None = None


def ok(data: Any) -> Envelope:
    return Envelope(ok=True, data=data, error=None)


def fail(code: str, message: str) -> Envelope:
    return Envelope(ok=False, data=None, error=ErrorBody(code=code, message=message))


class ApiException(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class CaptureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    file_id: str = Field(validation_alias="id")
    original_filename: str
    size_bytes: int
    sha256: str
    uploaded_at: UtcDatetime
    analyzed_at: UtcDatetime | None = None
    tool_version: str
    status: str
    analyst_note: str | None = None
    analyzed_sha256: str | None = None
    integrity_ok: bool | None = None


class StatusOut(BaseModel):
    file_id: str
    status: str
    packets_parsed: int
    error_message: str | None = None
    integrity_ok: bool | None = None
    integrity_warning: str | None = None


class OverrideIn(BaseModel):
        """`priority: null` clears an existing override. A reason is always required."""
        priority: Literal["P1", "P2", "P3", "P4"] | None
        analyst_note: str = Field(min_length=3, max_length=2000)
        analyst: str = Field(min_length=1, max_length=128)


class BaselineIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    capture_id: str