"""ORM models. Phase 1: captures, packets, connections. (findings/baselines: Phase 2)"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    original_filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    tool_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="uploaded")  # uploaded|queued|running|done|error
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    integrity_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class Packet(Base):
    __tablename__ = "packets"
    __table_args__ = (Index("ix_packets_capture_pn", "capture_id", "packet_number"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    packet_number: Mapped[int] = mapped_column(Integer)  # 1-based, equals Wireshark frame.number
    ts: Mapped[float] = mapped_column(Float)  # epoch seconds (UTC)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16))
    length: Mapped[int] = mapped_column(Integer)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flags: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(512), nullable=True)
    dns_qtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    dns_answers: Mapped[str | None] = mapped_column(Text, nullable=True)  # comma-separated response IPs
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    http_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    stream_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


class Connection(Base):
    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    connection_id: Mapped[str] = mapped_column(String(64))  # <stream_id>-<first_seen_ms>
    stream_id: Mapped[str] = mapped_column(String(32), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16))
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    packet_count: Mapped[int] = mapped_column(Integer)
    byte_count: Mapped[int] = mapped_column(Integer)

class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_capture_prio", "capture_id", "priority"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    priority: Mapped[str] = mapped_column(String(2))  # P1..P4 as assigned by the engine
    rule_id: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    confidence_breakdown_json: Mapped[str] = mapped_column(Text)
    packet_refs_json: Mapped[str] = mapped_column(Text)  # capped list of packet numbers
    packet_ref_count: Mapped[int] = mapped_column(Integer)  # true total before capping
    ts_first: Mapped[float] = mapped_column(Float)
    ts_last: Mapped[float] = mapped_column(Float)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    protocol: Mapped[str] = mapped_column(String(16))
    stream_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    overridden_priority: Mapped[str | None] = mapped_column(String(2), nullable=True)
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    overridden_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    overridden_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    config_json: Mapped[str] = mapped_column(Text)  # serialized BaselineProfile


class AnalysisRun(Base):
    """Reproducibility record: which ruleset, thresholds and data files produced the findings."""

    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    baseline_id: Mapped[int | None] = mapped_column(ForeignKey("baselines.id"), nullable=True)
    ruleset_version: Mapped[str] = mapped_column(String(32))
    config_json: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime)
    finished_at: Mapped[datetime] = mapped_column(DateTime)
    finding_count: Mapped[int] = mapped_column(Integer)