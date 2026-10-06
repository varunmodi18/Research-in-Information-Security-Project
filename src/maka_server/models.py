"""Persistence model (IMPLEMENTATION_PLAN.md §4.8). Every table has an integer `id` and
`created_at`. No column holds a key, scalar or plaintext secret: keystore entries are
AES-256-GCM ciphertexts under the KEK, and sessions carry metadata only."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # admin | operator | viewer
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Network(Base):
    __tablename__ = "networks"
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))  # product | lab
    mode: Mapped[str] = mapped_column(String(16))  # enhanced | original
    params: Mapped[str] = mapped_column(String(16))
    template: Mapped[str] = mapped_column(String(32))
    seed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="idle")  # idle | busy | failed
    bs_device_id: Mapped[str] = mapped_column(String(20), default="BS-01")
    step: Mapped[int] = mapped_column(Integer, default=0)
    options_json: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("network_id", "ident"),)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    ident: Mapped[str] = mapped_column(String(20))
    role: Mapped[str] = mapped_column(String(4))  # BS | CH | CM
    cluster: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="provisioned")
    epoch: Mapped[int] = mapped_column(Integer, default=0)
    pu_fingerprint: Mapped[str] = mapped_column(String(16), default="")
    status_history: Mapped[list] = mapped_column(JSON, default=list)  # type: ignore[type-arg]
    designated: Mapped[str | None] = mapped_column(String(20), nullable=True)  # a CM's designated CH (D2)
    undelivered: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # readings lost (D2)


class KeystoreEntry(Base):
    __tablename__ = "keystore_entries"
    __table_args__ = (UniqueConstraint("device_id", "name"),)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    cls: Mapped[str] = mapped_column(String(8))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)


class ProtocolSession(Base):
    """`sessions` in §4.8: metadata only, never keys."""

    __tablename__ = "sessions"
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    a: Mapped[str] = mapped_column(String(20))
    b: Mapped[str] = mapped_column(String(20))
    purpose: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(16))
    sid_hex: Mapped[str] = mapped_column(String(64), default="")
    established_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    epoch: Mapped[int] = mapped_column(Integer, default=0)
    sent: Mapped[int] = mapped_column(Integer, default=0)
    recv: Mapped[int] = mapped_column(Integer, default=0)
    superseded_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class FrameRow(Base):
    __tablename__ = "frames"
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    frame_id: Mapped[int] = mapped_column(Integer)
    step: Mapped[int] = mapped_column(Integer, index=True)
    sent_step: Mapped[int] = mapped_column(Integer)
    src: Mapped[str] = mapped_column(String(20))
    dst: Mapped[str] = mapped_column(String(20))
    to: Mapped[str | None] = mapped_column(String(20), nullable=True)
    label: Mapped[str] = mapped_column(String(32), index=True)
    bytes_len: Mapped[int] = mapped_column(Integer)
    paper_bits: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # ciphertext/public only
    verdict: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fate: Mapped[str] = mapped_column(String(16), default="sent")
    checks_json: Mapped[list] = mapped_column(JSON, default=list)  # type: ignore[type-arg]
    run_tag: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)  # Lab runs (M6)


class SecurityEventRow(Base):
    __tablename__ = "security_events"
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"),
                                                   index=True, nullable=True)
    step: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(8), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    device: Mapped[str] = mapped_column(String(20))
    peer: Mapped[str | None] = mapped_column(String(20), nullable=True)
    session_sid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    frame_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]
    run_tag: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)  # Lab runs (M6)


class Reading(Base):
    __tablename__ = "readings"
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    device: Mapped[str] = mapped_column(String(20), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    value_json: Mapped[dict] = mapped_column(JSON)  # type: ignore[type-arg]
    received_step: Mapped[int] = mapped_column(Integer)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (UniqueConstraint("network_id", "idempotency_key"),)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"),
                                                   index=True, nullable=True)
    type: Mapped[str] = mapped_column(String(32))
    args_json: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]
    idempotency_key: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="queued")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    phase: Mapped[str] = mapped_column(String(64), default="")
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # type: ignore[type-arg]
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128), default="")
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    outcome: Mapped[str] = mapped_column(String(32))


class EvaluationRun(Base):
    """Results of evaluation jobs (FR-17), served by GET /evaluation/runs/{id}."""

    __tablename__ = "evaluation_runs"
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # type: ignore[type-arg]
    state: Mapped[str] = mapped_column(String(16), default="running")
