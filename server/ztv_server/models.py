"""ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    department: Mapped[str] = mapped_column(String(64), default="research")
    clearance: Mapped[int] = mapped_column(Integer, default=1)
    employment_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def public(self) -> dict:
        return {"id": self.id, "username": self.username, "role": self.role, "department": self.department, "clearance": self.clearance, "employment_end": self.employment_end.isoformat().replace("+00:00", "Z") if self.employment_end else None}


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    jkt: Mapped[str] = mapped_column(String(128), index=True)
    jwk: Mapped[dict] = mapped_column(JSONType, default=dict)
    name: Mapped[str] = mapped_column(String(128), default="device")
    posture: Mapped[str] = mapped_column(String(32), default="registered")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("user_id", "jkt", name="uq_device_user_jkt"),)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    amr: Mapped[list] = mapped_column(JSONType, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(Text, unique=True)
    public_key: Mapped[str] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KeyBlob(Base):
    __tablename__ = "key_blobs"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    blob: Mapped[dict] = mapped_column(JSONType)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CertRequest(Base):
    __tablename__ = "cert_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    username: Mapped[str] = mapped_column(String(64))
    enc_pk: Mapped[str] = mapped_column(Text)
    sig_pk: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    confirmed_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def public(self) -> dict:
        return {"id": self.id, "user_id": self.user_id, "username": self.username, "enc_pk": self.enc_pk, "sig_pk": self.sig_pk, "fingerprint": self.fingerprint, "confirmed_fingerprint": self.confirmed_fingerprint, "status": self.status, "created_at": self.created_at.isoformat().replace("+00:00", "Z")}


class UserCert(Base):
    __tablename__ = "user_certs"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    cert: Mapped[dict] = mapped_column(JSONType)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class File(Base):
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    classification: Mapped[str] = mapped_column(String(16), default="INTERNAL")
    department: Mapped[str] = mapped_column(String(64), default="research")
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)


class FileVersion(Base):
    __tablename__ = "file_versions"
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("files.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    manifest: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="uploading")  # uploading/active/superseded
    cipher: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")
    chunk_count: Mapped[int] = mapped_column(Integer, default=1)
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WrappedDEK(Base):
    __tablename__ = "wrapped_deks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("files.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    record: Mapped[dict] = mapped_column(JSONType)
    __table_args__ = (UniqueConstraint("file_id", "version", "user_id", name="uq_wdek"),)


class Grant(Base):
    __tablename__ = "grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("files.id", ondelete="CASCADE"), index=True)
    owner_id: Mapped[str] = mapped_column(String(36))
    recipient_id: Mapped[str] = mapped_column(String(36), index=True)
    grant: Mapped[dict] = mapped_column(JSONType)
    downloads_used: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    document: Mapped[dict] = mapped_column(JSONType)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def as_dict(self) -> dict:
        return {"seq": self.seq, "ts": self.ts, "actor": self.actor, "action": self.action, "resource": self.resource, "decision": self.decision, "reason": self.reason, "ip": self.ip, "device": self.device, "details": self.details, "prev_hash": self.prev_hash, "hash": self.hash}


class AuditChainHead(Base):
    __tablename__ = "audit_chain_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, default=0)
    head_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_checkpoint_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    last_checkpoint_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditCheckpoint(Base):
    __tablename__ = "audit_checkpoints"
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    hash: Mapped[str] = mapped_column(String(64))
    ts: Mapped[str] = mapped_column(String(32))
    signature: Mapped[str] = mapped_column(Text)


class BaselineToken(Base):
    __tablename__ = "baseline_tokens"
    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
