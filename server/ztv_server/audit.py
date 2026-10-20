"""Tamper-evident audit service (CONTRACT §8).

Every entry is appended under a `SELECT ... FOR UPDATE` on the single audit_chain_head row so the
chain is strictly serialized.  In zerotrustvault mode entries carry prev_hash/hash; in baseline mode
rows are written plain (no chain) — the in-memory head still advances so a later switch back keeps
a consistent head.  Checkpoints (every 100 entries or 5 minutes) are Ed25519-signed and written to the
DB and to the write-once MinIO bucket.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ztv_crypto.audit import CHECKPOINT_EVERY_ENTRIES, CHECKPOINT_EVERY_SECONDS, GENESIS_HASH, entry_hash, sign_checkpoint, verify_chain, ChainReport
from ztv_crypto.encoding import b64u, b64u_decode
from ztv_crypto.sign import now_iso

from . import config
from .models import AuditCheckpoint, AuditChainHead, AuditEntry
from .security import keys

log = logging.getLogger("ztv.audit")


class AuditService:
    def __init__(self, sessionmaker: async_sessionmaker, storage=None):
        self.sm = sessionmaker
        self.storage = storage

    async def log(self, *, actor: str | None, action: str, resource: str | None, decision: str, reason: str | None = None, ip: str | None = None, device: str | None = None, details: dict | None = None) -> dict:
        chained = not config.is_baseline()
        async with self.sm() as db:
            async with db.begin():
                head = (await db.execute(select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update())).scalar_one_or_none()
                if head is None:
                    head = AuditChainHead(id=1, seq=0, head_hash=None)
                    db.add(head)
                    await db.flush()
                prev = b64u_decode(head.head_hash) if head.head_hash else GENESIS_HASH
                seq = int(head.seq) + 1
                entry = {"seq": seq, "ts": now_iso(), "actor": actor, "action": action, "resource": resource, "decision": decision, "reason": reason, "ip": ip, "device": device, "details": details or {}}
                h = entry_hash(prev, entry)
                row = AuditEntry(**entry, prev_hash=b64u(prev) if chained else None, hash=b64u(h) if chained else None)
                db.add(row)
                head.seq = seq
                head.head_hash = b64u(h)
            return {**entry, "prev_hash": row.prev_hash, "hash": row.hash}

    async def maybe_checkpoint(self, force: bool = False) -> dict | None:
        if config.is_baseline() and not force:
            return None
        async with self.sm() as db:
            async with db.begin():
                head = (await db.execute(select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update())).scalar_one_or_none()
                if head is None or head.seq == 0 or head.seq == head.last_checkpoint_seq:
                    return None
                due = force or (head.seq - head.last_checkpoint_seq >= CHECKPOINT_EVERY_ENTRIES)
                if not due and head.last_checkpoint_at is not None:
                    age = (datetime.now(timezone.utc) - head.last_checkpoint_at).total_seconds()
                    due = age >= CHECKPOINT_EVERY_SECONDS
                elif not due and head.last_checkpoint_at is None:
                    due = True
                if not due:
                    return None
                cp = sign_checkpoint(int(head.seq), b64u_decode(head.head_hash), keys().audit_sk)
                db.add(AuditCheckpoint(seq=cp["seq"], hash=cp["hash"], ts=cp["ts"], signature=cp["signature"]))
                head.last_checkpoint_seq = cp["seq"]
                head.last_checkpoint_at = datetime.now(timezone.utc)
        if self.storage is not None:
            try:
                await self.storage.put_checkpoint(cp)
            except Exception as e:  # noqa: BLE001
                log.warning("checkpoint object write failed: %s", e)
        return cp

    async def checkpoint_loop(self, interval: float = 15.0) -> None:
        while True:
            try:
                await self.maybe_checkpoint()
            except Exception as e:  # noqa: BLE001
                log.warning("checkpoint loop: %s", e)
            await asyncio.sleep(interval)

    async def export(self, db: AsyncSession) -> dict:
        entries = [e.as_dict() for e in (await db.execute(select(AuditEntry).order_by(AuditEntry.seq))).scalars()]
        cps = [{"seq": c.seq, "hash": c.hash, "ts": c.ts, "signature": c.signature} for c in (await db.execute(select(AuditCheckpoint).order_by(AuditCheckpoint.seq))).scalars()]
        return {"entries": entries, "checkpoints": cps, "audit_pk": b64u(keys().audit_pk)}

    async def verify(self, db: AsyncSession) -> ChainReport:
        """Recompute the chain.  Rows written in baseline mode carry no stored hash; the chain state still
        advanced through them, so they are reported as `unchained` rather than as a break (any edit to a row
        that is followed by chained rows is still pinpointed at the exact seq)."""
        data = await self.export(db)
        report = verify_chain(data["entries"], data["checkpoints"], keys().audit_pk)
        unchained = [i for i in report.issues if "no stored hash" in i]
        if unchained:
            report.issues = [i for i in report.issues if "no stored hash" not in i]
            report.ok = not report.issues
            if report.issues:
                first = report.issues[0]
                report.first_bad_seq = int(first.split()[1].rstrip(":"))
                report.problem = first.split(": ", 1)[1]
            else:
                report.first_bad_seq, report.problem = None, None
        report.unchained_entries = len(unchained)  # type: ignore[attr-defined]
        return report

    @staticmethod
    def report_dict(report: ChainReport) -> dict:
        d = report.as_dict()
        d["unchained_entries"] = getattr(report, "unchained_entries", 0)
        return d

    async def stats(self, db: AsyncSession) -> dict:
        total = (await db.execute(select(func.count()).select_from(AuditEntry))).scalar_one()
        last_cp = (await db.execute(select(func.max(AuditCheckpoint.seq)))).scalar_one() or 0
        return {"entries": int(total), "last_checkpoint_seq": int(last_cp)}


_service: AuditService | None = None


def audit() -> AuditService:
    assert _service is not None, "audit service not initialised"
    return _service


def init_audit(sessionmaker: async_sessionmaker, storage=None) -> AuditService:
    global _service
    _service = AuditService(sessionmaker, storage)
    return _service
