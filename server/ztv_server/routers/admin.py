"""Policy, admin users / cert requests, mode switch, dashboard, audit, health."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ztv_crypto.ca import cert_fingerprint, verify_user_cert
from ztv_crypto.encoding import b64u_decode
from ztv_crypto.kdf import hash_password

from .. import config
from ..audit import audit
from ..db import get_db
from ..models import AuditEntry, CertRequest, Policy, User, UserCert, new_id
from ..pdp import LocalJsonPDP, OpaPDP
from ..pep import Principal, authenticate, client_ip, forbidden, require_admin, store
from ..security import keys

router = APIRouter(tags=["admin"])


class PolicyIn(BaseModel):
    rules: list[dict]
    version: int | None = None
    name: str | None = None


class UserIn(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    department: str = "research"
    clearance: int = 1
    employment_end: str | None = None
    totp_secret: str | None = None


class ConfirmIn(BaseModel):
    fingerprint: str


class PublishIn(BaseModel):
    cert: dict


class ModeIn(BaseModel):
    mode: str


def _norm(fp: str) -> str:
    return "".join(fp.split()).upper()


# ---- policy -------------------------------------------------------------------------------
@router.get("/policy")
async def get_policy(p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    row = await db.get(Policy, 1)
    return row.document if row else {"rules": []}


@router.put("/policy")
async def put_policy(body: dict, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if not isinstance(body.get("rules"), list):
        raise HTTPException(400, {"error": "bad_policy"})
    row = await db.get(Policy, 1)
    if row is None:
        db.add(Policy(id=1, document=body))
    else:
        row.document = body
    await db.commit()
    pdp = request.app.state.pdp
    if isinstance(pdp, LocalJsonPDP):
        pdp.set_policy(body)
    elif isinstance(pdp, OpaPDP) and isinstance(pdp.fallback, LocalJsonPDP):
        pdp.fallback.set_policy(body)
    await audit().log(actor=admin.user.id if admin else "admin-key", action="policy.update", resource="policy", decision="INFO", reason=f"{len(body['rules'])} rules", ip=client_ip(request))
    return body


# ---- users -----------------------------------------------------------------------------------
@router.get("/admin/users")
async def list_users(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(select(User).order_by(User.username))).scalars().all()
    certs = {c.user_id for c in (await db.execute(select(UserCert).where(UserCert.revoked.is_(False)))).scalars()}
    return [{**u.public(), "has_cert": u.id in certs, "totp_enrolled": bool(u.totp_secret), "locked_until": u.locked_until.isoformat() if u.locked_until else None, "failed_logins": u.failed_logins} for u in users]


@router.post("/admin/users", status_code=201)
async def create_user(body: UserIn, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none() is not None:
        raise HTTPException(409, {"error": "exists"})
    emp = datetime.fromisoformat(body.employment_end.replace("Z", "+00:00")) if body.employment_end else None
    u = User(id=new_id(), username=body.username, password_hash=hash_password(body.password), role=body.role, department=body.department, clearance=body.clearance, employment_end=emp, totp_secret=body.totp_secret or pyotp.random_base32(), totp_confirmed=True)
    db.add(u)
    await db.commit()
    await audit().log(actor=admin.user.id if admin else "admin-key", action="admin.user_create", resource=f"user:{u.username}", decision="INFO", reason="user created", ip=client_ip(request), details={"role": u.role, "department": u.department, "clearance": u.clearance})
    # Provisioning secret: shown ONCE to the admin, who hands it to the user out-of-band (workflow A).
    return {**u.public(), "totp_secret": u.totp_secret, "otpauth_uri": pyotp.TOTP(u.totp_secret).provisioning_uri(name=u.username, issuer_name="ZeroTrustVault")}


# ---- cert requests ---------------------------------------------------------------------------
@router.get("/admin/cert-requests")
async def list_cert_requests(status: str | None = None, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(CertRequest).order_by(CertRequest.created_at)
    if status:
        stmt = stmt.where(CertRequest.status == status)
    return [c.public() for c in (await db.execute(stmt)).scalars()]


@router.get("/admin/cert-requests/{request_id}")
async def get_cert_request(request_id: str, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    c = await db.get(CertRequest, request_id)
    if c is None:
        raise HTTPException(404, {"error": "not_found"})
    return c.public()


@router.post("/admin/cert-requests/{request_id}/confirm")
async def confirm_cert_request(request_id: str, body: ConfirmIn, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    c = await db.get(CertRequest, request_id)
    if c is None:
        raise HTTPException(404, {"error": "not_found"})
    if _norm(body.fingerprint) != _norm(c.fingerprint):
        await audit().log(actor=admin.user.id if admin else "admin-key", action="cert.confirm", resource=f"cert-request:{c.id}", decision="DENY", reason="fingerprint mismatch (possible key substitution)", ip=client_ip(request))
        raise HTTPException(400, {"error": "fingerprint_mismatch"})
    c.confirmed_fingerprint = c.fingerprint
    c.status = "confirmed"
    await db.commit()
    await audit().log(actor=admin.user.id if admin else "admin-key", action="cert.confirm", resource=f"cert-request:{c.id}", decision="INFO", reason="fingerprint confirmed out-of-band; awaiting offline signer", ip=client_ip(request), details={"user": c.username})
    return c.public()


@router.post("/admin/cert-requests/{request_id}/publish")
async def publish_cert(request_id: str, body: PublishIn, request: Request, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    c = await db.get(CertRequest, request_id)
    if c is None:
        raise HTTPException(404, {"error": "not_found"})
    cert = body.cert
    if c.status != "confirmed":
        raise HTTPException(409, {"error": "not_confirmed"})
    ok = verify_user_cert(cert, keys().org_root_pk, expected_user_id=c.user_id) and cert.get("enc_pk") == c.enc_pk and cert.get("sig_pk") == c.sig_pk and cert.get("username") == c.username
    if not ok or _norm(cert_fingerprint(b64u_decode(cert["enc_pk"]), b64u_decode(cert["sig_pk"]))) != _norm(c.confirmed_fingerprint or ""):
        await audit().log(actor="ca-signer", action="cert.publish", resource=f"cert-request:{c.id}", decision="DENY", reason="certificate does not verify against the pinned org root / request", ip=client_ip(request))
        raise HTTPException(400, {"error": "bad_cert"})
    uc = await db.get(UserCert, c.user_id)
    if uc is None:
        db.add(UserCert(user_id=c.user_id, cert=cert, revoked=False))
    else:
        uc.cert = cert
        uc.revoked = False
    c.status = "issued"
    await db.commit()
    await audit().log(actor="ca-signer", action="cert.publish", resource=f"cert-request:{c.id}", decision="INFO", reason="certificate issued by offline org CA", ip=client_ip(request), details={"user": c.username, "serial": cert.get("serial")})
    return {"status": "issued", "user_id": c.user_id, "serial": cert.get("serial")}


# ---- mode --------------------------------------------------------------------------------------
@router.get("/mode")
async def get_mode():
    return {"mode": config.current_mode()}


@router.post("/admin/mode")
async def set_mode(body: ModeIn, request: Request, admin=Depends(require_admin)):
    if not config.settings.ALLOW_RUNTIME_MODE_SWITCH:
        raise forbidden()
    try:
        config.set_mode(body.mode)
    except ValueError:
        raise HTTPException(400, {"error": "bad_mode"})
    await audit().log(actor=admin.user.id if admin else "admin-key", action="admin.mode", resource="mode", decision="INFO", reason=f"mode switched to {body.mode}", ip=client_ip(request))
    return {"mode": config.current_mode()}


# ---- dashboard / audit -------------------------------------------------------------------------
@router.get("/dashboard/summary")
async def dashboard(request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    counts = {d: 0 for d in ("PERMIT", "DENY", "ALERT", "INFO")}
    for dec, n in (await db.execute(select(AuditEntry.decision, func.count()).group_by(AuditEntry.decision))).all():
        counts[dec] = int(n)
    stmt = select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(10)
    if not p.is_admin:
        stmt = stmt.where(AuditEntry.actor == p.user.id)
    recent = [e.as_dict() for e in (await db.execute(stmt)).scalars()]
    stats = await audit().stats(db)
    report = await audit().verify(db)
    return {"mode": config.current_mode(), "decisions": {"permit": counts["PERMIT"], "deny": counts["DENY"], "alerts": counts["ALERT"], "info": counts["INFO"]}, "recent": recent, "audit": {**stats, "chain_ok": report.ok, "first_bad_seq": report.first_bad_seq, "problem": report.problem}, "sessions_active": await store(request).active_sessions()}


@router.get("/audit/recent")
async def audit_recent(limit: int = 50, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    stmt = select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(max(1, min(limit, 500)))
    if not p.is_admin:
        stmt = stmt.where(AuditEntry.actor == p.user.id)
    return [e.as_dict() for e in (await db.execute(stmt)).scalars()]


@router.get("/audit/export")
async def audit_export(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return await audit().export(db)


@router.get("/audit/verify")
async def audit_verify(p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    return audit().report_dict(await audit().verify(db))


@router.post("/audit/checkpoint")
async def audit_checkpoint(admin=Depends(require_admin)):
    cp = await audit().maybe_checkpoint(force=True)
    return cp or {"status": "nothing_to_checkpoint"}


@router.get("/health")
async def health():
    return {"status": "ok", "mode": config.current_mode(), "time": int(time.time())}
