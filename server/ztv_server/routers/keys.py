"""Sealed key blobs, certificate requests, directory and org-root info."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ztv_crypto.ca import cert_fingerprint
from ztv_crypto.encoding import b64u, b64u_decode

from ..audit import audit
from ..db import get_db
from ..models import CertRequest, KeyBlob, User, UserCert
from ..pep import Principal, authenticate, client_ip
from ..security import keys

router = APIRouter(prefix="/keys", tags=["keys"])


class BlobIn(BaseModel):
    blob: dict


class CertRequestIn(BaseModel):
    enc_pk: str
    sig_pk: str


@router.get("/blob")
async def get_blob(p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    kb = await db.get(KeyBlob, p.user.id)
    if kb is None:
        raise HTTPException(404, {"error": "not_found"})
    return kb.blob


@router.put("/blob", status_code=204)
async def put_blob(body: BlobIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    b = body.blob
    if b.get("v") != 1 or b.get("cipher") != "AES-256-GCM" or not isinstance(b.get("kdf"), dict) or "ct" not in b or "iv" not in b:
        raise HTTPException(400, {"error": "bad_blob"})
    kb = await db.get(KeyBlob, p.user.id)
    if kb is None:
        db.add(KeyBlob(user_id=p.user.id, blob=b))
    else:
        kb.blob = b
    await db.commit()
    await audit().log(actor=p.user.id, action="keys.blob_put", resource=f"user:{p.user.username}", decision="INFO", reason="sealed key blob stored", ip=client_ip(request))
    from fastapi import Response

    return Response(status_code=204)


@router.post("/cert-request")
async def cert_request(body: CertRequestIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    try:
        enc, sig = b64u_decode(body.enc_pk), b64u_decode(body.sig_pk)
        if len(enc) != 32 or len(sig) != 32:
            raise ValueError
    except Exception:  # noqa: BLE001
        raise HTTPException(400, {"error": "bad_keys"})
    fp = cert_fingerprint(enc, sig)
    await db.execute(delete(CertRequest).where(CertRequest.user_id == p.user.id, CertRequest.status.in_(["pending", "confirmed"])))
    cr = CertRequest(user_id=p.user.id, username=p.user.username, enc_pk=body.enc_pk, sig_pk=body.sig_pk, fingerprint=fp, status="pending")
    db.add(cr)
    await db.commit()
    await audit().log(actor=p.user.id, action="keys.cert_request", resource=f"cert-request:{cr.id}", decision="INFO", reason="awaiting out-of-band fingerprint confirmation", ip=client_ip(request), details={"fingerprint": fp})
    return {"request_id": cr.id, "fingerprint": fp, "status": "pending"}


@router.get("/cert-request/{request_id}")
async def cert_request_status(request_id: str, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    cr = await db.get(CertRequest, request_id)
    if cr is None or (cr.user_id != p.user.id and not p.is_admin):
        raise HTTPException(404, {"error": "not_found"})
    out = {"request_id": cr.id, "status": cr.status, "fingerprint": cr.fingerprint}
    if cr.status == "issued":
        uc = await db.get(UserCert, cr.user_id)
        if uc is not None:
            out["cert"] = uc.cert
    return out


@router.get("/directory")
async def directory(q: str = "", p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    stmt = select(User).order_by(User.username)
    if q:
        stmt = stmt.where(User.username.ilike(f"%{q}%"))
    users = (await db.execute(stmt)).scalars().all()
    certs = {c.user_id for c in (await db.execute(select(UserCert).where(UserCert.revoked.is_(False)))).scalars()}
    return [{"user_id": u.id, "username": u.username, "department": u.department, "role": u.role, "has_cert": u.id in certs} for u in users]


@router.get("/directory/{user_id}")
async def directory_entry(user_id: str, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    u = await db.get(User, user_id)
    uc = await db.get(UserCert, user_id)
    if u is None or uc is None or uc.revoked:
        raise HTTPException(404, {"error": "not_found"})
    return {"user_id": u.id, "username": u.username, "cert": uc.cert}


@router.get("/org-root")
async def org_root():
    return {"pk": b64u(keys().org_root_pk)}
