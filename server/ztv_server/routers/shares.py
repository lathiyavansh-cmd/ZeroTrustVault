"""Shares: owner-signed grants + per-recipient wrapped DEKs; soft revocation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ztv_crypto.encoding import b64u_decode
from ztv_crypto.sign import verify_grant

from ..audit import audit
from ..db import get_db
from ..models import File, Grant, User, UserCert, WrappedDEK
from ..pep import Principal, authenticate, client_ip, forbidden, store

router = APIRouter(prefix="/shares", tags=["shares"])


class ShareIn(BaseModel):
    grant: dict
    wrapped_dek: dict


@router.post("")
async def create_share(body: ShareIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    g = body.grant
    try:
        f = await db.get(File, g["file_id"])
    except KeyError:
        raise HTTPException(400, {"error": "bad_grant"})
    if f is None or f.deleted:
        raise HTTPException(404, {"error": "not_found"})
    if f.owner_id != p.user.id or g.get("owner_id") != p.user.id:
        await audit().log(actor=p.user.id, action="share.create", resource=f"file:{f.id}", decision="DENY", reason="not owner", ip=client_ip(request))
        raise forbidden()
    cert = await db.get(UserCert, p.user.id)
    if cert is None or cert.revoked or not verify_grant(g, b64u_decode(cert.cert["sig_pk"])):
        await audit().log(actor=p.user.id, action="share.create", resource=f"file:{f.id}", decision="DENY", reason="grant signature invalid", ip=client_ip(request))
        raise HTTPException(400, {"error": "bad_signature"})
    recipient = await db.get(User, g.get("recipient_id"))
    rcert = await db.get(UserCert, g.get("recipient_id"))
    if recipient is None or rcert is None or rcert.revoked:
        raise HTTPException(400, {"error": "recipient_has_no_cert"})
    if not set(g.get("rights", [])) <= {"view", "download"} or "view" not in g.get("rights", []):
        raise HTTPException(400, {"error": "bad_rights"})
    if await db.get(Grant, g["grant_id"]) is not None:
        raise HTTPException(409, {"error": "grant_exists"})
    await db.execute(delete(WrappedDEK).where(WrappedDEK.file_id == f.id, WrappedDEK.version == f.current_version, WrappedDEK.user_id == recipient.id))
    db.add(Grant(id=g["grant_id"], file_id=f.id, owner_id=p.user.id, recipient_id=recipient.id, grant=g))
    db.add(WrappedDEK(file_id=f.id, version=f.current_version, user_id=recipient.id, record=body.wrapped_dek))
    await db.commit()
    await audit().log(actor=p.user.id, action="share.create", resource=f"file:{f.id}", decision="PERMIT", reason=f"grant issued to {recipient.username}", ip=client_ip(request), device=p.device.id if p.device else None, details={"grant_id": g["grant_id"], "recipient": recipient.id, "rights": g.get("rights"), "expires_at": g.get("expires_at"), "max_downloads": g.get("max_downloads")})
    return {"grant_id": g["grant_id"]}


@router.get("")
async def list_shares(file_id: str | None = None, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    stmt = select(Grant).where(Grant.revoked.is_(False))
    if file_id:
        stmt = stmt.where(Grant.file_id == file_id)
    rows = (await db.execute(stmt.order_by(Grant.created_at))).scalars().all()
    out = []
    for g in rows:
        if g.owner_id != p.user.id and g.recipient_id != p.user.id and not p.is_admin:
            continue
        out.append({**g.grant, "downloads_used": g.downloads_used, "revoked": g.revoked})
    return out


@router.delete("/{grant_id}", status_code=204)
async def revoke_share(grant_id: str, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    g = await db.get(Grant, grant_id)
    if g is None or g.revoked:
        raise HTTPException(404, {"error": "not_found"})
    if g.owner_id != p.user.id:
        await audit().log(actor=p.user.id, action="share.revoke", resource=f"grant:{grant_id}", decision="DENY", reason="not owner", ip=client_ip(request))
        raise forbidden()
    g.revoked = True
    await db.execute(delete(WrappedDEK).where(WrappedDEK.file_id == g.file_id, WrappedDEK.user_id == g.recipient_id))
    await db.commit()
    await store(request).revoke_blob_urls(g.file_id, g.recipient_id)
    await audit().log(actor=p.user.id, action="share.revoke", resource=f"grant:{grant_id}", decision="INFO", reason="soft revocation: grant + wrapped DEK removed, blob URLs revoked", ip=client_ip(request), details={"file_id": g.file_id, "recipient": g.recipient_id})
    return Response(status_code=204)
