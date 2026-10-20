"""Files: E2EE upload (init / chunk / finalize), PDP-gated access, blob URLs, integrity reports, versions; baseline upload/download."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File as UploadFileParam, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ztv_crypto.encoding import b64u_decode
from ztv_crypto.sign import verify_manifest

from .. import config
from ..audit import audit
from ..db import get_db
from ..models import File, FileVersion, Grant, User, UserCert, WrappedDEK, new_id
from ..pdp import CLASSIFICATION_LEVELS
from ..pep import Principal, authenticate, authorize_file, client_ip, forbidden, store
from ..security import sign_blob_token, verify_blob_token
from ..storage import storage

router = APIRouter(prefix="/files", tags=["files"])
blob_router = APIRouter(prefix="/blob", tags=["files"])

MAX_CHUNK = 4 * 1024 * 1024 + 16


class FileInit(BaseModel):
    name: str
    classification: str = "INTERNAL"
    size: int = 0
    chunk_count: int = 1
    cipher: str = "AES-256-GCM"


class VersionInit(BaseModel):
    size: int = 0
    chunk_count: int = 1
    cipher: str = "AES-256-GCM"


class FinalizeIn(BaseModel):
    manifest: dict
    wrapped_dek: dict | None = None
    wrapped_deks: dict[str, dict] | None = None


class AccessIn(BaseModel):
    intent: str = "view"


class IntegrityIn(BaseModel):
    version: int
    chunk_index: int | None = None
    reason: str = ""


def _iso(d: datetime | None) -> str | None:
    return d.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if d else None


def _public_base(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto")
    host = request.headers.get("x-forwarded-host")
    if proto and host:
        return f"{proto}://{host}"
    return f"{request.url.scheme}://{request.url.netloc}"


async def _get_file(db: AsyncSession, file_id: str) -> File:
    f = await db.get(File, file_id)
    if f is None or f.deleted:
        raise HTTPException(404, {"error": "not_found"})
    return f


async def _active_version(db: AsyncSession, f: File) -> FileVersion | None:
    return await db.get(FileVersion, (f.id, f.current_version))


# ---- upload ---------------------------------------------------------------------------------
@router.post("")
async def create_file(body: FileInit, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    if body.classification not in CLASSIFICATION_LEVELS:
        raise HTTPException(400, {"error": "bad_classification"})
    if body.cipher not in ("AES-256-GCM", "CHACHA20-POLY1305"):
        raise HTTPException(400, {"error": "bad_cipher"})
    f = File(id=new_id(), owner_id=p.user.id, name=body.name, classification=body.classification, department=p.user.department, size=body.size, current_version=1)
    db.add(f)
    db.add(FileVersion(file_id=f.id, version=1, status="uploading", cipher=body.cipher, chunk_count=max(1, body.chunk_count), size=body.size))
    await db.commit()
    await audit().log(actor=p.user.id, action="file.create", resource=f"file:{f.id}", decision="INFO", reason="upload initiated", ip=client_ip(request), device=p.device.id if p.device else None, details={"name": body.name, "classification": body.classification, "chunk_count": body.chunk_count})
    return {"file_id": f.id, "version": 1}


@router.put("/{file_id}/versions/{version}/chunks/{index}", status_code=204)
async def put_chunk(file_id: str, version: int, index: int, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    f = await _get_file(db, file_id)
    if f.owner_id != p.user.id:
        await audit().log(actor=p.user.id, action="file.chunk_put", resource=f"file:{file_id}", decision="DENY", reason="not owner", ip=client_ip(request))
        raise forbidden()
    fv = await db.get(FileVersion, (file_id, version))
    if fv is None or fv.status != "uploading":
        raise HTTPException(409, {"error": "version_not_uploading"})
    if not 0 <= index < fv.chunk_count:
        raise HTTPException(400, {"error": "bad_index"})
    data = await request.body()
    if len(data) > MAX_CHUNK:
        raise HTTPException(413, {"error": "chunk_too_large"})
    await storage().put_chunk(file_id, version, index, data)
    return Response(status_code=204)


@router.post("/{file_id}/versions/{version}/finalize")
async def finalize(file_id: str, version: int, body: FinalizeIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    f = await _get_file(db, file_id)
    if f.owner_id != p.user.id:
        await audit().log(actor=p.user.id, action="file.finalize", resource=f"file:{file_id}", decision="DENY", reason="not owner", ip=client_ip(request))
        raise forbidden()
    fv = await db.get(FileVersion, (file_id, version))
    if fv is None or fv.status != "uploading":
        raise HTTPException(409, {"error": "version_not_uploading"})
    m = body.manifest
    cert = await db.get(UserCert, p.user.id)
    if cert is None or cert.revoked:
        await audit().log(actor=p.user.id, action="file.finalize", resource=f"file:{file_id}", decision="DENY", reason="owner has no issued certificate", ip=client_ip(request))
        raise forbidden()
    if m.get("file_id") != file_id or m.get("version") != version or m.get("owner_id") != p.user.id or m.get("chunk_count") != fv.chunk_count or m.get("cipher") != fv.cipher:
        raise HTTPException(400, {"error": "manifest_mismatch"})
    if m.get("classification") not in CLASSIFICATION_LEVELS:
        raise HTTPException(400, {"error": "bad_classification"})
    if not verify_manifest(m, b64u_decode(cert.cert["sig_pk"])):
        await audit().log(actor=p.user.id, action="file.finalize", resource=f"file:{file_id}", decision="DENY", reason="manifest signature invalid", ip=client_ip(request))
        raise HTTPException(400, {"error": "bad_signature"})
    missing = await storage().missing_chunks(file_id, version, fv.chunk_count)
    if missing:
        raise HTTPException(409, {"error": "missing_chunks", "missing": missing[:20]})
    wrapped = dict(body.wrapped_deks or {})
    if body.wrapped_dek is not None:
        wrapped[p.user.id] = body.wrapped_dek
    if p.user.id not in wrapped:
        raise HTTPException(400, {"error": "owner_wrapped_dek_required"})
    # supersede older versions (hard revocation): delete old chunks + their wrapped DEKs
    old_versions = (await db.execute(select(FileVersion).where(FileVersion.file_id == file_id, FileVersion.version != version, FileVersion.status == "active"))).scalars().all()
    for ov in old_versions:
        ov.status = "superseded"
        await storage().delete_version(file_id, ov.version)
        await db.execute(delete(WrappedDEK).where(WrappedDEK.file_id == file_id, WrappedDEK.version == ov.version))
    await db.execute(delete(WrappedDEK).where(WrappedDEK.file_id == file_id, WrappedDEK.version == version))
    active_grants = {g.recipient_id for g in (await db.execute(select(Grant).where(Grant.file_id == file_id, Grant.revoked.is_(False)))).scalars()}
    for uid, rec in wrapped.items():
        if uid != p.user.id and uid not in active_grants:
            continue
        db.add(WrappedDEK(file_id=file_id, version=version, user_id=uid, record=rec))
    fv.manifest = m
    fv.status = "active"
    fv.size = int(m.get("size", fv.size))
    f.current_version = version
    f.name = m.get("name", f.name)
    f.classification = m["classification"]
    f.size = fv.size
    await db.commit()
    if old_versions:
        await store(request).revoke_blob_urls(file_id)
    await audit().log(actor=p.user.id, action="file.finalize", resource=f"file:{file_id}", decision="INFO", reason="version active" + (" (previous version re-keyed and deleted)" if old_versions else ""), ip=client_ip(request), device=p.device.id if p.device else None, details={"version": version, "merkle_root": m.get("merkle_root"), "recipients": list(wrapped)})
    return {"file_id": file_id, "version": version, "status": "active"}


@router.post("/{file_id}/versions")
async def new_version(file_id: str, body: VersionInit, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    f = await _get_file(db, file_id)
    if f.owner_id != p.user.id:
        await audit().log(actor=p.user.id, action="file.new_version", resource=f"file:{file_id}", decision="DENY", reason="not owner", ip=client_ip(request))
        raise forbidden()
    versions = (await db.execute(select(FileVersion).where(FileVersion.file_id == file_id))).scalars().all()
    v = max(x.version for x in versions) + 1
    for x in versions:
        if x.status == "uploading":
            x.status = "abandoned"
    db.add(FileVersion(file_id=file_id, version=v, status="uploading", cipher=body.cipher, chunk_count=max(1, body.chunk_count), size=body.size))
    await db.commit()
    await audit().log(actor=p.user.id, action="file.new_version", resource=f"file:{file_id}", decision="INFO", reason="re-key started (hard revocation)", ip=client_ip(request), details={"version": v})
    return {"version": v}


# ---- listing / metadata ------------------------------------------------------------------------
@router.get("")
async def list_files(p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    owned = (await db.execute(select(File).where(File.owner_id == p.user.id, File.deleted.is_(False)).order_by(File.created_at))).scalars().all()
    out = []
    users = {u.id: u.username for u in (await db.execute(select(User))).scalars()}
    for f in owned:
        out.append(_file_summary(f, users, "owner"))
    grants = (await db.execute(select(Grant).where(Grant.recipient_id == p.user.id, Grant.revoked.is_(False)))).scalars().all()
    seen = {f.id for f in owned}
    for g in grants:
        if g.file_id in seen:
            continue
        f = await db.get(File, g.file_id)
        if f and not f.deleted:
            seen.add(f.id)
            out.append(_file_summary(f, users, "grant"))
    if config.is_baseline():
        for f in (await db.execute(select(File).where(File.deleted.is_(False)))).scalars():
            if f.id not in seen:
                out.append(_file_summary(f, users, "baseline"))
    return out


def _file_summary(f: File, users: dict, via: str) -> dict:
    return {"file_id": f.id, "name": f.name, "classification": f.classification, "owner_id": f.owner_id, "owner_username": users.get(f.owner_id), "version": f.current_version, "size": f.size, "created_at": _iso(f.created_at), "via": via, "baseline": f.baseline, "department": f.department}


@router.get("/{file_id}")
async def get_file(file_id: str, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    f = await _get_file(db, file_id)
    if not config.is_baseline():
        await authorize_file(request, db, p, f, "view", "file.read_meta")
    fv = await _active_version(db, f)
    users = {u.id: u.username for u in (await db.execute(select(User))).scalars()}
    return {**_file_summary(f, users, "owner" if f.owner_id == p.user.id else "grant"), "manifest": fv.manifest if fv else None, "status": fv.status if fv else None}


@router.post("/{file_id}/access")
async def access(file_id: str, body: AccessIn, request: Request, response: Response, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    if body.intent not in ("view", "download"):
        raise HTTPException(400, {"error": "bad_intent"})
    f = await _get_file(db, file_id)
    t0 = time.perf_counter()
    grant_row = None
    if config.is_baseline():
        await audit().log(actor=p.user.id, action="file.access", resource=f"file:{file_id}", decision="PERMIT", reason="baseline mode: any authenticated user", ip=client_ip(request), details={"intent": body.intent, "mode": "baseline"})
    else:
        _, attrs, grant_row = await authorize_file(request, db, p, f, body.intent, "file.access")
    response.headers["X-PDP-Time-Ms"] = f"{(time.perf_counter() - t0) * 1000:.2f}"  # full authz pipeline: attrs + PDP + audit
    if hasattr(request.state, "pdp_eval_ms"):
        response.headers["X-PDP-Eval-Ms"] = f"{request.state.pdp_eval_ms:.3f}"  # PDP decision only
    fv = await _active_version(db, f)
    if fv is None or fv.status != "active":
        raise HTTPException(409, {"error": "no_active_version"})
    wd = (await db.execute(select(WrappedDEK).where(WrappedDEK.file_id == file_id, WrappedDEK.version == fv.version, WrappedDEK.user_id == p.user.id))).scalar_one_or_none()
    if wd is None and not config.is_baseline():
        await audit().log(actor=p.user.id, action="file.access", resource=f"file:{file_id}", decision="DENY", reason="no wrapped DEK for subject on current version", ip=client_ip(request))
        raise forbidden()
    if grant_row is not None and body.intent == "download":
        grant_row.downloads_used += 1
        await db.commit()
    st = store(request)
    gen = await st.blob_generation(file_id, p.user.id)
    fgen = await st.file_generation(file_id)
    exp = int(time.time()) + config.settings.BLOB_URL_SECONDS
    base = _public_base(request)
    urls = [base + "/api/blob/" + sign_blob_token({"f": file_id, "v": fv.version, "i": i, "u": p.user.id, "g": gen, "fg": fgen, "exp": exp}) for i in range(fv.chunk_count)]
    return {"version": fv.version, "manifest": fv.manifest, "wrapped_dek": wd.record if wd else None, "chunk_urls": urls, "expires_in": config.settings.BLOB_URL_SECONDS, "cipher": fv.cipher}


@blob_router.get("/{token}")
async def get_blob(token: str, request: Request):
    payload = verify_blob_token(token)
    if payload is None:
        raise forbidden()
    st = store(request)
    if not config.is_baseline():
        if payload.get("g") != await st.blob_generation(payload["f"], payload["u"]) or payload.get("fg") != await st.file_generation(payload["f"]):
            await audit().log(actor=payload.get("u"), action="blob.get", resource=f"file:{payload['f']}", decision="DENY", reason="blob URL revoked", ip=client_ip(request))
            raise forbidden()
    try:
        data = await storage().get_chunk(payload["f"], int(payload["v"]), int(payload["i"]))
    except Exception:  # noqa: BLE001
        raise HTTPException(404, {"error": "not_found"})
    return Response(content=data, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})


@router.post("/{file_id}/report-integrity", status_code=204)
async def report_integrity(file_id: str, body: IntegrityIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    await audit().log(actor=p.user.id, action="file.integrity", resource=f"file:{file_id}", decision="ALERT", reason=f"client integrity failure: {body.reason[:200]}", ip=client_ip(request), device=p.device.id if p.device else None, details={"version": body.version, "chunk_index": body.chunk_index})
    return Response(status_code=204)


@router.delete("/{file_id}", status_code=204)
async def delete_file(file_id: str, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    f = await _get_file(db, file_id)
    if f.owner_id != p.user.id:
        await audit().log(actor=p.user.id, action="file.delete", resource=f"file:{file_id}", decision="DENY", reason="not owner", ip=client_ip(request))
        raise forbidden()
    f.deleted = True
    await db.execute(delete(WrappedDEK).where(WrappedDEK.file_id == file_id))
    await db.execute(delete(Grant).where(Grant.file_id == file_id))
    await db.commit()
    await storage().delete_file(file_id)
    await store(request).revoke_blob_urls(file_id)
    await audit().log(actor=p.user.id, action="file.delete", resource=f"file:{file_id}", decision="INFO", reason="deleted (chunks removed)", ip=client_ip(request))
    return Response(status_code=204)


# ---- baseline: server-side encryption, no per-file authorization ---------------------------------
@router.post("/upload")
async def baseline_upload(request: Request, file: UploadFile = UploadFileParam(...), name: str | None = Form(None), classification: str = Form("INTERNAL"), p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    if not config.is_baseline():
        raise HTTPException(404, {"error": "not_found", "hint": "baseline mode only"})
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = await file.read()
    nonce = os.urandom(12)
    ct = AESGCM(config.settings.baseline_key).encrypt(nonce, data, None)
    f = File(id=new_id(), owner_id=p.user.id, name=name or file.filename or "upload", classification=classification if classification in CLASSIFICATION_LEVELS else "INTERNAL", department=p.user.department, size=len(data), current_version=1, baseline=True)
    db.add(f)
    db.add(FileVersion(file_id=f.id, version=1, status="active", cipher="AES-256-GCM(server)", chunk_count=1, size=len(data), manifest=None))
    await db.commit()
    await storage().put_baseline(f.id, nonce + ct)
    await audit().log(actor=p.user.id, action="file.upload", resource=f"file:{f.id}", decision="INFO", reason="baseline server-side encrypted upload", ip=client_ip(request), details={"name": f.name, "size": len(data)})
    return {"file_id": f.id, "version": 1}


@router.get("/{file_id}/download")
async def baseline_download(file_id: str, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    if not config.is_baseline():
        await audit().log(actor=p.user.id, action="file.download", resource=f"file:{file_id}", decision="DENY", reason="server-side download is baseline-only", ip=client_ip(request))
        raise forbidden()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    f = await _get_file(db, file_id)
    if not f.baseline:
        raise HTTPException(409, {"error": "not_baseline_file"})
    raw = await storage().get_baseline(file_id)
    data = AESGCM(config.settings.baseline_key).decrypt(raw[:12], raw[12:], None)
    await audit().log(actor=p.user.id, action="file.download", resource=f"file:{file_id}", decision="PERMIT", reason="baseline: authenticated user", ip=client_ip(request))
    return Response(content=data, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{f.name}"'})
