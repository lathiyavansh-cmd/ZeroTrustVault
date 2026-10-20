"""Auth: login (password) -> MFA (TOTP / WebAuthn) -> DPoP-bound tokens; refresh, step-up, logout, devices."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ztv_crypto.dpop import jwk_thumbprint
from ztv_crypto.kdf import verify_password

from .. import config
from ..audit import audit
from ..db import get_db
from ..models import Device, Session, User, WebAuthnCredential, new_id, utcnow
from ..pep import Principal, authenticate, client_ip, request_htu, store, unauthorized
from ..security import AuthError, check_dpop, compute_risk, issue_access_token, new_opaque_token, risk_level

router = APIRouter(prefix="/auth", tags=["auth"])
devices_router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceIn(BaseModel):
    jwk: dict | None = None
    name: str = "device"
    posture: str = "registered"


class LoginIn(BaseModel):
    username: str
    password: str
    device: DeviceIn | None = None


class TotpIn(BaseModel):
    login_ticket: str
    code: str


class RefreshIn(BaseModel):
    refresh_token: str


class CodeIn(BaseModel):
    code: str


class CredentialIn(BaseModel):
    credential: dict
    login_ticket: str | None = None


class TicketIn(BaseModel):
    login_ticket: str


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


async def _fail_login(request: Request, st, user: User | None, reason: str, code: str = "invalid_credentials") -> HTTPException:
    await audit().log(actor=user.id if user else None, action="auth.login", resource=f"user:{user.username if user else 'unknown'}", decision="DENY", reason=reason, ip=client_ip(request), details={"code": code})
    return unauthorized(code)


@router.post("/login")
async def login(body: LoginIn, request: Request, db: AsyncSession = Depends(get_db)):
    st = store(request)
    ip = client_ip(request)
    if await st.rate_limited(f"login:{ip}", config.settings.LOGIN_RATE_PER_MINUTE):
        await audit().log(actor=None, action="auth.login", resource=f"user:{body.username}", decision="DENY", reason="rate limited", ip=ip)
        raise HTTPException(status_code=429, detail={"error": "too_many_requests"})
    user = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if user is None:
        verify_password("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", body.password)  # constant-time-ish
        raise await _fail_login(request, st, None, "unknown user")
    if await st.locked(user.id) or (user.locked_until and user.locked_until > datetime.now(timezone.utc)):
        raise await _fail_login(request, st, user, "account locked", "locked")
    if not verify_password(user.password_hash, body.password):
        n = await st.record_failed_login(user.id)
        user.failed_logins = n
        if n >= config.settings.LOGIN_MAX_FAILURES:
            await st.lock(user.id, config.settings.LOGIN_LOCK_SECONDS)
            user.locked_until = datetime.now(timezone.utc) + timedelta(seconds=config.settings.LOGIN_LOCK_SECONDS)
            await db.commit()
            raise await _fail_login(request, st, user, f"wrong password #{n}: account locked for {config.settings.LOGIN_LOCK_SECONDS}s", "locked")
        await db.commit()
        raise await _fail_login(request, st, user, f"wrong password #{n}")

    if config.is_baseline():
        tok = new_opaque_token()
        await st.put_bearer(tok, user.id)
        user.failed_logins = 0
        user.locked_until = None
        await db.commit()
        await audit().log(actor=user.id, action="auth.login", resource=f"user:{user.username}", decision="PERMIT", reason="baseline password login", ip=ip, details={"mode": "baseline"})
        return {"status": "ok", "token_type": "Bearer", "access_token": tok, "user": user.public()}

    dev = body.device
    if dev is None or not dev.jwk:
        raise await _fail_login(request, st, user, "device jwk missing", "device_required")
    try:
        jkt = jwk_thumbprint(dev.jwk)
    except (KeyError, TypeError):
        raise await _fail_login(request, st, user, "malformed device jwk", "device_required")
    device = (await db.execute(select(Device).where(Device.user_id == user.id, Device.jkt == jkt))).scalar_one_or_none()
    if device is None:
        device = Device(id=new_id(), user_id=user.id, jkt=jkt, jwk=dev.jwk, name=dev.name, posture=dev.posture if dev.posture in ("registered", "trusted") else "registered")
        db.add(device)
    elif device.revoked:
        raise await _fail_login(request, st, user, "device revoked", "device_revoked")
    else:
        device.last_seen = utcnow()
        device.name = dev.name or device.name
    await db.commit()
    methods = []
    if user.totp_secret:
        methods.append("totp")
    creds = (await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))).scalars().all()
    if creds:
        methods.append("webauthn")
    if not methods:
        methods = ["totp"]
    ticket = await st.put_login_ticket({"user_id": user.id, "device_id": device.id, "jkt": jkt, "ip": ip, "geo": request.headers.get("x-demo-geo"), "demo_risk": request.headers.get("x-demo-risk", "0")})
    await audit().log(actor=user.id, action="auth.password", resource=f"user:{user.username}", decision="INFO", reason="password ok, MFA required", ip=ip, device=device.id)
    return {"status": "mfa_required", "login_ticket": ticket, "methods": methods}


async def _finish_login(request: Request, db: AsyncSession, ticket: dict, amr: list[str]) -> dict:
    st = store(request)
    user = await db.get(User, ticket["user_id"])
    device = await db.get(Device, ticket["device_id"])
    if user is None or device is None:
        raise unauthorized("invalid_ticket")
    ip = client_ip(request)
    # The session score is built from GENUINE signals only (new device / IP / hour / failures / geo).
    # The demo-only `X-Demo-Risk` header is a per-request environment signal added by the PEP on each
    # authorization, so it must not also be folded into the session score (it would double-count).
    geo = request.headers.get("x-demo-geo") or ticket.get("geo")
    score, signals = await compute_risk(st, user.id, ip=ip, jkt=ticket["jkt"], geo=geo, demo_risk=0)
    await st.clear_failed_logins(user.id)
    user.failed_logins = 0
    user.locked_until = None
    sess = Session(id=new_id(), user_id=user.id, device_id=device.id, amr=amr, risk_score=score, risk_level=risk_level(score), ip=ip)
    db.add(sess)
    device.last_seen = utcnow()
    await db.commit()
    await st.create_session(sess.id, user.id, device.id, ticket["jkt"])
    access = issue_access_token(user_id=user.id, session_id=sess.id, device_id=device.id, jkt=ticket["jkt"], amr=amr)
    refresh = await st.issue_refresh(sess.id, user.id, device.id, ticket["jkt"])
    await audit().log(actor=user.id, action="auth.login", resource=f"user:{user.username}", decision="PERMIT", reason="MFA ok", ip=ip, device=device.id, details={"amr": amr, "risk": score, "signals": signals, "session": sess.id})
    return {"status": "ok", "token_type": "DPoP", "access_token": access, "refresh_token": refresh, "expires_in": config.settings.ACCESS_TOKEN_SECONDS, "user": user.public(), "device_id": device.id, "session_id": sess.id, "risk": {"score": score, "level": risk_level(score), "signals": signals}}


@router.post("/mfa/totp")
async def mfa_totp(body: TotpIn, request: Request, db: AsyncSession = Depends(get_db)):
    st = store(request)
    ticket = await st.pop_login_ticket(body.login_ticket)
    if ticket is None:
        raise unauthorized("invalid_ticket")
    user = await db.get(User, ticket["user_id"])
    if user is None or not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        await st.r.set(f"ticket:{body.login_ticket}", json.dumps(ticket), ex=300)
        n = await st.record_failed_login(ticket["user_id"]) if user else 0
        if user and n >= config.settings.LOGIN_MAX_FAILURES:
            await st.lock(user.id, config.settings.LOGIN_LOCK_SECONDS)
        await audit().log(actor=ticket["user_id"], action="auth.mfa", resource="totp", decision="DENY", reason="bad TOTP code", ip=client_ip(request), device=ticket["device_id"])
        raise unauthorized("mfa_failed")
    return await _finish_login(request, db, ticket, ["pwd", "totp"])


# ---- WebAuthn --------------------------------------------------------------------------
def _wa_origins() -> list[str]:
    return [o.strip() for o in config.settings.WEBAUTHN_ORIGINS.split(",") if o.strip()]


@router.post("/webauthn/register/options")
async def webauthn_register_options(request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement

    creds = (await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == p.user.id))).scalars().all()
    opts = generate_registration_options(rp_id=config.settings.WEBAUTHN_RP_ID, rp_name="ZeroTrustVault", user_id=p.user.id.encode(), user_name=p.user.username, user_display_name=p.user.username, exclude_credentials=[PublicKeyCredentialDescriptor(id=_b64d(c.credential_id)) for c in creds], authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.PREFERRED))
    await store(request).put_challenge(f"reg:{p.user.id}", {"challenge": _b64(opts.challenge)})
    return json.loads(options_to_json(opts))


@router.post("/webauthn/register/verify", status_code=200)
async def webauthn_register_verify(body: CredentialIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    from webauthn import verify_registration_response

    chal = await store(request).pop_challenge(f"reg:{p.user.id}")
    if chal is None:
        raise HTTPException(400, {"error": "no_challenge"})
    try:
        v = verify_registration_response(credential=body.credential, expected_challenge=_b64d(chal["challenge"]), expected_rp_id=config.settings.WEBAUTHN_RP_ID, expected_origin=_wa_origins())
    except Exception as e:  # noqa: BLE001
        await audit().log(actor=p.user.id, action="webauthn.register", resource="credential", decision="DENY", reason=str(e), ip=client_ip(request))
        raise HTTPException(400, {"error": "registration_failed"})
    db.add(WebAuthnCredential(user_id=p.user.id, credential_id=_b64(v.credential_id), public_key=_b64(v.credential_public_key), sign_count=v.sign_count, transports=list(body.credential.get("response", {}).get("transports") or [])))
    await db.commit()
    await audit().log(actor=p.user.id, action="webauthn.register", resource="credential", decision="PERMIT", reason="credential registered", ip=client_ip(request))
    return {"status": "ok", "credential_id": _b64(v.credential_id)}


@router.post("/webauthn/login/options")
async def webauthn_login_options(body: TicketIn, request: Request, db: AsyncSession = Depends(get_db)):
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    st = store(request)
    raw = await st.r.get(f"ticket:{body.login_ticket}")
    if not raw:
        raise unauthorized("invalid_ticket")
    ticket = json.loads(raw)
    creds = (await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == ticket["user_id"]))).scalars().all()
    opts = generate_authentication_options(rp_id=config.settings.WEBAUTHN_RP_ID, allow_credentials=[PublicKeyCredentialDescriptor(id=_b64d(c.credential_id)) for c in creds], user_verification=UserVerificationRequirement.PREFERRED)
    await st.put_challenge(f"auth:{body.login_ticket}", {"challenge": _b64(opts.challenge)})
    return json.loads(options_to_json(opts))


@router.post("/webauthn/login/verify")
async def webauthn_login_verify(body: CredentialIn, request: Request, db: AsyncSession = Depends(get_db)):
    from webauthn import verify_authentication_response

    st = store(request)
    if not body.login_ticket:
        raise unauthorized("invalid_ticket")
    chal = await st.pop_challenge(f"auth:{body.login_ticket}")
    ticket = await st.pop_login_ticket(body.login_ticket)
    if chal is None or ticket is None:
        raise unauthorized("invalid_ticket")
    cid = body.credential.get("id") or body.credential.get("rawId")
    cred = (await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == ticket["user_id"], WebAuthnCredential.credential_id == cid))).scalar_one_or_none()
    if cred is None:
        raise unauthorized("mfa_failed")
    try:
        v = verify_authentication_response(credential=body.credential, expected_challenge=_b64d(chal["challenge"]), expected_rp_id=config.settings.WEBAUTHN_RP_ID, expected_origin=_wa_origins(), credential_public_key=_b64d(cred.public_key), credential_current_sign_count=cred.sign_count)
    except Exception as e:  # noqa: BLE001
        await audit().log(actor=ticket["user_id"], action="auth.mfa", resource="webauthn", decision="DENY", reason=str(e), ip=client_ip(request))
        raise unauthorized("mfa_failed")
    cred.sign_count = v.new_sign_count
    await db.commit()
    return await _finish_login(request, db, ticket, ["pwd", "webauthn"])


def _b64(b: bytes) -> str:
    from ztv_crypto.encoding import b64u

    return b64u(b)


def _b64d(s: str) -> bytes:
    from ztv_crypto.encoding import b64u_decode

    return b64u_decode(s)


# ---- refresh / step-up / logout / me ------------------------------------------------------
@router.post("/refresh")
async def refresh(body: RefreshIn, request: Request, db: AsyncSession = Depends(get_db)):
    st = store(request)
    if config.is_baseline():
        raise unauthorized("not_supported")
    data = await st.get_refresh(body.refresh_token)
    if data is None:
        await audit().log(actor=None, action="auth.refresh", resource="refresh", decision="DENY", reason="unknown refresh token", ip=client_ip(request))
        raise unauthorized("invalid_refresh")
    try:
        await check_dpop(st, request.headers.get("dpop"), request.method, request_htu(request), None, data["jkt"])
    except AuthError as e:
        await audit().log(actor=data["user_id"], action="auth.refresh", resource="refresh", decision="DENY", reason=e.reason, ip=client_ip(request), device=data["device_id"])
        raise unauthorized(e.code)
    if await st.session_alive(data["sid"]) is None:
        raise unauthorized("session_revoked")
    sess = await db.get(Session, data["sid"])
    access = issue_access_token(user_id=data["user_id"], session_id=data["sid"], device_id=data["device_id"], jkt=data["jkt"], amr=list(sess.amr) if sess else ["pwd"])
    await audit().log(actor=data["user_id"], action="auth.refresh", resource="refresh", decision="PERMIT", reason="rotated access token", ip=client_ip(request), device=data["device_id"])
    return {"access_token": access, "expires_in": config.settings.ACCESS_TOKEN_SECONDS, "token_type": "DPoP"}


@router.post("/step-up")
async def step_up(body: CodeIn, request: Request, p: Principal = Depends(authenticate)):
    st = store(request)
    if p.session_id is None:
        raise unauthorized("not_supported")
    if not p.user.totp_secret or not pyotp.TOTP(p.user.totp_secret).verify(body.code, valid_window=1):
        await audit().log(actor=p.user.id, action="auth.step_up", resource=f"session:{p.session_id}", decision="DENY", reason="bad TOTP code", ip=client_ip(request), device=p.device.id if p.device else None)
        raise unauthorized("mfa_failed")
    until = await st.elevate(p.session_id)
    await audit().log(actor=p.user.id, action="auth.step_up", resource=f"session:{p.session_id}", decision="PERMIT", reason="fresh MFA", ip=client_ip(request), device=p.device.id if p.device else None, details={"elevated_until": _iso(until)})
    return {"elevated_until": _iso(until)}


@router.post("/logout", status_code=204)
async def logout(request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    st = store(request)
    if p.session_id:
        await st.revoke_session(p.session_id)
        sess = await db.get(Session, p.session_id)
        if sess:
            sess.revoked_at = utcnow()
            await db.commit()
    elif p.token:
        await st.r.delete(f"bearer:{p.token}")
    await audit().log(actor=p.user.id, action="auth.logout", resource=f"session:{p.session_id}", decision="INFO", reason="logout", ip=client_ip(request), device=p.device.id if p.device else None)
    return Response(status_code=204)


@router.get("/me")
async def me(request: Request, p: Principal = Depends(authenticate)):
    dev = None
    if p.device:
        dev = {"id": p.device.id, "name": p.device.name, "jkt": p.device.jkt, "posture": p.device.posture}
    return {"user": p.user.public(), "device": dev, "session": {"id": p.session_id, "risk": {"score": p.risk_score, "level": p.risk_level}, "elevated_until": _iso(p.elevated_until) if p.elevated_until else None, "amr": p.amr, "mode": config.current_mode()}}


@router.post("/totp/setup")
async def totp_setup(request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    secret = pyotp.random_base32()
    await store(request).put_challenge(f"totp:{p.user.id}", {"secret": secret}, ttl=600)
    return {"secret": secret, "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=p.user.username, issuer_name="ZeroTrustVault")}


@router.post("/totp/confirm", status_code=204)
async def totp_confirm(body: CodeIn, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    chal = await store(request).pop_challenge(f"totp:{p.user.id}")
    if chal is None or not pyotp.TOTP(chal["secret"]).verify(body.code, valid_window=1):
        raise HTTPException(400, {"error": "bad_code"})
    user = await db.get(User, p.user.id)
    user.totp_secret = chal["secret"]
    user.totp_confirmed = True
    await db.commit()
    await audit().log(actor=p.user.id, action="auth.totp_enrol", resource=f"user:{p.user.username}", decision="INFO", reason="TOTP enrolled", ip=client_ip(request))
    return Response(status_code=204)


# ---- devices ---------------------------------------------------------------------------
@devices_router.get("")
async def list_devices(p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Device).where(Device.user_id == p.user.id, Device.revoked.is_(False)).order_by(Device.created_at))).scalars().all()
    return [{"id": d.id, "name": d.name, "jkt": d.jkt, "posture": d.posture, "created_at": _dt(d.created_at), "last_seen": _dt(d.last_seen)} for d in rows]


@devices_router.delete("/{device_id}", status_code=204)
async def delete_device(device_id: str, request: Request, p: Principal = Depends(authenticate), db: AsyncSession = Depends(get_db)):
    d = await db.get(Device, device_id)
    if d is None or (d.user_id != p.user.id and not p.is_admin):
        raise HTTPException(404, {"error": "not_found"})
    d.revoked = True
    await db.commit()
    n = await store(request).revoke_device_sessions(d.id)
    await audit().log(actor=p.user.id, action="device.revoke", resource=f"device:{d.id}", decision="INFO", reason=f"device removed, {n} sessions revoked", ip=client_ip(request))
    return Response(status_code=204)


def _dt(d: datetime | None) -> str | None:
    return d.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if d else None
