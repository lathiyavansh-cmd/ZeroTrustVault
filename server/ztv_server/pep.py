"""Policy Enforcement Point: FastAPI dependencies implementing the per-request chain.

TLS/mTLS (uvicorn) -> token -> session alive -> DPoP proof/replay/binding -> attribute collection -> PDP.
Every decision is written to the audit log.  Authz failures return generic bodies; reasons go to the log only.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ztv_crypto.sign import verify_grant

from . import config
from .audit import audit
from .db import get_db
from .models import Device, File, Grant, Session, User, UserCert
from .pdp import Decision, LocalJsonPDP, OpaPDP, PolicyDecisionPoint, level_of
from .security import AuthError, SessionStore, check_dpop, verify_access_token


def unauthorized(code: str) -> HTTPException:
    return HTTPException(status_code=401, detail={"error": "unauthorized", "code": code}, headers={"WWW-Authenticate": "DPoP"})


def forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail={"error": "forbidden"})


@dataclass
class Principal:
    user: User
    session_id: str | None = None
    device: Device | None = None
    amr: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "low"
    elevated_until: int | None = None
    token: str | None = None
    claims: dict = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return self.user.role == "admin"

    @property
    def mfa_fresh(self) -> bool:
        return self.elevated_until is not None and self.elevated_until > int(time.time())


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def request_htu(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto")
    host = request.headers.get("x-forwarded-host")
    if proto and host:
        return f"{proto.lower()}://{host.lower()}{request.url.path}"
    return f"{request.url.scheme}://{request.url.netloc.lower()}{request.url.path}"


def store(request: Request) -> SessionStore:
    return request.app.state.store


def pdp(request: Request) -> PolicyDecisionPoint:
    return request.app.state.pdp


def build_pdp(policy: dict) -> PolicyDecisionPoint:
    local = LocalJsonPDP(policy)
    if config.settings.OPA_URL:
        return OpaPDP(config.settings.OPA_URL, fallback=local)
    return local


async def _deny_auth(request: Request, code: str, reason: str, actor: str | None = None) -> HTTPException:
    await audit().log(actor=actor, action="auth.request", resource=request.url.path, decision="DENY", reason=reason, ip=client_ip(request), device=None, details={"code": code, "method": request.method})
    return unauthorized(code)


async def authenticate(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    """Token + session + DPoP chain (ZTV) or opaque bearer (baseline)."""
    st = store(request)
    auth = request.headers.get("authorization", "")
    scheme, _, cred = auth.partition(" ")
    cred = cred.strip()
    if config.is_baseline():
        if scheme.lower() != "bearer" or not cred:
            raise await _deny_auth(request, "missing_token", "no bearer token")
        user_id = await st.get_bearer(cred)
        if not user_id:
            raise await _deny_auth(request, "invalid_token", "unknown/expired bearer token")
        user = await db.get(User, user_id)
        if user is None:
            raise await _deny_auth(request, "invalid_token", "bearer token user missing")
        return Principal(user=user, session_id=None, amr=["pwd"], token=cred)

    if scheme.lower() != "dpop" or not cred:
        raise await _deny_auth(request, "missing_token", "Authorization: DPoP <token> required")
    try:
        claims = verify_access_token(cred)
    except AuthError as e:
        raise await _deny_auth(request, e.code, e.reason)
    sess = await st.session_alive(claims["sid"])
    if sess is None:
        raise await _deny_auth(request, "session_revoked", "session not alive (revoked or expired)", claims.get("sub"))
    try:
        await check_dpop(st, request.headers.get("dpop"), request.method, request_htu(request), cred, claims["cnf"]["jkt"])
    except AuthError as e:
        raise await _deny_auth(request, e.code, e.reason, claims.get("sub"))
    user = await db.get(User, claims["sub"])
    if user is None:
        raise await _deny_auth(request, "invalid_token", "user missing", claims.get("sub"))
    device = await db.get(Device, claims.get("dev")) if claims.get("dev") else None
    if device is not None and device.revoked:
        raise await _deny_auth(request, "device_revoked", "device revoked", user.id)
    srow = await db.get(Session, claims["sid"])
    return Principal(user=user, session_id=claims["sid"], device=device, amr=list(claims.get("amr") or []), risk_score=srow.risk_score if srow else 0, risk_level=srow.risk_level if srow else "low", elevated_until=await st.elevated_until(claims["sid"]), token=cred, claims=claims)


async def require_admin(request: Request, db: AsyncSession = Depends(get_db)) -> Principal | None:
    """Admin role with a normal session OR X-Admin-Key (offline tools). Returns None for key auth."""
    key = request.headers.get("x-admin-key")
    if key:
        if key == config.settings.ADMIN_API_KEY:
            return None
        await audit().log(actor=None, action="admin.key", resource=request.url.path, decision="DENY", reason="bad admin key", ip=client_ip(request))
        raise forbidden()
    p = await authenticate(request, db)
    if not p.is_admin:
        await audit().log(actor=p.user.id, action="admin.access", resource=request.url.path, decision="DENY", reason=f"role {p.user.role} is not admin", ip=client_ip(request), device=p.device.id if p.device else None)
        raise forbidden()
    return p


def require_admin_key(request: Request) -> None:
    if request.headers.get("x-admin-key") != config.settings.ADMIN_API_KEY:
        raise forbidden()


# ---- attribute collection + PDP for file routes -----------------------------------------
def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if dt else None


async def collect_attributes(request: Request, db: AsyncSession, p: Principal, f: File, intent: str) -> tuple[dict, Grant | None]:
    now = datetime.now(timezone.utc)
    st = store(request)
    emp_end = p.user.employment_end
    cert = await db.get(UserCert, p.user.id)
    demo_risk = 0
    try:
        demo_risk = int(request.headers.get("x-demo-risk", "0") or 0)
    except ValueError:
        demo_risk = 0
    geo = request.headers.get("x-demo-geo")
    risk = p.risk_score + demo_risk
    last_geo = await st.last_geo(p.user.id)
    if geo and last_geo and geo != last_geo:
        risk += 30
    risk = min(risk, 100)
    from .security import risk_level

    grant_row = (await db.execute(select(Grant).where(Grant.file_id == f.id, Grant.recipient_id == p.user.id, Grant.revoked.is_(False)))).scalars().first()
    grant_attrs: dict = {"present": False, "rights": [], "expired": True, "downloads_left": 0, "posture_ok": False, "signature_ok": False}
    if grant_row is not None:
        g = grant_row.grant
        owner_cert = await db.get(UserCert, f.owner_id)
        sig_ok = bool(owner_cert and not owner_cert.revoked and verify_grant(g, _b64(owner_cert.cert["sig_pk"])))
        try:
            expired = datetime.fromisoformat(g["expires_at"].replace("Z", "+00:00")) <= now
        except Exception:  # noqa: BLE001
            expired = True
        posture = p.device.posture if p.device else "none"
        req_posture = g.get("required_posture", "any")
        posture_ok = req_posture == "any" or posture == req_posture or (req_posture == "registered" and posture == "trusted")
        grant_attrs = {"present": True, "grant_id": g["grant_id"], "rights": list(g.get("rights", [])), "expired": expired, "downloads_left": int(g.get("max_downloads", 0)) - int(grant_row.downloads_used), "posture_ok": posture_ok, "signature_ok": sig_ok}
    attrs = {
        "subject": {"id": p.user.id, "username": p.user.username, "role": p.user.role, "department": p.user.department, "clearance": int(p.user.clearance), "employment_end": _iso(emp_end), "employment_active": emp_end is None or emp_end > now, "mfa_fresh": p.mfa_fresh, "cert_revoked": bool(cert and cert.revoked), "has_cert": bool(cert and not cert.revoked)},
        "device": {"id": p.device.id if p.device else None, "posture": p.device.posture if p.device else "none", "jkt": p.device.jkt if p.device else None, "registered": bool(p.device and not p.device.revoked)},
        "resource": {"file_id": f.id, "owner_id": f.owner_id, "department": f.department, "classification": f.classification, "level": level_of(f.classification), "version": f.current_version},
        "environment": {"ip": client_ip(request), "geo": geo or last_geo, "hour_utc": now.hour, "risk_score": risk, "risk_level": risk_level(risk), "mode": config.current_mode()},
        "grant": grant_attrs,
        "action": {"intent": intent},
    }
    return attrs, grant_row


def _b64(s: str) -> bytes:
    from ztv_crypto.encoding import b64u_decode

    return b64u_decode(s)


async def authorize_file(request: Request, db: AsyncSession, p: Principal, f: File, intent: str, action: str) -> tuple[Decision, dict, Grant | None]:
    """Collect attributes, ask the PDP, log the decision, and raise 403/401 on DENY / step-up."""
    attrs, grant_row = await collect_attributes(request, db, p, f, intent)
    t_eval = time.perf_counter()
    decision = await pdp(request).decide(attrs)
    request.state.pdp_eval_ms = (time.perf_counter() - t_eval) * 1000.0  # the policy decision alone
    details = {"rule_id": decision.rule_id, "intent": intent, "risk": attrs["environment"]["risk_score"], "obligations": decision.obligations, "grant": attrs["grant"].get("grant_id"), "classification": f.classification}
    dev = p.device.id if p.device else None
    if not decision.permit:
        await audit().log(actor=p.user.id, action=action, resource=f"file:{f.id}", decision="DENY", reason=decision.reason, ip=client_ip(request), device=dev, details=details)
        raise forbidden()
    if "step_up_required" in decision.obligations:
        await audit().log(actor=p.user.id, action=action, resource=f"file:{f.id}", decision="DENY", reason="step-up required: " + decision.reason, ip=client_ip(request), device=dev, details={**details, "step_up": True})
        raise unauthorized("step_up_required")
    await audit().log(actor=p.user.id, action=action, resource=f"file:{f.id}", decision="PERMIT", reason=decision.reason, ip=client_ip(request), device=dev, details=details)
    return decision, attrs, grant_row
