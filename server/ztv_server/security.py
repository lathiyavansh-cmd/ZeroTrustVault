"""Tokens (EdDSA access tokens, refresh tokens, baseline bearer), DPoP, sessions, rate limits, risk scoring, blob URLs."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from redis.asyncio import Redis

from ztv_crypto.dpop import DPOP_WINDOW_SECONDS, JTI_CACHE_SECONDS, DPoPError, verify_dpop_proof
from ztv_crypto.encoding import b64u, b64u_decode

from .config import settings


class AuthError(Exception):
    def __init__(self, code: str, reason: str | None = None):
        super().__init__(reason or code)
        self.code = code
        self.reason = reason or code


# ---- key material ---------------------------------------------------------------
def _load_ed25519(path: Path) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    d = json.loads(path.read_text())
    sk = serialization.load_der_private_key(b64u_decode(d["sk"]), password=None)
    assert isinstance(sk, ed25519.Ed25519PrivateKey)
    return sk, b64u_decode(d["pk"])


class ServerKeys:
    def __init__(self, keys_dir: str | None = None):
        d = Path(keys_dir or settings.SERVER_KEYS_DIR)
        self.signing_sk, self.signing_pk = _load_ed25519(d / "server_signing.json")
        self.audit_sk, self.audit_pk = _load_ed25519(d / "audit_signing.json")
        self.blob_hmac = b64u_decode(json.loads((d / "blob_url_hmac.json").read_text())["k"])
        self.org_root_pk = settings.org_root_pk


_keys: ServerKeys | None = None


def keys() -> ServerKeys:
    global _keys
    if _keys is None:
        _keys = ServerKeys()
    return _keys


def set_keys(k: ServerKeys) -> None:
    global _keys
    _keys = k


# ---- access / refresh tokens (CONTRACT §9) ----------------------------------------
def issue_access_token(*, user_id: str, session_id: str, device_id: str, jkt: str, amr: list[str], sk: ed25519.Ed25519PrivateKey | None = None, now: int | None = None) -> str:
    now = now or int(time.time())
    claims = {"iss": "ztv", "sub": user_id, "sid": session_id, "dev": device_id, "iat": now, "exp": now + settings.ACCESS_TOKEN_SECONDS, "cnf": {"jkt": jkt}, "amr": amr}
    return jwt.encode(claims, sk or keys().signing_sk, algorithm="EdDSA")


def verify_access_token(token: str, pk_raw: bytes | None = None, now: int | None = None) -> dict:
    pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_raw or keys().signing_pk)
    try:
        claims = jwt.decode(token, pk, algorithms=["EdDSA"], issuer="ztv", options={"verify_exp": False, "require": ["sub", "sid", "exp", "cnf"]})
    except jwt.PyJWTError as e:
        raise AuthError("invalid_token", f"token signature/claims invalid: {e}") from e
    now = now or int(time.time())
    if int(claims["exp"]) < now:
        raise AuthError("token_expired", "access token expired")
    return claims


# ---- redis-backed state ----------------------------------------------------------
class SessionStore:
    """All revocable state lives in Redis so revocation is instant."""

    def __init__(self, redis: Redis):
        self.r = redis

    async def create_session(self, sid: str, user_id: str, device_id: str, jkt: str, ttl: int | None = None) -> None:
        await self.r.set(f"sess:{sid}", json.dumps({"user_id": user_id, "device_id": device_id, "jkt": jkt}), ex=ttl or settings.REFRESH_TOKEN_SECONDS)
        await self.r.sadd(f"usersess:{user_id}", sid)
        await self.r.sadd(f"devsess:{device_id}", sid)

    async def session_alive(self, sid: str) -> dict | None:
        raw = await self.r.get(f"sess:{sid}")
        return json.loads(raw) if raw else None

    async def revoke_session(self, sid: str) -> None:
        raw = await self.r.get(f"sess:{sid}")
        await self.r.delete(f"sess:{sid}", f"elev:{sid}")
        if raw:
            d = json.loads(raw)
            await self.r.srem(f"usersess:{d['user_id']}", sid)
        for k in await self.r.smembers(f"refresh_by_sid:{sid}"):
            await self.r.delete(f"refresh:{_s(k)}")
        await self.r.delete(f"refresh_by_sid:{sid}")

    async def revoke_device_sessions(self, device_id: str) -> int:
        n = 0
        for sid in await self.r.smembers(f"devsess:{device_id}"):
            await self.revoke_session(_s(sid))
            n += 1
        await self.r.delete(f"devsess:{device_id}")
        return n

    async def revoke_user_sessions(self, user_id: str) -> int:
        n = 0
        for sid in await self.r.smembers(f"usersess:{user_id}"):
            await self.revoke_session(_s(sid))
            n += 1
        return n

    async def active_sessions(self) -> int:
        n = 0
        async for _ in self.r.scan_iter(match="sess:*", count=500):
            n += 1
        return n

    async def issue_refresh(self, sid: str, user_id: str, device_id: str, jkt: str) -> str:
        tok = b64u(os.urandom(32))
        await self.r.set(f"refresh:{tok}", json.dumps({"sid": sid, "user_id": user_id, "device_id": device_id, "jkt": jkt}), ex=settings.REFRESH_TOKEN_SECONDS)
        await self.r.sadd(f"refresh_by_sid:{sid}", tok)
        return tok

    async def get_refresh(self, tok: str) -> dict | None:
        raw = await self.r.get(f"refresh:{tok}")
        return json.loads(raw) if raw else None

    async def jti_unseen(self, jti: str) -> bool:
        return bool(await self.r.set(f"jti:{jti}", "1", ex=JTI_CACHE_SECONDS, nx=True))

    async def elevate(self, sid: str, seconds: int | None = None) -> int:
        until = int(time.time()) + (seconds or settings.STEP_UP_SECONDS)
        await self.r.set(f"elev:{sid}", str(until), ex=seconds or settings.STEP_UP_SECONDS)
        return until

    async def elevated_until(self, sid: str) -> int | None:
        v = await self.r.get(f"elev:{sid}")
        return int(v) if v else None

    # login ticket (between password and MFA)
    async def put_login_ticket(self, data: dict) -> str:
        t = b64u(os.urandom(24))
        await self.r.set(f"ticket:{t}", json.dumps(data), ex=300)
        return t

    async def pop_login_ticket(self, t: str) -> dict | None:
        raw = await self.r.get(f"ticket:{t}")
        if raw:
            await self.r.delete(f"ticket:{t}")
            return json.loads(raw)
        return None

    async def put_challenge(self, key: str, data: dict, ttl: int = 300) -> None:
        await self.r.set(f"chal:{key}", json.dumps(data), ex=ttl)

    async def pop_challenge(self, key: str) -> dict | None:
        raw = await self.r.get(f"chal:{key}")
        if raw:
            await self.r.delete(f"chal:{key}")
            return json.loads(raw)
        return None

    # rate limiting / lockout
    async def rate_limited(self, bucket: str, limit: int, window: int = 60) -> bool:
        k = f"rl:{bucket}"
        n = await self.r.incr(k)
        if n == 1:
            await self.r.expire(k, window)
        return n > limit

    async def record_failed_login(self, user_id: str) -> int:
        k = f"fail:{user_id}"
        n = await self.r.incr(k)
        if n == 1:
            await self.r.expire(k, settings.LOGIN_LOCK_SECONDS)
        return n

    async def failed_logins(self, user_id: str) -> int:
        v = await self.r.get(f"fail:{user_id}")
        return int(v) if v else 0

    async def clear_failed_logins(self, user_id: str) -> None:
        await self.r.delete(f"fail:{user_id}")

    async def lock(self, user_id: str, seconds: int) -> None:
        await self.r.set(f"lock:{user_id}", "1", ex=seconds)

    async def locked(self, user_id: str) -> bool:
        return bool(await self.r.exists(f"lock:{user_id}"))

    # risk memory
    async def seen_before(self, user_id: str, kind: str, value: str) -> bool:
        return bool(await self.r.sismember(f"known:{kind}:{user_id}", value))

    async def remember(self, user_id: str, kind: str, value: str) -> None:
        await self.r.sadd(f"known:{kind}:{user_id}", value)

    async def last_geo(self, user_id: str) -> str | None:
        v = await self.r.get(f"geo:{user_id}")
        return _s(v) if v else None

    async def set_geo(self, user_id: str, geo: str) -> None:
        await self.r.set(f"geo:{user_id}", geo)

    # blob URL revocation generation
    async def blob_generation(self, file_id: str, user_id: str) -> int:
        v = await self.r.get(f"blobgen:{file_id}:{user_id}")
        return int(v) if v else 0

    async def revoke_blob_urls(self, file_id: str, user_id: str | None = None) -> None:
        if user_id:
            await self.r.incr(f"blobgen:{file_id}:{user_id}")
            await self.r.sadd("blobrev", f"{file_id}:{user_id}")
        else:
            async for k in self.r.scan_iter(match=f"blobgen:{file_id}:*", count=200):
                await self.r.incr(k)
            await self.r.incr(f"blobgen:{file_id}:*")
            await self.r.sadd("blobrev", f"{file_id}:*")

    async def file_generation(self, file_id: str) -> int:
        v = await self.r.get(f"blobgen:{file_id}:*")
        return int(v) if v else 0

    # baseline tokens
    async def put_bearer(self, token: str, user_id: str) -> None:
        await self.r.set(f"bearer:{token}", user_id, ex=settings.BASELINE_TOKEN_SECONDS)

    async def get_bearer(self, token: str) -> str | None:
        v = await self.r.get(f"bearer:{token}")
        return _s(v) if v else None


def _s(v) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


# ---- DPoP ------------------------------------------------------------------------
async def check_dpop(store: SessionStore, proof: str | None, method: str, htu_url: str, access_token: str | None, expected_jkt: str | None, now: int | None = None) -> dict:
    """Full DPoP chain: proof signature -> htm/htu -> iat window -> jti unseen -> ath -> cnf.jkt."""
    if not proof:
        raise AuthError("dpop_missing", "DPoP proof header missing")
    try:
        info = verify_dpop_proof(proof, method, htu_url, access_token=access_token, now=now, window=DPOP_WINDOW_SECONDS)
    except DPoPError as e:
        msg = str(e)
        code = "dpop_htu" if "htu" in msg else "dpop_htm" if "htm" in msg else "dpop_iat" if "iat" in msg else "dpop_ath" if "ath" in msg else "dpop_invalid"
        raise AuthError(code, msg) from e
    if not await store.jti_unseen(info["jti"]):
        raise AuthError("dpop_replay", "DPoP jti already used (replay)")
    if expected_jkt is not None and info["jkt"] != expected_jkt:
        raise AuthError("dpop_jkt", "DPoP key does not match token cnf.jkt")
    return info


# ---- risk scoring (CONTRACT §11) ---------------------------------------------------
RISK_NEW_DEVICE = 25
RISK_NEW_IP = 20
RISK_OFF_HOURS = 15
RISK_FAILED_LOGINS = 30
RISK_GEO_MISMATCH = 30


def risk_level(score: int) -> str:
    return "critical" if score >= 85 else "high" if score >= 60 else "medium" if score >= 30 else "low"


async def compute_risk(store: SessionStore, user_id: str, *, ip: str, jkt: str, geo: str | None, demo_risk: int = 0, hour_utc: int | None = None, remember: bool = True) -> tuple[int, list[str]]:
    signals: list[str] = []
    score = 0
    if not await store.seen_before(user_id, "dev", jkt):
        score += RISK_NEW_DEVICE
        signals.append("new_device")
    if not await store.seen_before(user_id, "ip", ip):
        score += RISK_NEW_IP
        signals.append("new_ip")
    hour = datetime.now(timezone.utc).hour if hour_utc is None else hour_utc
    if hour < 7 or hour >= 21:
        score += RISK_OFF_HOURS
        signals.append("outside_hours")
    if await store.failed_logins(user_id) >= 3:
        score += RISK_FAILED_LOGINS
        signals.append("failed_logins")
    last = await store.last_geo(user_id)
    if geo and last and geo != last:
        score += RISK_GEO_MISMATCH
        signals.append("geo_mismatch")
    if demo_risk:
        score += demo_risk
        signals.append(f"demo_risk:{demo_risk}")
    if remember:
        await store.remember(user_id, "dev", jkt)
        await store.remember(user_id, "ip", ip)
        if geo:
            await store.set_geo(user_id, geo)
    return min(score, 100), signals


# ---- 60-second HMAC blob URLs -------------------------------------------------------
def sign_blob_token(payload: dict, key: bytes | None = None) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    mac = hmac.new(key or keys().blob_hmac, body, hashlib.sha256).digest()
    return b64u(body) + "." + b64u(mac)


def verify_blob_token(token: str, key: bytes | None = None, now: int | None = None) -> dict | None:
    try:
        body_b, mac_b = token.split(".", 1)
        body = b64u_decode(body_b)
        if not hmac.compare_digest(hmac.new(key or keys().blob_hmac, body, hashlib.sha256).digest(), b64u_decode(mac_b)):
            return None
        payload = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    if int(payload.get("exp", 0)) < (now or int(time.time())):
        return None
    return payload


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)
