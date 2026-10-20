"""Level-0 Organization Root (Ed25519, OFFLINE).

The root key file is only ever loaded by the `ztv-ca` CLI / signer daemon,
never by the running API server.  User certificates are canonical JSON signed
with domain separation; the client verifies them against a pinned root public key.

cert = {"serial","user_id","username","enc_pk","sig_pk","iat","exp","issuer"} + "signature"
fingerprint = SHA-256(enc_pk_raw || sig_pk_raw), shown as 8 groups of 4 hex chars for out-of-band confirmation
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .encoding import b64u, b64u_decode
from .sign import ed25519_sign, ed25519_verify, now_iso

CERT_DOMAIN = b"ZTV-user-cert-v1\x00"
ROOT_CRYPTOPERIOD_DAYS = 2 * 365  # NIST SP 800-57: 2 years for the org root
USER_CERT_DAYS = 365  # user key pairs rotate yearly
CERT_FIELDS = ("serial", "user_id", "username", "enc_pk", "sig_pk", "iat", "exp", "issuer")
ISSUER = "ztv-org-root"


def generate_org_root() -> dict:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "kty": "Ed25519",
        "sk": b64u(sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        "pk": b64u(pk),
        "created": created.isoformat().replace("+00:00", "Z"),
        "expires": (created + timedelta(days=ROOT_CRYPTOPERIOD_DAYS)).isoformat().replace("+00:00", "Z"),
    }


def save_org_root(root: dict, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(root, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def load_org_root(path: str | Path) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    root = json.loads(Path(path).read_text())
    sk = serialization.load_der_private_key(b64u_decode(root["sk"]), password=None)
    if not isinstance(sk, ed25519.Ed25519PrivateKey):
        raise ValueError("root key is not Ed25519")
    return sk, b64u_decode(root["pk"])


def cert_fingerprint(enc_pk_raw: bytes, sig_pk_raw: bytes) -> str:
    h = hashlib.sha256(enc_pk_raw + sig_pk_raw).hexdigest().upper()
    return " ".join(h[i : i + 4] for i in range(0, 32, 4))  # first 128 bits, 8 groups of 4


def issue_user_cert(root_sk: ed25519.Ed25519PrivateKey, *, user_id: str, username: str, enc_pk_raw: bytes, sig_pk_raw: bytes, days: int = USER_CERT_DAYS, serial: str | None = None) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {
        "serial": serial or b64u(os.urandom(12)),
        "user_id": user_id,
        "username": username,
        "enc_pk": b64u(enc_pk_raw),
        "sig_pk": b64u(sig_pk_raw),
        "iat": now.isoformat().replace("+00:00", "Z"),
        "exp": (now + timedelta(days=days)).isoformat().replace("+00:00", "Z"),
        "issuer": ISSUER,
    }
    return {**body, "signature": ed25519_sign(root_sk, CERT_DOMAIN, body)}


def verify_user_cert(cert: dict, root_pk_raw: bytes, *, now: datetime | None = None, expected_user_id: str | None = None) -> bool:
    try:
        body = {f: cert[f] for f in CERT_FIELDS}
    except (KeyError, TypeError):
        return False
    if body["issuer"] != ISSUER:
        return False
    if expected_user_id is not None and body["user_id"] != expected_user_id:
        return False
    if not ed25519_verify(root_pk_raw, CERT_DOMAIN, body, cert.get("signature", "")):
        return False
    now = now or datetime.now(timezone.utc)
    exp = datetime.fromisoformat(body["exp"].replace("Z", "+00:00"))
    iat = datetime.fromisoformat(body["iat"].replace("Z", "+00:00"))
    return iat - timedelta(minutes=5) <= now <= exp


__all__ = ["generate_org_root", "save_org_root", "load_org_root", "cert_fingerprint", "issue_user_cert", "verify_user_cert", "CERT_DOMAIN", "now_iso"]
