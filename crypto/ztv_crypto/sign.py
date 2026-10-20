"""Ed25519 signatures over canonical-JSON manifests and share grants (RSA-PSS baseline optional)."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from .encoding import b64u, b64u_decode, canonical_json

MANIFEST_DOMAIN = b"ZTV-manifest-v1\x00"
GRANT_DOMAIN = b"ZTV-grant-v1\x00"
MANIFEST_FIELDS = ("file_id", "version", "name", "size", "classification", "merkle_root", "chunk_count", "chunk_size", "cipher", "nonce_prefix", "owner_id", "timestamp")
GRANT_FIELDS = ("grant_id", "file_id", "owner_id", "recipient_id", "rights", "expires_at", "max_downloads", "required_posture", "issued_at")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ed25519_sign(sk: ed25519.Ed25519PrivateKey, domain: bytes, obj: dict) -> str:
    return b64u(sk.sign(domain + canonical_json(obj)))


def ed25519_verify(pk_raw: bytes, domain: bytes, obj: dict, signature_b64u: str) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk_raw).verify(b64u_decode(signature_b64u), domain + canonical_json(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def build_manifest(*, file_id: str, version: int, name: str, size: int, classification: str, merkle_root: bytes, chunk_count: int, chunk_size: int, cipher: str, nonce_prefix: bytes, owner_id: str, timestamp: str | None = None) -> dict:
    return {
        "file_id": file_id,
        "version": version,
        "name": name,
        "size": size,
        "classification": classification,
        "merkle_root": b64u(merkle_root),
        "chunk_count": chunk_count,
        "chunk_size": chunk_size,
        "cipher": cipher,
        "nonce_prefix": b64u(nonce_prefix),
        "owner_id": owner_id,
        "timestamp": timestamp or now_iso(),
    }


def _strip(obj: dict, fields: tuple[str, ...]) -> dict:
    missing = [f for f in fields if f not in obj]
    if missing:
        raise ValueError(f"missing fields: {missing}")
    return {f: obj[f] for f in fields}


def sign_manifest(manifest: dict, owner_sk: ed25519.Ed25519PrivateKey) -> dict:
    body = _strip(manifest, MANIFEST_FIELDS)
    return {**body, "signature": ed25519_sign(owner_sk, MANIFEST_DOMAIN, body)}


def verify_manifest(signed_manifest: dict, owner_pk_raw: bytes) -> bool:
    try:
        body = _strip(signed_manifest, MANIFEST_FIELDS)
        return ed25519_verify(owner_pk_raw, MANIFEST_DOMAIN, body, signed_manifest["signature"])
    except (KeyError, ValueError, TypeError):
        return False


def sign_grant(grant: dict, owner_sk: ed25519.Ed25519PrivateKey) -> dict:
    body = _strip(grant, GRANT_FIELDS)
    return {**body, "signature": ed25519_sign(owner_sk, GRANT_DOMAIN, body)}


def verify_grant(signed_grant: dict, owner_pk_raw: bytes) -> bool:
    try:
        body = _strip(signed_grant, GRANT_FIELDS)
        return ed25519_verify(owner_pk_raw, GRANT_DOMAIN, body, signed_grant["signature"])
    except (KeyError, ValueError, TypeError):
        return False


# ---- RSA-PSS comparison baseline ---------------------------------------------
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def rsa_pss_sign(sk: rsa.RSAPrivateKey, domain: bytes, obj: dict) -> str:
    return b64u(sk.sign(domain + canonical_json(obj), _PSS, hashes.SHA256()))


def rsa_pss_verify(pk: rsa.RSAPublicKey, domain: bytes, obj: dict, sig: str) -> bool:
    try:
        pk.verify(b64u_decode(sig), domain + canonical_json(obj), _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
