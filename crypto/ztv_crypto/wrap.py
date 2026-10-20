"""Level-2 per-file DEK wrapping.

Primary:  ECDH(X25519 ephemeral, recipient static) -> HKDF-SHA256 -> AES-KW (RFC 3394)
Baseline: RSA-OAEP-3072 / SHA-256 (measured comparison only, selected by flag)
"""
from __future__ import annotations

import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from .encoding import b64u, b64u_decode

ALG_X25519 = "X25519-HKDF-SHA256-A256KW"
ALG_RSA = "RSA-OAEP-3072-SHA256"
HKDF_INFO_DOMAIN = b"ZTV-DEK-wrap-v1"


def hkdf_info(file_id: str, version: int) -> bytes:
    return HKDF_INFO_DOMAIN + uuid.UUID(file_id).bytes + version.to_bytes(4, "big")


def _kek_from_shared(shared: bytes, file_id: str, version: int) -> bytes:
    # salt=None -> HashLen zero bytes (RFC 5869), identical to Web Crypto HKDF with an empty salt
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=hkdf_info(file_id, version)).derive(shared)


def wrap_dek(dek: bytes, recipient_pk_raw: bytes, file_id: str, version: int) -> dict:
    """Returns {"alg","epk","wrapped"}; the ephemeral secret is discarded immediately."""
    if len(dek) != 32:
        raise ValueError("DEK must be 32 bytes")
    recipient = x25519.X25519PublicKey.from_public_bytes(recipient_pk_raw)
    esk = x25519.X25519PrivateKey.generate()
    kek = _kek_from_shared(esk.exchange(recipient), file_id, version)
    epk = esk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"alg": ALG_X25519, "epk": b64u(epk), "wrapped": b64u(aes_key_wrap(kek, dek))}


def unwrap_dek(record: dict, recipient_sk: x25519.X25519PrivateKey, file_id: str, version: int) -> bytes:
    if record.get("alg") != ALG_X25519:
        raise ValueError(f"unexpected wrap alg {record.get('alg')}")
    epk = x25519.X25519PublicKey.from_public_bytes(b64u_decode(record["epk"]))
    kek = _kek_from_shared(recipient_sk.exchange(epk), file_id, version)
    return aes_key_unwrap(kek, b64u_decode(record["wrapped"]))  # raises InvalidUnwrap on tamper


# ---- RSA comparison baseline -------------------------------------------------
def generate_rsa_keypair(bits: int = 3072) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def wrap_dek_rsa(dek: bytes, recipient_pk: rsa.RSAPublicKey) -> dict:
    return {"alg": ALG_RSA, "wrapped": b64u(recipient_pk.encrypt(dek, _OAEP))}


def unwrap_dek_rsa(record: dict, recipient_sk: rsa.RSAPrivateKey) -> bytes:
    if record.get("alg") != ALG_RSA:
        raise ValueError("unexpected wrap alg")
    return recipient_sk.decrypt(b64u_decode(record["wrapped"]), _OAEP)
