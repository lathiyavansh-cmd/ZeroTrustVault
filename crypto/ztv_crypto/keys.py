"""Level-1 user keys: X25519 (encryption) + Ed25519 (signing), sealed under KEK_user.

The sealed blob is the ONLY thing the server ever stores for a private key.
Blob format (JSON):
  {"v":1,"kdf":{"name":"argon2id","m":65536,"t":3,"p":1,"salt":b64u},
   "cipher":"AES-256-GCM","iv":b64u(12),"ct":b64u}
ct = AES-256-GCM(KEK, iv, canonical_json({"enc_sk":b64u(pkcs8),"sig_sk":b64u(pkcs8)}), aad="ZTV-keyblob-v1")
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import b64u, b64u_decode, canonical_json
from .kdf import CLIENT_ARGON2, Argon2Params, derive_kek, new_salt

KEYBLOB_AAD = b"ZTV-keyblob-v1"


def raw_pub(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pkcs8(key) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@dataclass
class UserKeyPair:
    enc_sk: x25519.X25519PrivateKey
    sig_sk: ed25519.Ed25519PrivateKey

    @property
    def enc_pk(self) -> bytes:
        return raw_pub(self.enc_sk)

    @property
    def sig_pk(self) -> bytes:
        return raw_pub(self.sig_sk)

    def public_record(self) -> dict:
        return {"enc_pk": b64u(self.enc_pk), "sig_pk": b64u(self.sig_pk)}


def generate_user_keys() -> UserKeyPair:
    return UserKeyPair(enc_sk=x25519.X25519PrivateKey.generate(), sig_sk=ed25519.Ed25519PrivateKey.generate())


def seal_private_keys(keys: UserKeyPair, passphrase: str, params: Argon2Params = CLIENT_ARGON2, salt: bytes | None = None) -> dict:
    salt = salt or new_salt()
    kek = derive_kek(passphrase, salt, params)
    iv = os.urandom(12)
    inner = canonical_json({"enc_sk": b64u(pkcs8(keys.enc_sk)), "sig_sk": b64u(pkcs8(keys.sig_sk))})
    ct = AESGCM(kek).encrypt(iv, inner, KEYBLOB_AAD)
    return {"v": 1, "kdf": {"name": "argon2id", "m": params.memory_kib, "t": params.time_cost, "p": params.parallelism, "salt": b64u(salt)}, "cipher": "AES-256-GCM", "iv": b64u(iv), "ct": b64u(ct)}


def open_private_keys(blob: dict, passphrase: str) -> UserKeyPair:
    kdf = blob["kdf"]
    params = Argon2Params(memory_kib=kdf["m"], time_cost=kdf["t"], parallelism=kdf["p"])
    kek = derive_kek(passphrase, b64u_decode(kdf["salt"]), params)
    inner = json.loads(AESGCM(kek).decrypt(b64u_decode(blob["iv"]), b64u_decode(blob["ct"]), KEYBLOB_AAD))
    enc_sk = serialization.load_der_private_key(b64u_decode(inner["enc_sk"]), password=None)
    sig_sk = serialization.load_der_private_key(b64u_decode(inner["sig_sk"]), password=None)
    if not isinstance(enc_sk, x25519.X25519PrivateKey) or not isinstance(sig_sk, ed25519.Ed25519PrivateKey):
        raise ValueError("unexpected key types in blob")
    return UserKeyPair(enc_sk=enc_sk, sig_sk=sig_sk)


def reseal_private_keys(blob: dict, old_passphrase: str, new_passphrase: str) -> dict:
    """Passphrase change: only the small blob is re-encrypted, no file re-encryption needed."""
    return seal_private_keys(open_private_keys(blob, old_passphrase), new_passphrase)
