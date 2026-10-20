"""DPoP proof-of-possession (RFC 9449) with ES256 device keys.

Every request carries a proof JWT signed by the device key:
  header: {"typ":"dpop+jwt","alg":"ES256","jwk":{...public key...}}
  claims: {"jti": unique, "htm": METHOD, "htu": scheme://host/path, "iat": unix,
           "ath": b64u(SHA-256(access_token))  (when a token is presented)}
The access token is bound to the key via cnf.jkt = RFC 7638 thumbprint.
The server additionally rejects any `jti` seen in the last 2 minutes (Redis) and
any `iat` outside +/- 60 s.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .encoding import b64u

DPOP_WINDOW_SECONDS = 60
JTI_CACHE_SECONDS = 120


class DPoPError(Exception):
    pass


def htu_from_url(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", ""))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint for an EC key."""
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    return b64u(hashlib.sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()).digest())


@dataclass
class DeviceKey:
    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "DeviceKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes) -> "DeviceKey":
        k = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(k, ec.EllipticCurvePrivateKey):
            raise ValueError("device key must be EC P-256")
        return cls(k)

    def to_pem(self) -> bytes:
        return self.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def public_jwk(self) -> dict:
        nums = self.private_key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk())


def access_token_hash(token: str) -> str:
    return b64u(hashlib.sha256(token.encode("ascii")).digest())


def make_dpop_proof(key: DeviceKey, method: str, url: str, access_token: str | None = None, iat: int | None = None, jti: str | None = None) -> str:
    claims = {"jti": jti or b64u(os.urandom(16)), "htm": method.upper(), "htu": htu_from_url(url), "iat": iat if iat is not None else int(time.time())}
    if access_token:
        claims["ath"] = access_token_hash(access_token)
    return jwt.encode(claims, key.private_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": key.public_jwk()})


def verify_dpop_proof(proof: str, method: str, url: str, access_token: str | None = None, now: int | None = None, window: int = DPOP_WINDOW_SECONDS) -> dict:
    """Verifies signature + binding; returns {"jti","jkt","iat","jwk"}.  Replay (jti reuse) is checked by the caller against Redis."""
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as e:
        raise DPoPError(f"malformed proof: {e}") from e
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
        raise DPoPError("unsupported DPoP header")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise DPoPError("invalid DPoP jwk")
    try:
        pub = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(proof, pub, algorithms=["ES256"], options={"verify_exp": False, "verify_iat": False, "require": ["jti", "htm", "htu", "iat"]})
    except jwt.PyJWTError as e:
        raise DPoPError(f"invalid DPoP signature: {e}") from e
    if claims["htm"] != method.upper():
        raise DPoPError("DPoP htm mismatch")
    if claims["htu"] != htu_from_url(url):
        raise DPoPError("DPoP htu mismatch")
    now = now if now is not None else int(time.time())
    if abs(int(claims["iat"]) - now) > window:
        raise DPoPError("DPoP iat outside allowed window")
    if access_token is not None and claims.get("ath") != access_token_hash(access_token):
        raise DPoPError("DPoP ath does not match access token")
    return {"jti": claims["jti"], "jkt": jwk_thumbprint(jwk), "iat": int(claims["iat"]), "jwk": jwk}
