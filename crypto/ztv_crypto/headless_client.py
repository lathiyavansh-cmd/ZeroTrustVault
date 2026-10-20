"""Headless Python client implementing all six ZeroTrustVault workflows client-side (CONTRACT v1).

Used by the seed script, the attack lab and the evaluation harness.  Everything the browser client
does with Web Crypto is done here with the shared `ztv_crypto` core: key generation + Argon2id sealing,
chunked AEAD, Merkle root, Ed25519 manifests/grants, X25519 DEK wrapping, ES256 DPoP proofs.
"""
from __future__ import annotations

import hashlib
import os
import ssl
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pyotp

from .ca import verify_user_cert
from .chunks import CHUNK_SIZE, ChunkCipher, split_chunks
from .dpop import DeviceKey, htu_from_url, make_dpop_proof
from .encoding import b64u, b64u_decode
from .keys import UserKeyPair, generate_user_keys, open_private_keys, seal_private_keys
from .merkle import merkle_root
from .sign import build_manifest, now_iso, sign_grant, sign_manifest, verify_manifest
from .wrap import unwrap_dek, wrap_dek


def make_ssl_context(verify=False, client_cert=None, insecure: bool = False) -> ssl.SSLContext:
    """SSL context for httpx (works with httpx 0.2x and 1.x): CA bundle path / True / False, optional mTLS client cert."""
    if isinstance(verify, ssl.SSLContext):
        ctx = verify
    elif verify and not insecure:
        ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert:
        crt, key = client_cert if isinstance(client_cert, (tuple, list)) else (client_cert, None)
        ctx.load_cert_chain(crt, key)
    return ctx


class IntegrityError(Exception):
    """Any tag / Merkle / chunk-count / manifest-signature failure on download."""


class AccessDenied(Exception):
    """403 from the policy enforcement point."""


class StepUpRequired(Exception):
    """401 step_up_required: fresh MFA needed for this risk level."""


class CertError(Exception):
    """A certificate did not verify against the pinned org root."""


class ZTVClient:
    def __init__(self, base_url: str, *, verify=False, client_cert=None, pin_spki_b64: str | None = None, device_key: DeviceKey | None = None, device_name: str = "headless", posture: str = "registered", org_root_pk_b64u: str | None = None, extra_headers: dict | None = None, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.pin_spki_b64 = pin_spki_b64
        self.device_key = device_key or DeviceKey.generate()
        self.device_name = device_name
        self.posture = posture
        self.org_root_pk = b64u_decode(org_root_pk_b64u) if org_root_pk_b64u else None
        self.extra_headers = dict(extra_headers or {})
        self.user: dict | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.keys: UserKeyPair | None = None
        self._mode: str | None = None
        self._totp_secret: str | None = None
        self._cert_cache: dict[str, dict] = {}
        if pin_spki_b64:
            self._check_pin()
        self.http = httpx.Client(base_url=self.base_url, verify=make_ssl_context(verify, client_cert, insecure=bool(pin_spki_b64)), timeout=timeout, headers=self.extra_headers)

    # ---- TLS pinning -------------------------------------------------------------------------
    def _check_pin(self) -> None:
        from urllib.parse import urlsplit

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        u = urlsplit(self.base_url)
        host, port = u.hostname, u.port or 443
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        import socket

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        import base64

        pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
        if pin != self.pin_spki_b64:
            raise ssl.SSLError(f"SPKI pin mismatch: server presented {pin}, expected {self.pin_spki_b64}")

    # ---- mode / transport ----------------------------------------------------------------------
    @property
    def mode(self) -> str:
        if self._mode is None:
            self._mode = self.http.get("/api/mode").json()["mode"]
        return self._mode

    def refresh_mode(self) -> str:
        self._mode = None
        return self.mode

    def request(self, method: str, path: str, *, dpop: bool = True, token: bool = True, **kw) -> httpx.Response:
        headers = dict(kw.pop("headers", {}) or {})
        url = path if path.startswith("http") else self.base_url + path
        if self.access_token and token:
            if self.mode == "baseline":
                headers["Authorization"] = f"Bearer {self.access_token}"
            else:
                headers["Authorization"] = f"DPoP {self.access_token}"
        if self.mode != "baseline" and dpop:
            headers["DPoP"] = make_dpop_proof(self.device_key, method, url, self.access_token if token else None)
        r = self.http.request(method, url, headers=headers, **kw)
        if r.status_code == 403:
            raise AccessDenied(f"{method} {path}: forbidden")
        if r.status_code == 401:
            try:
                code = r.json().get("code")
            except Exception:  # noqa: BLE001
                code = None
            if code == "step_up_required":
                raise StepUpRequired(path)
        return r

    def _json(self, method: str, path: str, **kw) -> dict:
        r = self.request(method, path, **kw)
        if r.status_code >= 400:
            raise httpx.HTTPStatusError(f"{method} {path} -> {r.status_code}: {r.text[:300]}", request=r.request, response=r)
        return r.json() if r.content else {}

    # ---- A. login ----------------------------------------------------------------------------
    def login(self, username: str, password: str, totp_secret: str | None = None) -> dict:
        self._totp_secret = totp_secret
        body = {"username": username, "password": password, "device": {"jwk": self.device_key.public_jwk(), "name": self.device_name, "posture": self.posture}}
        r = self.request("POST", "/api/auth/login", json=body, token=False, dpop=False)
        if r.status_code >= 400:
            raise httpx.HTTPStatusError(f"login -> {r.status_code}: {r.text[:300]}", request=r.request, response=r)
        data = r.json()
        if data.get("status") == "ok":
            self._finish(data)
            return data
        if data.get("status") != "mfa_required":
            raise RuntimeError(f"unexpected login response {data}")
        self.login_ticket = data["login_ticket"]
        if totp_secret is None:
            return data
        code = pyotp.TOTP(totp_secret).now()
        data = self._json("POST", "/api/auth/mfa/totp", json={"login_ticket": self.login_ticket, "code": code}, token=False, dpop=False)
        self._finish(data)
        return data

    def _finish(self, data: dict) -> None:
        self.access_token = data["access_token"]
        self.refresh_token = data.get("refresh_token")
        self.user = data["user"]
        self.device_id = data.get("device_id")

    def refresh(self) -> dict:
        data = self._json("POST", "/api/auth/refresh", json={"refresh_token": self.refresh_token}, token=False)
        self.access_token = data["access_token"]
        return data

    def step_up(self, totp_secret: str | None = None) -> None:
        secret = totp_secret or self._totp_secret
        self._json("POST", "/api/auth/step-up", json={"code": pyotp.TOTP(secret).now()})

    def logout(self) -> None:
        self.request("POST", "/api/auth/logout")
        self.access_token = None

    def me(self) -> dict:
        return self._json("GET", "/api/auth/me")

    # ---- B. keys + certificate enrolment ------------------------------------------------------
    def enroll_keys(self, passphrase: str) -> dict:
        self.keys = generate_user_keys()
        blob = seal_private_keys(self.keys, passphrase)
        r = self.request("PUT", "/api/keys/blob", json={"blob": blob})
        r.raise_for_status()
        return self._json("POST", "/api/keys/cert-request", json=self.keys.public_record())

    def load_keys(self, passphrase: str) -> None:
        blob = self._json("GET", "/api/keys/blob")
        self.keys = open_private_keys(blob, passphrase)

    def cert_request_status(self, request_id: str) -> dict:
        return self._json("GET", f"/api/keys/cert-request/{request_id}")

    def wait_for_cert(self, timeout: float = 60, request_id: str | None = None) -> dict:
        rid = request_id or getattr(self, "_last_request_id", None)
        deadline = time.time() + timeout
        while True:
            if rid:
                s = self.cert_request_status(rid)
                if s.get("status") == "issued" and s.get("cert"):
                    self._verify_cert(s["cert"], self.user["id"])
                    return s["cert"]
            else:
                r = self.request("GET", f"/api/keys/directory/{self.user['id']}")
                if r.status_code == 200:
                    cert = r.json()["cert"]
                    self._verify_cert(cert, self.user["id"])
                    return cert
            if time.time() > deadline:
                raise TimeoutError("certificate not issued in time")
            time.sleep(1.0)

    def _verify_cert(self, cert: dict, user_id: str) -> None:
        if self.org_root_pk is None:
            self.org_root_pk = b64u_decode(self.http.get("/api/keys/org-root").json()["pk"])  # unpinned fallback (dev)
        if not verify_user_cert(cert, self.org_root_pk, expected_user_id=user_id):
            raise CertError(f"certificate for {user_id} does not verify against the pinned org root")

    def get_cert(self, user_id: str) -> dict:
        if user_id not in self._cert_cache:
            cert = self._json("GET", f"/api/keys/directory/{user_id}")["cert"]
            self._verify_cert(cert, user_id)
            self._cert_cache[user_id] = cert
        return self._cert_cache[user_id]

    def directory(self, q: str = "") -> list[dict]:
        return self._json("GET", "/api/keys/directory", params={"q": q} if q else None)

    def user_id_of(self, username: str) -> str:
        for u in self.directory(username):
            if u["username"] == username:
                return u["user_id"]
        raise KeyError(username)

    # ---- C. upload -------------------------------------------------------------------------------
    def upload(self, name: str, data: bytes, classification: str = "INTERNAL", cipher: str = "AES-256-GCM") -> str:
        if self.mode == "baseline":
            r = self.request("POST", "/api/files/upload", files={"file": (name, data)}, data={"name": name, "classification": classification})
            r.raise_for_status()
            return r.json()["file_id"]
        assert self.keys is not None, "load_keys/enroll_keys first"
        plain_chunks = split_chunks(data)
        init = self._json("POST", "/api/files", json={"name": name, "classification": classification, "size": len(data), "chunk_count": len(plain_chunks), "cipher": cipher})
        file_id, version = init["file_id"], init["version"]
        self._upload_version(file_id, version, name, data, classification, cipher, extra_recipients={})
        return file_id

    def _upload_version(self, file_id: str, version: int, name: str, data: bytes, classification: str, cipher: str, extra_recipients: dict[str, dict]) -> None:
        plain_chunks = split_chunks(data)
        cc = ChunkCipher.new(file_id, version, cipher)
        cts = list(cc.encrypt_stream(plain_chunks))
        for i, ct in enumerate(cts):
            r = self.request("PUT", f"/api/files/{file_id}/versions/{version}/chunks/{i}", content=ct, headers={"Content-Type": "application/octet-stream"})
            r.raise_for_status()
        manifest = sign_manifest(build_manifest(file_id=file_id, version=version, name=name, size=len(data), classification=classification, merkle_root=merkle_root(cts), chunk_count=len(cts), chunk_size=CHUNK_SIZE, cipher=cipher, nonce_prefix=cc.nonce_prefix, owner_id=self.user["id"]), self.keys.sig_sk)
        wrapped = {self.user["id"]: wrap_dek(cc.dek, self.keys.enc_pk, file_id, version)}
        for uid, cert in extra_recipients.items():
            wrapped[uid] = wrap_dek(cc.dek, b64u_decode(cert["enc_pk"]), file_id, version)
        body = {"manifest": manifest, "wrapped_dek": wrapped[self.user["id"]], "wrapped_deks": wrapped}
        self._json("POST", f"/api/files/{file_id}/versions/{version}/finalize", json=body)

    # ---- D. share ------------------------------------------------------------------------------
    def share(self, file_id: str, recipient_username: str, rights=("view", "download"), expires_in_days: int = 7, max_downloads: int = 10, posture: str = "any") -> str:
        assert self.keys is not None
        rid = self.user_id_of(recipient_username)
        cert = self.get_cert(rid)  # verified against the pinned org root
        acc = self.access(file_id, intent="view")
        dek = unwrap_dek(acc["wrapped_dek"], self.keys.enc_sk, file_id, acc["version"])
        grant = {"grant_id": str(uuid.uuid4()), "file_id": file_id, "owner_id": self.user["id"], "recipient_id": rid, "rights": list(rights), "expires_at": _iso(datetime.now(timezone.utc) + timedelta(days=expires_in_days)), "max_downloads": int(max_downloads), "required_posture": posture, "issued_at": now_iso()}
        signed = sign_grant(grant, self.keys.sig_sk)
        wd = wrap_dek(dek, b64u_decode(cert["enc_pk"]), file_id, acc["version"])
        return self._json("POST", "/api/shares", json={"grant": signed, "wrapped_dek": wd})["grant_id"]

    def revoke_share(self, grant_id: str) -> None:
        r = self.request("DELETE", f"/api/shares/{grant_id}")
        r.raise_for_status()

    def list_shares(self, file_id: str | None = None) -> list[dict]:
        return self._json("GET", "/api/shares", params={"file_id": file_id} if file_id else None)

    def list_files(self) -> list[dict]:
        return self._json("GET", "/api/files")

    # ---- E. access + download ---------------------------------------------------------------------
    def access(self, file_id: str, intent: str = "view") -> dict:
        return self._json("POST", f"/api/files/{file_id}/access", json={"intent": intent})

    def download(self, file_id: str, intent: str = "download", chunk_urls: list[str] | None = None, access: dict | None = None) -> bytes:
        if self.mode == "baseline":
            r = self.request("GET", f"/api/files/{file_id}/download")
            r.raise_for_status()
            return r.content
        assert self.keys is not None
        acc = access or self.access(file_id, intent=intent)
        manifest, version = acc["manifest"], acc["version"]
        owner_cert = self.get_cert(manifest["owner_id"])
        if not verify_manifest(manifest, b64u_decode(owner_cert["sig_pk"])):
            self._report(file_id, version, None, "manifest signature invalid")
            raise IntegrityError("manifest signature invalid")
        if manifest["file_id"] != file_id or manifest["version"] != version:
            self._report(file_id, version, None, "manifest binding mismatch")
            raise IntegrityError("manifest does not match requested file/version")
        urls = chunk_urls or acc["chunk_urls"]
        if len(urls) != manifest["chunk_count"]:
            self._report(file_id, version, None, f"chunk count {len(urls)} != {manifest['chunk_count']}")
            raise IntegrityError("chunk count mismatch")
        cts: list[bytes] = []
        for i, u in enumerate(urls):
            r = self.http.get(u)
            if r.status_code != 200:
                self._report(file_id, version, i, f"chunk fetch failed {r.status_code}")
                raise IntegrityError(f"chunk {i} fetch failed: {r.status_code}")
            cts.append(r.content)
        if merkle_root(cts) != b64u_decode(manifest["merkle_root"]):
            self._report(file_id, version, None, "merkle root mismatch")
            raise IntegrityError("Merkle root mismatch")
        dek = unwrap_dek(acc["wrapped_dek"], self.keys.enc_sk, file_id, version)
        cc = ChunkCipher(dek=dek, nonce_prefix=b64u_decode(manifest["nonce_prefix"]), file_id=file_id, version=version, cipher=manifest["cipher"])
        out = bytearray()
        n = len(cts)
        for i, ct in enumerate(cts):
            try:
                out += cc.decrypt_chunk(i, ct, final=(i == n - 1))
            except Exception as e:  # InvalidTag
                self._report(file_id, version, i, f"AEAD tag failure: {type(e).__name__}")
                raise IntegrityError(f"chunk {i} authentication failed") from e
        if len(out) != manifest["size"]:
            self._report(file_id, version, None, "size mismatch")
            raise IntegrityError("plaintext size mismatch")
        return bytes(out)

    def _report(self, file_id: str, version: int, chunk_index: int | None, reason: str) -> None:
        try:
            self.request("POST", f"/api/files/{file_id}/report-integrity", json={"version": version, "chunk_index": chunk_index, "reason": reason})
        except Exception:  # noqa: BLE001
            pass

    # ---- F. hard revocation / re-key ---------------------------------------------------------------
    def rotate_file(self, file_id: str, data: bytes) -> int:
        assert self.keys is not None
        meta = self._json("GET", f"/api/files/{file_id}")
        name, classification = meta["name"], meta["classification"]
        cipher = (meta.get("manifest") or {}).get("cipher", "AES-256-GCM")
        recipients = {}
        for g in self.list_shares(file_id):
            if not g.get("revoked"):
                recipients[g["recipient_id"]] = self.get_cert(g["recipient_id"])
        chunks = split_chunks(data)
        v = self._json("POST", f"/api/files/{file_id}/versions", json={"size": len(data), "chunk_count": len(chunks), "cipher": cipher})["version"]
        self._upload_version(file_id, v, name, data, classification, cipher, extra_recipients=recipients)
        return v

    # ---- admin helpers -------------------------------------------------------------------------------
    def admin_confirm_cert(self, request_id: str, fingerprint: str) -> dict:
        return self._json("POST", f"/api/admin/cert-requests/{request_id}/confirm", json={"fingerprint": fingerprint})

    def admin_create_user(self, **fields) -> dict:
        return self._json("POST", "/api/admin/users", json=fields)

    def audit_recent(self, limit: int = 50) -> list[dict]:
        return self._json("GET", "/api/audit/recent", params={"limit": limit})

    def audit_verify(self) -> dict:
        return self._json("GET", "/api/audit/verify")

    def close(self) -> None:
        self.http.close()


def _iso(d: datetime) -> str:
    return d.replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = ["ZTVClient", "IntegrityError", "AccessDenied", "StepUpRequired", "CertError", "DeviceKey", "htu_from_url", "b64u", "os"]
