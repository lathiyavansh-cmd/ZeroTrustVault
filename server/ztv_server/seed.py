"""Idempotent seed (CONTRACT §13).

1. users + policy straight into the DB (Argon2id hashes, TOTP secrets -> seed/generated/credentials.json)
2. through the API with the headless client (exactly what a browser would do): key enrolment, out-of-band
   fingerprint confirmation by the admin, certificate issuance by the offline ca-signer (fallback: sign with
   /offline/org_root.json locally — allowed in seed only), sample uploads and the alice -> bob share.
3. seed/generated/state.json with file ids and grant ids.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pyotp
from sqlalchemy import select

from ztv_crypto.ca import issue_user_cert, load_org_root
from ztv_crypto.encoding import b64u_decode
from ztv_crypto.headless_client import ZTVClient
from ztv_crypto.kdf import hash_password

from .config import settings
from .db import SessionLocal, init_db
from .models import Policy, User, new_id

OFFLINE_ROOT = Path(os.environ.get("OFFLINE_ORG_ROOT", "/offline/org_root.json"))


def log(msg: str) -> None:
    print(f"[seed] {msg}", flush=True)


def make_content(name: str, size: int, marker: str) -> bytes:
    """Deterministic plaintext of `size` bytes that contains the marker (and is not trivially compressible)."""
    header = f"{name}\n{marker}\nAcme Research Labs — sample document\n".encode()
    body = bytearray(header)
    seed = hashlib.sha256(name.encode()).digest()
    i = 0
    while len(body) < size:
        seed = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        body += seed.hex().encode()[:48] + b"\n"
        i += 1
        if i % 4000 == 0:
            body += marker.encode() + b"\n"
    body = body[:size]
    tail = f"\n{marker}\n".encode()
    body[-len(tail):] = tail
    return bytes(body)


async def seed_db(cfg: dict, creds_path: Path) -> dict:
    await init_db()
    existing = json.loads(creds_path.read_text()) if creds_path.exists() else {}
    creds: dict = {}
    async with SessionLocal() as db:
        for u in cfg["users"]:
            row = (await db.execute(select(User).where(User.username == u["username"]))).scalar_one_or_none()
            secret = (existing.get(u["username"]) or {}).get("totp_secret") or (row.totp_secret if row else None) or pyotp.random_base32()
            emp = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=u["employment_end_days"]) if u.get("employment_end_days") else None
            if row is None:
                row = User(id=new_id(), username=u["username"], password_hash=hash_password(u["password"]), role=u["role"], department=u["department"], clearance=u["clearance"], employment_end=emp, totp_secret=secret, totp_confirmed=True)
                db.add(row)
                log(f"created user {u['username']} ({u['role']}/{u['department']}/clearance {u['clearance']})")
            else:
                row.role, row.department, row.clearance, row.employment_end = u["role"], u["department"], u["clearance"], emp
                row.totp_secret, row.totp_confirmed = secret, True
                if not row.password_hash:
                    row.password_hash = hash_password(u["password"])
            creds[u["username"]] = {"username": u["username"], "password": u["password"], "totp_secret": secret, "key_passphrase": u["password"], "role": u["role"], "department": u["department"], "clearance": u["clearance"]}
        pol_path = Path(settings.SEED_FILE).parent / "policy.json"
        if pol_path.exists():
            doc = json.loads(pol_path.read_text())
            prow = await db.get(Policy, 1)
            if prow is None:
                db.add(Policy(id=1, document=doc))
            else:
                prow.document = doc
            log(f"policy loaded ({len(doc.get('rules', []))} rules)")
        await db.commit()
        for name, c in creds.items():
            c["user_id"] = (await db.execute(select(User.id).where(User.username == name))).scalar_one()
    creds_path.parent.mkdir(parents=True, exist_ok=True)
    creds_path.write_text(json.dumps(creds, indent=2))
    log(f"credentials written to {creds_path}")
    return creds


def api_client(device_name: str = "seed") -> ZTVClient:
    certs = Path(settings.TLS_DIR)
    client_cert = (str(certs / "nginx-client.crt"), str(certs / "nginx-client.key")) if (certs / "nginx-client.crt").exists() else None
    verify = str(certs / "internal-ca.crt") if (certs / "internal-ca.crt").exists() else False
    root_pk = json.loads(Path(settings.ORG_ROOT_PUB_FILE).read_text())["pk"]
    return ZTVClient(settings.SEED_API_URL, verify=verify, client_cert=client_cert, org_root_pk_b64u=root_pk, device_name=device_name, posture="trusted")


def wait_for_api(timeout: float = 120) -> None:
    c = api_client()
    deadline = time.time() + timeout
    while True:
        try:
            r = c.http.get("/api/health")
            if r.status_code == 200:
                log(f"api healthy: {r.json()}")
                return
        except Exception as e:  # noqa: BLE001
            err = e
        if time.time() > deadline:
            raise RuntimeError(f"api not reachable: {err}")
        time.sleep(2)


def ensure_cert(admin: ZTVClient, c: ZTVClient, cred: dict) -> dict:
    uid = c.user["id"]
    r = c.request("GET", f"/api/keys/directory/{uid}")
    if r.status_code == 200:
        c.load_keys(cred["key_passphrase"])
        log(f"{cred['username']}: certificate already issued, keys loaded")
        return r.json()["cert"]
    req = c.enroll_keys(cred["key_passphrase"])
    log(f"{cred['username']}: keys enrolled, cert request {req['request_id']} fingerprint {req['fingerprint']}")
    admin.admin_confirm_cert(req["request_id"], req["fingerprint"])  # simulated out-of-band confirmation
    try:
        cert = c.wait_for_cert(timeout=20, request_id=req["request_id"])
        log(f"{cred['username']}: certificate issued by ca-signer daemon (serial {cert['serial']})")
        return cert
    except TimeoutError:
        if not OFFLINE_ROOT.exists():
            raise
        log(f"{cred['username']}: ca-signer not reachable, signing with the offline org root (seed fallback)")
        root_sk, _ = load_org_root(OFFLINE_ROOT)
        cert = issue_user_cert(root_sk, user_id=uid, username=cred["username"], enc_pk_raw=c.keys.enc_pk, sig_pk_raw=c.keys.sig_pk)
        r = admin.http.post(f"/api/admin/cert-requests/{req['request_id']}/publish", json={"cert": cert}, headers={"X-Admin-Key": settings.ADMIN_API_KEY})
        r.raise_for_status()
        return c.wait_for_cert(timeout=10, request_id=req["request_id"])


def seed_api(cfg: dict, creds: dict, state_path: Path) -> dict:
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    state.setdefault("files", {})
    state.setdefault("grants", {})
    admin = api_client("seed-admin")
    admin.login("admin", creds["admin"]["password"], creds["admin"]["totp_secret"])
    mode = admin.mode
    log(f"server mode: {mode}")
    clients: dict[str, ZTVClient] = {}
    for name in cfg["key_users"]:
        c = api_client(f"seed-{name}")
        c.login(name, creds[name]["password"], creds[name]["totp_secret"])
        clients[name] = c
        if mode != "baseline":
            ensure_cert(admin, c, creds[name])
    users_by_name = {name: c.user["id"] for name, c in clients.items()}
    for f in cfg["files"]:
        owner = clients[f["owner"]]
        key = f["key"]
        existing = state["files"].get(key)
        if existing and existing.get("mode") == mode and any(x["file_id"] == existing["file_id"] for x in owner.list_files()):
            log(f"{f['name']}: already present ({existing['file_id']})")
            fid = existing["file_id"]
        else:
            data = make_content(f["name"], f["size"], cfg["marker"])
            fid = owner.upload(f["name"], data, classification=f["classification"])
            state["files"][key] = {"file_id": fid, "name": f["name"], "owner": f["owner"], "owner_id": owner.user["id"], "classification": f["classification"], "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": mode}
            log(f"{f['name']}: uploaded as {fid} ({len(data)} bytes, {f['classification']})")
        for s in f.get("share_with", []) if mode != "baseline" else []:
            gkey = f"{key}->{s['recipient']}"
            have = state["grants"].get(gkey)
            active = {g["grant_id"] for g in owner.list_shares(fid)}
            if have and have["grant_id"] in active:
                log(f"share {gkey}: already active ({have['grant_id']})")
                continue
            gid = owner.share(fid, s["recipient"], rights=tuple(s["rights"]), expires_in_days=s.get("expires_in_days", 7), max_downloads=s.get("max_downloads", 10))
            state["grants"][gkey] = {"grant_id": gid, "file_id": fid, "owner": f["owner"], "recipient": s["recipient"], "recipient_id": users_by_name[s["recipient"]], "rights": s["rights"]}
            log(f"share {gkey}: grant {gid}")
    state["users"] = {name: {"user_id": uid} for name, uid in users_by_name.items()}
    state["users"]["admin"] = {"user_id": admin.user["id"]}
    state["mode"] = mode
    state["seeded_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    state_path.write_text(json.dumps(state, indent=2))
    log(f"state written to {state_path}")
    return state


def main() -> int:
    cfg = json.loads(Path(settings.SEED_FILE).read_text())
    out = Path(settings.SEED_OUTPUT_DIR)
    out.mkdir(parents=True, exist_ok=True)
    creds = asyncio.run(seed_db(cfg, out / "credentials.json"))
    wait_for_api()
    seed_api(cfg, creds, out / "state.json")
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
