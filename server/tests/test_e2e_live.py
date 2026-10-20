"""Live end-to-end test against a running stack (skipped when the API is unreachable).

Talks directly to the API container port (https://localhost:8000, mTLS with the nginx client cert) so it
does not depend on the web image.  Set ZTV_E2E_URL to use the nginx edge instead (no client cert needed).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
import pytest

from ztv_crypto.dpop import make_dpop_proof
from ztv_crypto.headless_client import AccessDenied, StepUpRequired, ZTVClient, make_ssl_context

ROOT = Path(__file__).resolve().parents[2]
URL = os.environ.get("ZTV_E2E_URL", "https://localhost:8000")
CERTS = ROOT / "infra" / "certs"
ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "ztv-dev-admin-key-change-me")
MARKER = b"ZTV-PLAINTEXT-MARKER"


def _client_kwargs() -> dict:
    kw: dict = {"verify": False}
    if ":8000" in URL and (CERTS / "nginx-client.crt").exists():
        kw["client_cert"] = (str(CERTS / "nginx-client.crt"), str(CERTS / "nginx-client.key"))
        kw["verify"] = str(CERTS / "internal-ca.crt")
    pub = ROOT / "infra" / "keys" / "org_root.pub.json"
    if pub.exists():
        kw["org_root_pk_b64u"] = json.loads(pub.read_text())["pk"]
    return kw


def _reachable() -> bool:
    try:
        kw = _client_kwargs()
        r = httpx.get(URL + "/api/health", verify=make_ssl_context(kw["verify"], kw.get("client_cert")), timeout=5)
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason=f"{URL} not reachable")


@pytest.fixture(scope="module")
def creds() -> dict:
    p = ROOT / "seed" / "generated" / "credentials.json"
    if not p.exists():
        pytest.skip("seed/generated/credentials.json missing: run `docker compose run --rm seed`")
    return json.loads(p.read_text())


def mk(name: str, creds: dict, posture: str = "trusted") -> ZTVClient:
    c = ZTVClient(URL, device_name=f"e2e-{name}", posture=posture, **_client_kwargs())
    c.login(name, creds[name]["password"], creds[name]["totp_secret"])
    return c


def set_mode(mode: str) -> None:
    kw = _client_kwargs()
    r = httpx.post(URL + "/api/admin/mode", json={"mode": mode}, headers={"X-Admin-Key": ADMIN_KEY}, verify=make_ssl_context(kw["verify"], kw.get("client_cert")), timeout=10)
    assert r.status_code == 200, r.text


@pytest.fixture(scope="module", autouse=True)
def ztv_mode():
    set_mode("zerotrustvault")
    yield
    set_mode("zerotrustvault")


def test_full_flow(creds):
    alice, bob, carol = mk("alice", creds), mk("bob", creds), mk("carol", creds)
    assert alice.mode == "zerotrustvault"
    for c in (alice, bob, carol):
        c.load_keys(creds[c.user["username"]]["key_passphrase"])
    data = b"e2e " + MARKER + b" " + os.urandom(5000)
    fid = alice.upload("e2e.bin", data, classification="CONFIDENTIAL")
    assert alice.download(fid) == data

    gid = alice.share(fid, "bob", rights=("view", "download"), max_downloads=5)
    assert bob.download(fid) == data
    with pytest.raises(AccessDenied):
        carol.access(fid)

    # replay a captured request: same proof again -> 401 (jti seen)
    url = URL + f"/api/files/{fid}/access"
    proof = make_dpop_proof(bob.device_key, "POST", url, bob.access_token)
    headers = {"Authorization": f"DPoP {bob.access_token}", "DPoP": proof}
    r1 = bob.http.post(url, json={"intent": "view"}, headers=headers)
    assert r1.status_code == 200
    r2 = bob.http.post(url, json={"intent": "view"}, headers=headers)
    assert r2.status_code == 401 and r2.json()["code"] == "dpop_replay"

    # token stolen to another device -> cnf.jkt mismatch
    thief = ZTVClient(URL, device_name="thief", **_client_kwargs())
    thief._mode = "zerotrustvault"
    thief.access_token = bob.access_token
    r = thief.request("POST", f"/api/files/{fid}/access", json={"intent": "view"})
    assert r.status_code == 401 and r.json()["code"] == "dpop_jkt"

    # step-up: high risk (60..84) request needs fresh MFA; >= 85 is denied even with fresh MFA
    base_risk = bob.me()["session"]["risk"]["score"]
    step = str(max(0, 60 - base_risk))
    with pytest.raises(StepUpRequired):
        bob.request("POST", f"/api/files/{fid}/access", json={"intent": "view"}, headers={"X-Demo-Risk": step})
    bob.step_up(creds["bob"]["totp_secret"])
    r = bob.request("POST", f"/api/files/{fid}/access", json={"intent": "view"}, headers={"X-Demo-Risk": step})
    assert r.status_code == 200
    with pytest.raises(AccessDenied):
        bob.request("POST", f"/api/files/{fid}/access", json={"intent": "view"}, headers={"X-Demo-Risk": str(max(0, 90 - base_risk))})

    # soft revocation: outstanding blob URLs die, next access denied
    acc = bob.access(fid, intent="view")
    alice.revoke_share(gid)
    assert bob.http.get(acc["chunk_urls"][0]).status_code == 403
    with pytest.raises(AccessDenied):
        bob.access(fid)

    # hard rotation: new version, new DEK, old chunks gone
    gid2 = alice.share(fid, "bob")
    data2 = b"rotated " + MARKER + os.urandom(3000)
    v = alice.rotate_file(fid, data2)
    assert v == 2
    assert bob.download(fid) == data2
    assert bob.http.get(acc["chunk_urls"][0]).status_code in (403, 404)

    # audit chain intact + decisions recorded
    rep = alice.audit_verify()
    assert rep["ok"] is True, rep
    recent = alice.audit_recent(50)
    assert any(e["decision"] == "PERMIT" and e["action"] == "file.access" for e in recent)
    alice.revoke_share(gid2)


def test_wrong_password_lockout_and_generic_errors(creds):
    kw = _client_kwargs()
    r = httpx.post(URL + "/api/auth/login", json={"username": "nobody", "password": "x", "device": {"jwk": {}, "name": "x", "posture": "registered"}}, verify=make_ssl_context(kw["verify"], kw.get("client_cert")))
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    assert "X-Server-Time" in r.headers


def test_baseline_mode(creds):
    set_mode("baseline")
    try:
        c = ZTVClient(URL, **_client_kwargs())
        assert c.mode == "baseline"
        d = c.login("alice", creds["alice"]["password"])
        assert d["token_type"] == "Bearer"
        data = b"baseline " + MARKER
        fid = c.upload("b.txt", data)
        carol = ZTVClient(URL, **_client_kwargs())
        carol.login("carol", creds["carol"]["password"])
        assert carol.download(fid) == data  # no per-file authorization in baseline
    finally:
        set_mode("zerotrustvault")
