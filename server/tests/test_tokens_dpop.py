import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from ztv_crypto.dpop import DeviceKey, make_dpop_proof
from ztv_server import security
from ztv_server.security import AuthError, SessionStore, check_dpop, issue_access_token, sign_blob_token, verify_access_token, verify_blob_token

pytestmark = pytest.mark.asyncio


class FakeKeys:
    def __init__(self):
        self.signing_sk = ed25519.Ed25519PrivateKey.generate()
        self.signing_pk = self.signing_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.audit_sk = ed25519.Ed25519PrivateKey.generate()
        self.audit_pk = self.audit_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.blob_hmac = b"k" * 32
        self.org_root_pk = b"\x00" * 32


@pytest.fixture(autouse=True)
def fake_keys():
    security.set_keys(FakeKeys())


@pytest.fixture
def store():
    import fakeredis.aioredis

    return SessionStore(fakeredis.aioredis.FakeRedis())


URL = "https://localhost:8443/api/files/abc/access"


async def test_access_token_roundtrip_and_expiry():
    tok = issue_access_token(user_id="u1", session_id="s1", device_id="d1", jkt="J", amr=["pwd", "totp"])
    claims = verify_access_token(tok)
    assert claims["sub"] == "u1" and claims["cnf"]["jkt"] == "J" and claims["exp"] - claims["iat"] == 300
    with pytest.raises(AuthError) as e:
        verify_access_token(tok, now=int(time.time()) + 301)
    assert e.value.code == "token_expired"
    other = ed25519.Ed25519PrivateKey.generate()
    forged = issue_access_token(user_id="u1", session_id="s1", device_id="d1", jkt="J", amr=[], sk=other)
    with pytest.raises(AuthError):
        verify_access_token(forged)


async def test_dpop_ok_then_replay_rejected(store):
    key = DeviceKey.generate()
    tok = issue_access_token(user_id="u1", session_id="s1", device_id="d1", jkt=key.thumbprint, amr=[])
    proof = make_dpop_proof(key, "POST", URL, tok)
    info = await check_dpop(store, proof, "POST", URL, tok, key.thumbprint)
    assert info["jkt"] == key.thumbprint
    with pytest.raises(AuthError) as e:
        await check_dpop(store, proof, "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_replay"


async def test_dpop_wrong_key_htu_htm_iat_ath(store):
    key, other = DeviceKey.generate(), DeviceKey.generate()
    tok = issue_access_token(user_id="u1", session_id="s1", device_id="d1", jkt=key.thumbprint, amr=[])
    with pytest.raises(AuthError) as e:
        await check_dpop(store, make_dpop_proof(other, "POST", URL, tok), "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_jkt"
    with pytest.raises(AuthError) as e:
        await check_dpop(store, make_dpop_proof(key, "POST", "https://localhost:8443/api/files/xyz/access", tok), "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_htu"
    with pytest.raises(AuthError) as e:
        await check_dpop(store, make_dpop_proof(key, "GET", URL, tok), "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_htm"
    with pytest.raises(AuthError) as e:
        await check_dpop(store, make_dpop_proof(key, "POST", URL, tok, iat=int(time.time()) - 600), "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_iat"
    with pytest.raises(AuthError) as e:
        await check_dpop(store, make_dpop_proof(key, "POST", URL, "other-token"), "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_ath"
    with pytest.raises(AuthError) as e:
        await check_dpop(store, None, "POST", URL, tok, key.thumbprint)
    assert e.value.code == "dpop_missing"


async def test_session_revocation_is_instant(store):
    await store.create_session("s1", "u1", "d1", "J")
    assert await store.session_alive("s1")
    await store.revoke_session("s1")
    assert await store.session_alive("s1") is None


async def test_lockout_and_rate_limit(store):
    for i in range(4):
        await store.record_failed_login("u1")
    assert await store.failed_logins("u1") == 4
    await store.lock("u1", 900)
    assert await store.locked("u1")
    hits = [await store.rate_limited("login:1.1.1.1", 3) for _ in range(5)]
    assert hits == [False, False, False, True, True]


async def test_blob_token_hmac_and_expiry():
    now = int(time.time())
    t = sign_blob_token({"f": "f1", "v": 1, "i": 0, "u": "u1", "g": 0, "fg": 0, "exp": now + 60})
    assert verify_blob_token(t)["f"] == "f1"
    assert verify_blob_token(t, now=now + 61) is None
    assert verify_blob_token(t[:-3] + "AAA") is None
    assert verify_blob_token(t, key=b"x" * 32) is None


async def test_risk_scoring(store):
    score, signals = await security.compute_risk(store, "u1", ip="1.1.1.1", jkt="J", geo="IN", demo_risk=0, hour_utc=12)
    assert score == 45 and set(signals) == {"new_device", "new_ip"}
    score, signals = await security.compute_risk(store, "u1", ip="1.1.1.1", jkt="J", geo="IN", demo_risk=0, hour_utc=12)
    assert score == 0
    score, signals = await security.compute_risk(store, "u1", ip="1.1.1.1", jkt="J", geo="US", demo_risk=10, hour_utc=23)
    assert score == 55 and "geo_mismatch" in signals and "outside_hours" in signals
