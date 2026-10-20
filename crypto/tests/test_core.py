import os
import uuid

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from ztv_crypto import (
    CLIENT_ARGON2,
    ChunkCipher,
    DeviceKey,
    aad_for_chunk,
    b64u,
    b64u_decode,
    build_manifest,
    canonical_json,
    cert_fingerprint,
    decrypt_chunks,
    derive_kek,
    encrypt_bytes,
    generate_org_root,
    generate_rsa_keypair,
    generate_user_keys,
    hash_password,
    issue_user_cert,
    make_dpop_proof,
    merkle_root,
    open_private_keys,
    reseal_private_keys,
    seal_private_keys,
    sign_grant,
    sign_manifest,
    split_chunks,
    unwrap_dek,
    unwrap_dek_rsa,
    verify_dpop_proof,
    verify_grant,
    verify_manifest,
    verify_password,
    verify_user_cert,
    wrap_dek,
    wrap_dek_rsa,
)
from ztv_crypto.audit import HashChain, sign_checkpoint, verify_chain
from ztv_crypto.ca import load_org_root, save_org_root
from ztv_crypto.dpop import DPoPError
from ztv_crypto.kdf import Argon2Params
from ztv_crypto.encoding import sha256
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

FID = str(uuid.uuid4())
SMALL = 1024  # small chunk size so tests are fast but multi-chunk


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 1, "a": [1, {"z": None, "y": "é"}]}) == '{"a":[1,{"y":"é","z":null}],"b":1}'.encode("utf-8")
    with pytest.raises(TypeError):
        canonical_json({"x": 1.5})


def test_b64u_roundtrip_and_url_safety():
    # round-trips every length, including ones that would normally need "=" padding
    for n in range(0, 40):
        data = os.urandom(n)
        enc = b64u(data)
        assert "=" not in enc
        assert b64u_decode(enc) == data
    # bytes that standard base64 encodes as "+" and "/" must become "-" and "_"
    assert b64u(b"\xfb\xff") == "-_8"
    assert b64u_decode("-_8") == b"\xfb\xff"
    assert b64u(b"") == ""


def test_canonical_json_rejects_unsafe_input_and_hashes_match():
    # key order in the input must not change the output (signatures depend on this)
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})
    # booleans, null and tuples serialise predictably
    assert canonical_json({"t": True, "n": None, "l": (1, 2)}) == b'{"l":[1,2],"n":null,"t":true}'
    # floats are rejected even when nested deep inside lists/dicts
    with pytest.raises(TypeError):
        canonical_json({"outer": [{"inner": 0.1}]})
    # non-string dict keys are rejected
    with pytest.raises(TypeError):
        canonical_json({1: "x"})
    # unsupported types (bytes, sets) are rejected
    with pytest.raises(TypeError):
        canonical_json({"raw": b"\x00"})
    with pytest.raises(TypeError):
        canonical_json({"s": {1, 2}})
    # sha256 matches the standard NIST test vector for "abc"
    assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_chunk_roundtrip_and_aad_binding():
    data = os.urandom(SMALL * 3 + 17)
    cc, cts = encrypt_bytes(data, FID, 1, chunk_size=SMALL)
    assert len(cts) == 4
    assert decrypt_chunks(cc, cts, expected_count=4) == data
    # byte flip
    bad = bytearray(cts[1]); bad[5] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_chunks(cc, [cts[0], bytes(bad), cts[2], cts[3]])
    # chunk swap
    with pytest.raises(InvalidTag):
        decrypt_chunks(cc, [cts[1], cts[0], cts[2], cts[3]])
    # truncation: dropping the last chunk makes chunk 2 'final' -> AAD mismatch
    with pytest.raises(InvalidTag):
        decrypt_chunks(cc, cts[:3])
    with pytest.raises(ValueError):
        decrypt_chunks(cc, cts[:3], expected_count=4)
    # cross-file splice
    other = ChunkCipher(dek=cc.dek, nonce_prefix=cc.nonce_prefix, file_id=str(uuid.uuid4()), version=1)
    with pytest.raises(InvalidTag):
        other.decrypt_chunk(0, cts[0], False)
    # version binding
    v2 = ChunkCipher(dek=cc.dek, nonce_prefix=cc.nonce_prefix, file_id=FID, version=2)
    with pytest.raises(InvalidTag):
        v2.decrypt_chunk(0, cts[0], False)


def test_empty_file_and_chacha():
    cc, cts = encrypt_bytes(b"", FID, 1, cipher="CHACHA20-POLY1305")
    assert len(cts) == 1 and decrypt_chunks(cc, cts) == b""
    assert aad_for_chunk(FID, 1, 0, True)[-1] == 1


def test_merkle_detects_changes():
    chunks = [os.urandom(100) for _ in range(5)]
    root = merkle_root(chunks)
    assert merkle_root(chunks) == root
    assert merkle_root(chunks[:4]) != root
    assert merkle_root([chunks[1], chunks[0]] + chunks[2:]) != root
    c2 = list(chunks); c2[3] = c2[3][:-1] + bytes([c2[3][-1] ^ 1])
    assert merkle_root(c2) != root


def test_wrap_unwrap_x25519_and_rsa():
    recipient = generate_user_keys()
    dek = os.urandom(32)
    rec = wrap_dek(dek, recipient.enc_pk, FID, 1)
    assert unwrap_dek(rec, recipient.enc_sk, FID, 1) == dek
    with pytest.raises(InvalidUnwrap):
        unwrap_dek(rec, recipient.enc_sk, FID, 2)  # wrong version in HKDF info
    other = generate_user_keys()
    with pytest.raises(InvalidUnwrap):
        unwrap_dek(rec, other.enc_sk, FID, 1)
    rsa_sk = generate_rsa_keypair(2048)  # smaller for test speed; prod baseline is 3072
    assert unwrap_dek_rsa(wrap_dek_rsa(dek, rsa_sk.public_key()), rsa_sk) == dek


def test_manifest_and_grant_signatures():
    owner = generate_user_keys()
    m = build_manifest(file_id=FID, version=1, name="q3.pdf", size=10, classification="CONFIDENTIAL", merkle_root=b"\x00" * 32, chunk_count=1, chunk_size=4194304, cipher="AES-256-GCM", nonce_prefix=b"\x01" * 8, owner_id="u1")
    sm = sign_manifest(m, owner.sig_sk)
    assert verify_manifest(sm, owner.sig_pk)
    tampered = {**sm, "classification": "PUBLIC"}
    assert not verify_manifest(tampered, owner.sig_pk)
    assert not verify_manifest(sm, generate_user_keys().sig_pk)
    g = {"grant_id": "g1", "file_id": FID, "owner_id": "u1", "recipient_id": "u2", "rights": ["view"], "expires_at": "2030-01-01T00:00:00Z", "max_downloads": 3, "required_posture": "registered", "issued_at": "2026-01-01T00:00:00Z"}
    sg = sign_grant(g, owner.sig_sk)
    assert verify_grant(sg, owner.sig_pk)
    assert not verify_grant({**sg, "rights": ["view", "download"]}, owner.sig_pk)


def test_kek_and_keyblob():
    fast = Argon2Params(memory_kib=8 * 1024, time_cost=1, parallelism=1)
    salt = b"\x07" * 16
    assert derive_kek("correct horse", salt, fast) == derive_kek("correct horse", salt, fast)
    assert derive_kek("correct horse", salt, fast) != derive_kek("correct horse!", salt, fast)
    keys = generate_user_keys()
    blob = seal_private_keys(keys, "pass-1", fast)
    opened = open_private_keys(blob, "pass-1")
    assert opened.enc_pk == keys.enc_pk and opened.sig_pk == keys.sig_pk
    with pytest.raises(InvalidTag):
        open_private_keys(blob, "pass-2")
    blob2 = reseal_private_keys(blob, "pass-1", "pass-2")
    assert open_private_keys(blob2, "pass-2").sig_pk == keys.sig_pk
    assert blob["kdf"]["m"] == 8192 and CLIENT_ARGON2.memory_kib == 65536


def test_password_hashing():
    h = hash_password("hunter2")
    assert h.startswith("$argon2id$") and "m=19456,t=2,p=1" in h
    assert verify_password(h, "hunter2") and not verify_password(h, "hunter3")


def test_org_ca(tmp_path):
    root = generate_org_root()
    save_org_root(root, tmp_path / "root.json")
    sk, pk = load_org_root(tmp_path / "root.json")
    user = generate_user_keys()
    cert = issue_user_cert(sk, user_id="u1", username="alice", enc_pk_raw=user.enc_pk, sig_pk_raw=user.sig_pk)
    assert verify_user_cert(cert, pk)
    assert verify_user_cert(cert, pk, expected_user_id="u1")
    assert not verify_user_cert(cert, pk, expected_user_id="u2")
    # malicious server substitutes its own key -> fails against pinned root
    evil = generate_user_keys()
    assert not verify_user_cert({**cert, "enc_pk": b64u(evil.enc_pk)}, pk)
    assert not verify_user_cert(cert, generate_user_keys().sig_pk)
    fp = cert_fingerprint(user.enc_pk, user.sig_pk)
    assert len(fp.replace(" ", "")) == 32


def _audit_key():
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_audit_chain_pinpoints_tampering():
    sk, pk = _audit_key()
    chain = HashChain()
    for i in range(12):
        chain.append(actor=f"u{i % 3}", action="file.read", resource=f"f{i}", decision="PERMIT", reason="policy:ok", ip="10.0.0.1", device="d1", details={"n": i})
    cps = [sign_checkpoint(5, b64u_decode(chain.entries[4]["hash"]), sk), sign_checkpoint(12, chain.prev, sk)]
    assert verify_chain(chain.entries, cps, pk).ok
    # modify entry 7 silently
    import copy
    ents = copy.deepcopy(chain.entries); ents[6]["decision"] = "DENY"
    r = verify_chain(ents, cps, pk)
    assert not r.ok and r.first_bad_seq == 7 and "modified" in r.problem
    # delete entry 4
    ents = copy.deepcopy(chain.entries); del ents[3]
    r = verify_chain(ents, cps, pk)
    assert not r.ok and r.first_bad_seq == 4 and "deleted" in r.problem
    # truncate the tail
    r = verify_chain(chain.entries[:10], cps, pk)
    assert not r.ok and r.first_bad_seq == 12 and "truncated" in r.problem
    # attacker recomputes hashes after editing entry 2 -> caught by checkpoint
    rebuilt = HashChain()
    for e in chain.entries:
        rebuilt.append(**{k: e[k] for k in ("ts", "actor", "action", "resource", "decision", "reason", "ip", "device", "details")})
    rebuilt2 = HashChain()
    for i, e in enumerate(chain.entries):
        f = {k: e[k] for k in ("ts", "actor", "action", "resource", "decision", "reason", "ip", "device", "details")}
        if i == 1:
            f["actor"] = "mallory"
        rebuilt2.append(**f)
    assert verify_chain(rebuilt.entries, cps, pk).ok
    r = verify_chain(rebuilt2.entries, cps, pk)
    assert not r.ok and r.first_bad_seq == 5 and "rewritten" in r.problem
    # forged checkpoint
    fake_sk, _ = _audit_key()
    r = verify_chain(chain.entries, [sign_checkpoint(12, chain.prev, fake_sk)], pk)
    assert not r.ok and "forged" in r.problem


def test_dpop_proofs():
    k = DeviceKey.generate()
    url = "https://vault.local:8443/api/files/abc?x=1"
    proof = make_dpop_proof(k, "GET", url, access_token="tok")
    info = verify_dpop_proof(proof, "get", "https://VAULT.local:8443/api/files/abc", access_token="tok")
    assert info["jkt"] == k.thumbprint and len(info["jti"]) > 10
    with pytest.raises(DPoPError):
        verify_dpop_proof(proof, "POST", url, access_token="tok")
    with pytest.raises(DPoPError):
        verify_dpop_proof(proof, "GET", "https://vault.local:8443/api/files/xyz", access_token="tok")
    with pytest.raises(DPoPError):
        verify_dpop_proof(proof, "GET", url, access_token="stolen-other-token")
    old = make_dpop_proof(k, "GET", url, iat=1_000_000)
    with pytest.raises(DPoPError):
        verify_dpop_proof(old, "GET", url)
    # proof signed by another device must not match the token-bound thumbprint
    other = DeviceKey.generate()
    assert verify_dpop_proof(make_dpop_proof(other, "GET", url), "GET", url)["jkt"] != k.thumbprint
    assert DeviceKey.from_pem(k.to_pem()).thumbprint == k.thumbprint