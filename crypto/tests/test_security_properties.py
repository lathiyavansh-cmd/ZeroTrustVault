"""Extra security-property tests for the ZeroTrustVault crypto core (M10).

Complements test_core.py: randomized tamper detection, key separation,
manifest/Merkle binding, DPoP proof uniqueness and password-hash salting.
"""
import os
import random
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from ztv_crypto import (
    ChunkCipher,
    DeviceKey,
    build_manifest,
    decrypt_chunks,
    encrypt_bytes,
    generate_user_keys,
    hash_password,
    make_dpop_proof,
    merkle_root,
    sign_manifest,
    verify_manifest,
    verify_password,
)

FID = str(uuid.uuid4())
SMALL = 1024


def test_random_bit_flips_are_always_detected():
    data = os.urandom(SMALL * 4 + 9)
    cc, cts = encrypt_bytes(data, FID, 1, chunk_size=SMALL)
    rng = random.Random(1234)
    for _ in range(200):
        i = rng.randrange(len(cts))
        pos = rng.randrange(len(cts[i]))
        bad = bytearray(cts[i])
        bad[pos] ^= 1 << rng.randrange(8)
        tampered = list(cts)
        tampered[i] = bytes(bad)
        with pytest.raises(InvalidTag):
            decrypt_chunks(cc, tampered)


def test_wrong_dek_cannot_decrypt():
    data = os.urandom(SMALL * 2)
    cc, cts = encrypt_bytes(data, FID, 1, chunk_size=SMALL)
    other = ChunkCipher(
        dek=os.urandom(32), nonce_prefix=cc.nonce_prefix, file_id=FID, version=1
    )
    with pytest.raises(InvalidTag):
        other.decrypt_chunk(0, cts[0], False)


def test_same_file_encrypted_twice_gives_different_ciphertext():
    data = os.urandom(SMALL)
    _, cts1 = encrypt_bytes(data, FID, 1, chunk_size=SMALL)
    _, cts2 = encrypt_bytes(data, FID, 1, chunk_size=SMALL)
    assert cts1 != cts2  # fresh DEK and nonce prefix per upload


def test_manifest_signature_binds_merkle_root():
    owner = generate_user_keys()
    chunks = [os.urandom(64) for _ in range(3)]
    m = build_manifest(
        file_id=FID, version=1, name="a.pdf", size=192,
        classification="CONFIDENTIAL", merkle_root=merkle_root(chunks),
        chunk_count=3, chunk_size=64, cipher="AES-256-GCM",
        nonce_prefix=b"\x02" * 8, owner_id="u1",
    )
    sm = sign_manifest(m, owner.sig_sk)
    assert verify_manifest(sm, owner.sig_pk)
    other_root = merkle_root([os.urandom(64) for _ in range(3)])
    forged = {**sm, "merkle_root": sm["merkle_root"][:-2] + "AA"}
    assert not verify_manifest(forged, owner.sig_pk)
    assert merkle_root(chunks) != other_root


def test_dpop_proofs_have_unique_ids():
    k = DeviceKey.generate()
    url = "https://vault.local:8443/api/files/abc"
    jtis = set()
    from ztv_crypto import verify_dpop_proof

    for _ in range(20):
        info = verify_dpop_proof(make_dpop_proof(k, "GET", url), "GET", url)
        jtis.add(info["jti"])
    assert len(jtis) == 20  # every request carries a fresh nonce


def test_password_hashes_are_salted():
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2
    assert verify_password(h1, "same-password")
    assert verify_password(h2, "same-password")
    assert not verify_password(h1, "Same-password")
