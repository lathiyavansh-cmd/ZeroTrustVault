"""Generates client/src/test/vectors.json from the Python reference core."""
import json, sys, hashlib
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from ztv_crypto import *
from ztv_crypto.chunks import aad_for_chunk, nonce_for_chunk, ChunkCipher
from ztv_crypto.wrap import hkdf_info, wrap_dek, unwrap_dek
from ztv_crypto.sign import MANIFEST_DOMAIN, GRANT_DOMAIN
from ztv_crypto.ca import CERT_DOMAIN
from ztv_crypto.kdf import Argon2Params
from ztv_crypto.dpop import DeviceKey, make_dpop_proof, jwk_thumbprint

file_id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
out = {}
obj = {"z": 1, "a": {"y": [3, {"b": True, "a": None}], "x": "ü \"\\"}, "m": "ascii"}
out["canonical_json"] = {"obj": obj, "bytes_b64u": b64u(canonical_json(obj))}
out["aad"] = {"file_id": file_id, "version": 7, "index": 3, "final": True, "aad_b64u": b64u(aad_for_chunk(file_id, 7, 3, True))}
prefix = bytes(range(8))
out["nonce"] = {"prefix_b64u": b64u(prefix), "index": 258, "nonce_b64u": b64u(nonce_for_chunk(prefix, 258))}
# chunks: deterministic DEK/prefix
dek = bytes(range(32)); 
cc = ChunkCipher(dek=dek, nonce_prefix=prefix, file_id=file_id, version=2)
pts = [b"hello chunk zero", b"", b"x" * 100]
cts = [cc.encrypt_chunk(i, p, i == len(pts) - 1) for i, p in enumerate(pts)]
out["chunks"] = {"dek_b64u": b64u(dek), "prefix_b64u": b64u(prefix), "file_id": file_id, "version": 2,
                 "plain_b64u": [b64u(p) for p in pts], "ct_b64u": [b64u(c) for c in cts],
                 "merkle_root_b64u": b64u(merkle_root(cts)), "leaves_b64u": [b64u(leaf_hash(c)) for c in cts]}
out["merkle_5"] = {"chunks_b64u": [b64u(bytes([i]) * (i + 1)) for i in range(5)], "root_b64u": b64u(merkle_root([bytes([i]) * (i + 1) for i in range(5)]))}
out["hkdf_info"] = {"file_id": file_id, "version": 3, "info_b64u": b64u(hkdf_info(file_id, 3))}
# wrap: recipient X25519 key with fixed seed
rsk = x25519.X25519PrivateKey.from_private_bytes(bytes([7]) * 32)
rec = wrap_dek(dek, raw_pub(rsk), file_id, 3)
out["wrap"] = {"recipient_sk_pkcs8_b64u": b64u(pkcs8(rsk)), "recipient_pk_b64u": b64u(raw_pub(rsk)), "dek_b64u": b64u(dek), "file_id": file_id, "version": 3, "record": rec}
# sealed blob with small argon2 params
ek = x25519.X25519PrivateKey.from_private_bytes(bytes([9]) * 32)
sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([11]) * 32)
kp = UserKeyPair(enc_sk=ek, sig_sk=sk)
blob = seal_private_keys(kp, "correct horse", Argon2Params(memory_kib=1024, time_cost=1, parallelism=1), salt=bytes(range(16)))
out["blob"] = {"passphrase": "correct horse", "blob": blob, "enc_pk_b64u": b64u(kp.enc_pk), "sig_pk_b64u": b64u(kp.sig_pk),
               "enc_sk_pkcs8_b64u": b64u(pkcs8(ek)), "sig_sk_pkcs8_b64u": b64u(pkcs8(sk))}
# manifest signed by sk
man = build_manifest(file_id=file_id, version=2, name="q3-results.pdf", size=116, classification="CONFIDENTIAL", merkle_root=merkle_root(cts), chunk_count=3, chunk_size=4194304, cipher="AES-256-GCM", nonce_prefix=prefix, owner_id="11111111-2222-3333-4444-555555555555", timestamp="2026-10-20T14:03:00Z")
out["manifest"] = {"signed": sign_manifest(man, sk), "owner_sig_pk_b64u": b64u(kp.sig_pk)}
grant = {"grant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "file_id": file_id, "owner_id": "11111111-2222-3333-4444-555555555555", "recipient_id": "66666666-7777-8888-9999-000000000000", "rights": ["view", "download"], "expires_at": "2026-11-20T14:03:00Z", "max_downloads": 5, "required_posture": "registered", "issued_at": "2026-10-20T14:03:00Z"}
out["grant"] = {"signed": sign_grant(grant, sk), "owner_sig_pk_b64u": b64u(kp.sig_pk)}
# cert from a root
root = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([13]) * 32)
root_pk = root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
cert = issue_user_cert(root, user_id="66666666-7777-8888-9999-000000000000", username="bob", enc_pk_raw=kp.enc_pk, sig_pk_raw=kp.sig_pk, days=36500, serial="serial-1")
out["cert"] = {"root_pk_b64u": b64u(root_pk), "cert": cert, "fingerprint": cert_fingerprint(kp.enc_pk, kp.sig_pk)}
# dpop thumbprint
dk = DeviceKey.generate()
out["dpop"] = {"jwk": dk.public_jwk(), "jkt": dk.thumbprint, "ath_of_abc": b64u(hashlib.sha256(b"abc").digest())}
out["audit"] = {"genesis_b64u": b64u(GENESIS_HASH)}
json.dump(out, open(sys.argv[1], "w"), indent=1)
print("ok")
