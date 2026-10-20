"""ZeroTrustVault cryptographic core.

Everything here is built only from NIST/IETF standard primitives exposed by the
`cryptography` package (OpenSSL 3): AES-256-GCM, ChaCha20-Poly1305, SHA-256,
HKDF-SHA256, AES-KW (RFC 3394), X25519, Ed25519, Argon2id, ECDSA P-256 (DPoP),
and RSA-OAEP/RSA-PSS (comparison baseline only).  No home-made cryptography.
"""
from .encoding import b64u, b64u_decode, canonical_json, sha256
from .chunks import CHUNK_SIZE, ChunkCipher, aad_for_chunk, nonce_for_chunk, encrypt_bytes, decrypt_chunks, split_chunks
from .merkle import merkle_root, leaf_hash, merkle_root_from_leaves
from .wrap import wrap_dek, unwrap_dek, wrap_dek_rsa, unwrap_dek_rsa, generate_rsa_keypair
from .sign import sign_manifest, verify_manifest, sign_grant, verify_grant, build_manifest, now_iso
from .kdf import derive_kek, hash_password, verify_password, CLIENT_ARGON2, SERVER_ARGON2, Argon2Params
from .keys import UserKeyPair, generate_user_keys, seal_private_keys, open_private_keys, reseal_private_keys, raw_pub, pkcs8
from .ca import generate_org_root, issue_user_cert, verify_user_cert, cert_fingerprint, load_org_root, save_org_root
from .audit import GENESIS_HASH, entry_hash, chain_hash, sign_checkpoint, verify_checkpoint, verify_chain, ChainReport
from .dpop import DeviceKey, make_dpop_proof, verify_dpop_proof, jwk_thumbprint, htu_from_url

__all__ = [n for n in dir() if not n.startswith("_")]
