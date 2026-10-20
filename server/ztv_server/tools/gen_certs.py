"""Generate all dev PKI material programmatically (no real secrets, re-runnable, idempotent).

/certs  (shared volume):
  internal-ca.crt/.key   internal CA for mTLS between nginx and the API
  api.crt/.key           API server cert (SAN: api, localhost, 127.0.0.1), signed by internal CA
  nginx-client.crt/.key  client cert nginx presents to the API (mTLS)
  public.crt/.key        public TLS cert for https://localhost:8443 (self-signed, SPKI pinned by clients)
  public.spki.sha256     base64 SPKI pin of public.crt
/keys   (shared volume):
  server_signing.json    Ed25519 key that signs access tokens
  audit_signing.json     Ed25519 key that signs audit checkpoints  (+ audit_signing.pub.json)
  blob_url_hmac.json     HMAC key for 60-second ciphertext URLs
  org_root.pub.json      copy of the org root PUBLIC key (the private key stays in --org-root, offline)
--org-root path: creates infra/keys/org_root.json if missing (offline Org CA, loaded only by ztv-ca).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ztv_crypto.ca import generate_org_root, save_org_root
from ztv_crypto.encoding import b64u


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrustVault Dev"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, subject_cn, issuer_key, issuer_name, *, ca=False, sans=None, days=825, eku=None):
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def ed25519_json(sk: ed25519.Ed25519PrivateKey) -> dict:
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "Ed25519", "sk": b64u(sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())), "pk": b64u(pk)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="infra/certs")
    ap.add_argument("--keys", default="infra/keys/server")
    ap.add_argument("--org-root", default="infra/keys/org_root.json")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    out, keys, org_root = Path(a.out), Path(a.keys), Path(a.org_root)

    if a.force or not (out / "public.crt").exists():
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_cert = _cert(ca_key, "ZTV Internal CA", ca_key, _name("ZTV Internal CA"), ca=True, days=3650)
        api_key = ec.generate_private_key(ec.SECP256R1())
        api_cert = _cert(api_key, "api", ca_key, ca_cert.subject, sans=[x509.DNSName("api"), x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        cli_key = ec.generate_private_key(ec.SECP256R1())
        cli_cert = _cert(cli_key, "nginx-pep", ca_key, ca_cert.subject, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
        pub_key = ec.generate_private_key(ec.SECP256R1())
        pub_cert = _cert(pub_key, "localhost", pub_key, _name("localhost"), sans=[x509.DNSName("localhost"), x509.DNSName("web"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        for name, key, cert in (("internal-ca", ca_key, ca_cert), ("api", api_key, api_cert), ("nginx-client", cli_key, cli_cert), ("public", pub_key, pub_cert)):
            _write(out / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM))
            _write(out / f"{name}.key", _pem_key(key))
        spki = pub_cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        _write(out / "public.spki.sha256", base64.b64encode(hashlib.sha256(spki).digest()))
        print(f"TLS material written to {out} (public SPKI pin {base64.b64encode(hashlib.sha256(spki).digest()).decode()})")
    else:
        print(f"TLS material already present in {out}")

    for fname in ("server_signing.json", "audit_signing.json"):
        p = keys / fname
        if a.force or not p.exists():
            d = ed25519_json(ed25519.Ed25519PrivateKey.generate())
            _write(p, json.dumps(d, indent=2).encode())
            _write(keys / fname.replace(".json", ".pub.json"), json.dumps({"kty": "Ed25519", "pk": d["pk"]}, indent=2).encode())
    if a.force or not (keys / "blob_url_hmac.json").exists():
        _write(keys / "blob_url_hmac.json", json.dumps({"k": b64u(os.urandom(32))}).encode())

    if a.force or not org_root.exists():
        root = generate_org_root()
        save_org_root(root, org_root)
        print(f"OFFLINE org root created at {org_root} (never mounted into the api container)")
    root = json.loads(org_root.read_text())
    _write(keys / "org_root.pub.json", json.dumps({"kty": "Ed25519", "pk": root["pk"], "created": root["created"], "expires": root["expires"]}, indent=2).encode())
    _write(org_root.parent / "org_root.pub.json", json.dumps({"kty": "Ed25519", "pk": root["pk"], "created": root["created"], "expires": root["expires"]}, indent=2).encode())
    print(f"org root public key: {root['pk']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
