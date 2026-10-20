"""Command-line tools.

ztv-ca            offline Organization CA (init-root, fingerprint, sign, verify, approve, daemon)
ztv-audit-verify  recompute the audit hash chain + checkpoints and pinpoint the first broken entry
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .audit import verify_chain
from .ca import cert_fingerprint, generate_org_root, issue_user_cert, load_org_root, save_org_root, verify_user_cert
from .encoding import b64u_decode


def _print(obj) -> None:
    print(json.dumps(obj, indent=2))


def ca_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ztv-ca", description="ZeroTrustVault offline Organization CA (Ed25519)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init-root", help="generate the org root key (keep OFFLINE)")
    p.add_argument("--out", required=True)
    p.add_argument("--pub-out", help="write the public key JSON for pinning in the client/server")

    p = sub.add_parser("fingerprint", help="compute the out-of-band fingerprint of a cert request")
    p.add_argument("--request", required=True, help="JSON with enc_pk and sig_pk")

    p = sub.add_parser("sign", help="sign a user cert request after out-of-band fingerprint confirmation")
    p.add_argument("--root", required=True)
    p.add_argument("--request", required=True)
    p.add_argument("--confirm-fingerprint", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("verify", help="verify a user certificate against the root public key")
    p.add_argument("--root-pub", required=True, help="JSON file with {'pk': b64u}")
    p.add_argument("--cert", required=True)

    p = sub.add_parser("approve", help="fetch a pending request from the server, sign it and publish the cert")
    p.add_argument("--root", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--admin-key", required=True)
    p.add_argument("--request-id", required=True)
    p.add_argument("--confirm-fingerprint", required=True)
    p.add_argument("--insecure", action="store_true")
    _tls_args(p)

    p = sub.add_parser("daemon", help="simulated offline signer: poll the server for OOB-confirmed requests and sign them")
    p.add_argument("--root", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--admin-key", required=True)
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--once", action="store_true")
    _tls_args(p)

    a = ap.parse_args(argv)

    if a.cmd == "init-root":
        root = generate_org_root()
        save_org_root(root, a.out)
        if a.pub_out:
            Path(a.pub_out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.pub_out).write_text(json.dumps({"kty": "Ed25519", "pk": root["pk"], "created": root["created"], "expires": root["expires"]}, indent=2))
        print(f"org root written to {a.out} (expires {root['expires']}); public key: {root['pk']}")
        return 0

    if a.cmd == "fingerprint":
        req = json.loads(Path(a.request).read_text())
        print(cert_fingerprint(b64u_decode(req["enc_pk"]), b64u_decode(req["sig_pk"])))
        return 0

    if a.cmd == "sign":
        root_sk, _ = load_org_root(a.root)
        req = json.loads(Path(a.request).read_text())
        fp = cert_fingerprint(b64u_decode(req["enc_pk"]), b64u_decode(req["sig_pk"]))
        if _norm(fp) != _norm(a.confirm_fingerprint):
            print(f"REFUSED: fingerprint mismatch. Request has {fp}", file=sys.stderr)
            return 2
        cert = issue_user_cert(root_sk, user_id=req["user_id"], username=req["username"], enc_pk_raw=b64u_decode(req["enc_pk"]), sig_pk_raw=b64u_decode(req["sig_pk"]))
        Path(a.out).write_text(json.dumps(cert, indent=2))
        print(f"certificate {cert['serial']} written to {a.out}")
        return 0

    if a.cmd == "verify":
        pk = b64u_decode(json.loads(Path(a.root_pub).read_text())["pk"])
        ok = verify_user_cert(json.loads(Path(a.cert).read_text()), pk)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1

    if a.cmd in ("approve", "daemon"):
        import httpx

        root_sk, _ = load_org_root(a.root)
        from .headless_client import make_ssl_context

        ctx = make_ssl_context(a.ca_cert if a.ca_cert else (not a.insecure), (a.client_cert, a.client_key) if a.client_cert else None)
        client = httpx.Client(base_url=a.server.rstrip("/"), verify=ctx, headers={"X-Admin-Key": a.admin_key}, timeout=10)

        def sign_and_publish(req: dict) -> None:
            cert = issue_user_cert(root_sk, user_id=req["user_id"], username=req["username"], enc_pk_raw=b64u_decode(req["enc_pk"]), sig_pk_raw=b64u_decode(req["sig_pk"]))
            r = client.post(f"/api/admin/cert-requests/{req['id']}/publish", json={"cert": cert})
            r.raise_for_status()
            print(f"signed + published cert for {req['username']} ({req['id']}) serial {cert['serial']}")

        if a.cmd == "approve":
            r = client.get(f"/api/admin/cert-requests/{a.request_id}")
            r.raise_for_status()
            req = r.json()
            fp = cert_fingerprint(b64u_decode(req["enc_pk"]), b64u_decode(req["sig_pk"]))
            if _norm(fp) != _norm(a.confirm_fingerprint):
                print(f"REFUSED: fingerprint mismatch. Request has {fp}", file=sys.stderr)
                return 2
            sign_and_publish(req)
            return 0

        print(f"offline signer daemon polling {a.server} every {a.interval}s (only OOB-confirmed requests are signed)", flush=True)
        while True:
            try:
                r = client.get("/api/admin/cert-requests", params={"status": "confirmed"})
                r.raise_for_status()
                for req in r.json():
                    fp = cert_fingerprint(b64u_decode(req["enc_pk"]), b64u_decode(req["sig_pk"]))
                    if _norm(req.get("confirmed_fingerprint") or "") != _norm(fp):
                        print(f"skip {req['id']}: confirmed fingerprint does not match request", file=sys.stderr)
                        continue
                    sign_and_publish(req)
            except Exception as e:  # noqa: BLE001 - keep the daemon alive (API may not be up yet)
                print(f"signer: {e}", file=sys.stderr, flush=True)
            if a.once:
                return 0
            time.sleep(a.interval)

    return 1


def _tls_args(p) -> None:
    p.add_argument("--ca-cert", help="CA bundle used to verify the API server certificate")
    p.add_argument("--client-cert", help="client certificate (PEM) for mTLS to the API")
    p.add_argument("--client-key", help="client private key (PEM) for mTLS to the API")


def _norm(fp: str) -> str:
    return "".join(fp.split()).upper()


def audit_verify_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ztv-audit-verify", description="Verify the tamper-evident audit chain and pinpoint the first broken entry")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--export", help="JSON file {entries:[...], checkpoints:[...], audit_pk?:b64u}")
    src.add_argument("--db", help="PostgreSQL DSN (reads audit_entries + audit_checkpoints)")
    src.add_argument("--server", help="API base URL (uses /api/audit/export)")
    ap.add_argument("--admin-key")
    ap.add_argument("--checkpoints", help="directory of write-once checkpoint JSON files (overrides the ones in the source)")
    ap.add_argument("--audit-pub", help="JSON file with {'pk': b64u} of the audit signing key")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    entries: list[dict]
    checkpoints: list[dict]
    audit_pk = None
    if a.export:
        data = json.loads(Path(a.export).read_text())
        entries, checkpoints = data["entries"], data.get("checkpoints", [])
        if data.get("audit_pk"):
            audit_pk = b64u_decode(data["audit_pk"])
    elif a.server:
        import httpx

        from .headless_client import make_ssl_context

        r = httpx.get(a.server.rstrip("/") + "/api/audit/export", headers={"X-Admin-Key": a.admin_key or ""}, verify=make_ssl_context(not a.insecure), timeout=30)
        r.raise_for_status()
        data = r.json()
        entries, checkpoints = data["entries"], data.get("checkpoints", [])
        if data.get("audit_pk"):
            audit_pk = b64u_decode(data["audit_pk"])
    else:
        import psycopg

        with psycopg.connect(a.db) as conn:
            cols = ",".join(["seq", "ts", "actor", "action", "resource", "decision", "reason", "ip", "device", "details", "prev_hash", "hash"])
            rows = conn.execute(f"SELECT {cols} FROM audit_entries ORDER BY seq").fetchall()
            entries = [dict(zip(cols.split(","), r)) for r in rows]
            for e in entries:
                if hasattr(e["ts"], "isoformat"):
                    e["ts"] = e["ts"].replace(microsecond=0).isoformat().replace("+00:00", "Z")
            cps = conn.execute("SELECT seq, hash, ts, signature FROM audit_checkpoints ORDER BY seq").fetchall()
            checkpoints = [{"seq": r[0], "hash": r[1], "ts": r[2], "signature": r[3]} for r in cps]
    if a.checkpoints:
        checkpoints = [json.loads(p.read_text()) for p in sorted(Path(a.checkpoints).glob("*.json"))]
    if a.audit_pub:
        audit_pk = b64u_decode(json.loads(Path(a.audit_pub).read_text())["pk"])

    report = verify_chain(entries, checkpoints, audit_pk)
    # Rows written while the server ran in baseline mode carry no stored hash; the chain state still
    # advanced through them, so (like the server) report them as 'unchained' rather than as a break.
    unchained = [i for i in report.issues if "no stored hash" in i]
    if unchained:
        report.issues = [i for i in report.issues if "no stored hash" not in i]
        report.ok = not report.issues
        if report.issues:
            first = report.issues[0]
            report.first_bad_seq = int(first.split()[1].rstrip(":"))
            report.problem = first.split(": ", 1)[1]
        else:
            report.first_bad_seq, report.problem = None, None
    if a.json:
        _print(report.as_dict())
    else:
        print(f"entries checked: {report.entries_checked}   checkpoints checked: {report.checkpoints_checked}   unchained (baseline-mode) rows: {len(unchained)}")
        if report.ok:
            print(f"CHAIN INTACT  (head hash {report.last_hash})")
        else:
            print(f"CHAIN BROKEN at seq {report.first_bad_seq}: {report.problem}")
            for i in report.issues[1:10]:
                print("  also:", i)
    return 0 if report.ok else 1
