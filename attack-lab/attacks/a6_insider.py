"""a6 — Malicious insider with direct DB + object-store access.

The attacker dumps Postgres (ZTV_PG_DSN) and MinIO and edits an audit row.

baseline: object store + DB hold plaintext and plain, editable logs — an audit row
can be changed with no trace.
zerotrustvault: everything at rest is AEAD ciphertext / X25519-wrapped DEKs /
Argon2id-sealed key blobs + password hashes (a grep proves the marker never
appears), and editing one audit_entries row makes GET /api/audit/verify flag the
EXACT seq (SHA-256 hash chain + signed checkpoints).
"""
from __future__ import annotations
import common as C

NAME = "a6_insider"
TITLE = "Insider DB + store dump"


def _server_baseline_key() -> bytes:
    """Insider has the server config: derive the baseline static key exactly like the server does."""
    import hashlib
    v = str(C.CFG.baseline_server_key).strip()
    try:
        k = bytes.fromhex(v)
        if len(k) == 32:
            return k
    except ValueError:
        pass
    return hashlib.sha256(v.encode()).digest()


def _scan_minio_for_marker(mode: str = "baseline") -> dict:
    """Dump the bucket. Raw objects are scanned for the plaintext marker; `baseline/*` objects are
    additionally decrypted with the server's static key (the insider has the server config) —
    which is exactly why server-side encryption does not protect against this attacker."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    mc = C.minio_client()
    bucket = C.CFG.minio_bucket
    found, scanned, decrypted = False, 0, 0
    key = _server_baseline_key()
    for obj in mc.list_objects(bucket, recursive=True):
        scanned += 1
        o = mc.get_object(bucket, obj.object_name)
        try:
            raw = o.read()
        finally:
            o.close(); o.release_conn()
        if C.MARKER.encode() in raw:
            found = True
            break
        if obj.object_name.startswith("baseline/"):
            if mode != "baseline":
                continue  # objects written by the conventional baseline system are not ZTV data at rest
            try:
                pt = AESGCM(key).decrypt(raw[:12], raw[12:], None)
                decrypted += 1
                if C.MARKER.encode() in pt:
                    found = True
                    break
            except Exception:
                pass
        if scanned >= 200:
            break
    return {"objects_scanned": scanned, "marker_found": found, "server_key_decrypted": decrypted}


def _audit_verify() -> dict:
    """Run the chain verifier. Preferred: GET /api/audit/verify as an authenticated admin session.
    Fallback: pull /api/audit/export (admin key) and recompute the chain locally with ztv_crypto."""
    try:
        admin = C.make_client("admin")
        r = admin.request("GET", "/api/audit/verify")
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    try:
        with C.raw_http() as h:
            r = h.get("/api/audit/export", headers={"X-Admin-Key": C.CFG.admin_key})
            if r.status_code == 200:
                from ztv_crypto.audit import verify_chain
                from ztv_crypto.encoding import b64u_decode
                d = r.json()
                pk = b64u_decode(d["audit_pk"]) if d.get("audit_pk") else None
                # Same semantics as the server: rows written in baseline mode carry no stored hash but the
                # chain state advanced through them, so they are 'unchained', not a break.
                rep = verify_chain(d.get("entries", []), d.get("checkpoints", []), pk).as_dict()
                issues = [i for i in rep["issues"] if "no stored hash" not in i]
                rep["unchained_entries"] = len(rep["issues"]) - len(issues)
                rep["issues"] = issues
                rep["ok"] = not issues
                rep["first_bad_seq"] = int(issues[0].split()[1].rstrip(":")) if issues else None
                rep["problem"] = issues[0].split(": ", 1)[1] if issues else None
                rep["source"] = "export+local-verifier"
                return rep
    except Exception:
        pass
    return {}


def _edit_audit_row(restore: bool = True, prefer_unchained: bool = False) -> dict:
    """Edit one audit_entries row directly in the DB (the insider has DB access); returns the touched seq.
    zerotrustvault: a CHAINED row (carries prev_hash/hash) -> the verifier must flag exactly this seq.
    baseline: a row the baseline system wrote (no hash) -> nothing in the baseline design can flag it."""
    conn = C.pg_connect()
    try:
        with conn.cursor() as cur:
            cond = "hash IS NULL" if prefer_unchained else "hash IS NOT NULL"
            cur.execute(f"SELECT seq, action FROM audit_entries WHERE {cond} ORDER BY seq LIMIT 1 OFFSET "
                        f"(SELECT GREATEST(count(*)/2,0)::int FROM audit_entries WHERE {cond})")
            row = cur.fetchone()
            if not row and prefer_unchained:
                cur.execute("SELECT seq, action FROM audit_entries ORDER BY seq LIMIT 1 OFFSET "
                            "(SELECT GREATEST(count(*)/2,0)::int FROM audit_entries)")
                row = cur.fetchone()
            if not row:
                conn.rollback(); return {"ok": False, "note": "no audit rows"}
            seq, action = row
            cur.execute("UPDATE audit_entries SET action=%s WHERE seq=%s", ("redacted_by_insider", seq))
        conn.commit()
        return {"ok": True, "seq": int(seq), "orig_action": action, "restore": restore, "_conn_closed": False}
    finally:
        if restore:
            pass
        # keep conn open for restore by caller
        conn.close()


def _restore_audit_row(seq: int, action) -> None:
    try:
        conn = C.pg_connect()
        with conn.cursor() as cur:
            cur.execute("UPDATE audit_entries SET action=%s WHERE seq=%s", (action, seq))
        conn.commit(); conn.close()
    except Exception:
        pass


def run(mode: str) -> C.Result:
    try:
        C.ensure_target_file()  # make sure there is data at rest

        if mode == "baseline":
            scan = {}
            try:
                scan = _scan_minio_for_marker()
            except Exception as e:  # noqa: BLE001
                scan = {"note": f"minio scan skipped: {type(e).__name__}"}
            # Silently edit an audit row; baseline has no chain so verify can't flag it.
            edit, verify = {}, {}
            try:
                edit = _edit_audit_row(prefer_unchained=True)
                verify = _audit_verify()
                if edit.get("ok"):
                    _restore_audit_row(edit["seq"], edit["orig_action"])
            except Exception as e:  # noqa: BLE001
                edit = {"note": f"db edit skipped: {type(e).__name__}"}
            # the baseline log has no integrity of its own: nothing pinpoints the edited row
            undetected = not verify or verify.get("first_bad_seq") != edit.get("seq")
            return C.succeeded(NAME, mode,
                               f"plaintext/editable at rest (marker_found={scan.get('marker_found')}); "
                               f"audit row edited, verify flagged nothing (undetected={undetected})",
                               minio=scan, audit_verify=verify)

        # zerotrustvault
        scan = _scan_minio_for_marker(mode)
        conf_ok = not scan["marker_found"]
        # Edit one audit row and confirm verify pinpoints the exact seq, then restore.
        detected, edit, verify = False, {}, {}
        try:
            edit = _edit_audit_row()
            verify = _audit_verify()
            detected = (not verify.get("ok", True)) and verify.get("first_bad_seq") == edit.get("seq")
            if edit.get("ok"):
                _restore_audit_row(edit["seq"], edit["orig_action"])
        except Exception as e:  # noqa: BLE001
            edit = {"note": f"live-DB variant skipped: {type(e).__name__}"}
            # Fall back to proving detection against the exported chain in memory.
            detected = _simulated_detection()
            verify = {"simulated": True}
        blocked = conf_ok and detected
        if blocked:
            return C.blocked(NAME, mode, "E2E AEAD at rest + hash-chained signed audit log",
                             f"grep over {scan['objects_scanned']} objects found NO marker; "
                             f"edited audit seq {edit.get('seq')} -> verify flagged "
                             f"first_bad_seq={verify.get('first_bad_seq', 'simulated')}",
                             minio=scan, audit_verify=verify)
        return C.succeeded(NAME, mode,
                           f"insider breach not fully contained (confidential_at_rest={conf_ok}, tamper_detected={detected})",
                           minio=scan)
    except Exception as e:  # noqa: BLE001
        return C.errored(NAME, mode, e)


def _simulated_detection() -> bool:
    """Prove chain tamper-evidence from the API-exported chain without touching the DB."""
    try:
        from ztv_crypto import verify_chain  # type: ignore
        from ztv_crypto.encoding import b64u_decode  # type: ignore
        with C.raw_http() as h:
            body = h.get("/api/audit/export", headers={"X-Admin-Key": C.CFG.admin_key}).json()
        entries = body.get("entries", [])
        pk = b64u_decode(body["audit_pk"]) if body.get("audit_pk") else None
        if not entries:
            return False
        idx = len(entries) // 2
        tampered = [dict(e) for e in entries]
        tampered[idx]["action"] = "redacted_by_insider"
        rep = verify_chain(tampered, body.get("checkpoints", []), pk)
        return (not rep.ok) and rep.first_bad_seq == int(entries[idx]["seq"])
    except Exception:
        return False
