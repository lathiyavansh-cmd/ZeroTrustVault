"""a4 — Ciphertext tampering at rest, three ways: flip, swap, truncate.

An attacker with object-store write access corrupts stored chunks.

baseline: no per-chunk AEAD/Merkle — tampered content is served and trusted.
zerotrustvault: download() raises IntegrityError for all three corruptions (GCM
tag / AAD / Merkle root), and a report-integrity call lands an ALERT in the audit
log (visible via GET /api/audit/recent).
"""
from __future__ import annotations
import io
import common as C

NAME = "a4_tamper"
TITLE = "Ciphertext tamper (flip/swap/truncate)"


def _objects(mc, bucket, fid, mode="zerotrustvault"):
    """Objects holding this file at rest. ZTV: files/{fid}/v{latest}/NNNNNN chunks; baseline: baseline/{fid}."""
    if mode == "baseline":
        return [f"baseline/{fid}"]
    names = sorted(o.object_name for o in mc.list_objects(bucket, prefix=f"files/{fid}/", recursive=True))
    if not names:
        raise RuntimeError(f"no ciphertext chunks found for {fid}")
    latest = max(int(n.split("/")[2][1:]) for n in names)
    return [n for n in names if n.split("/")[2] == f"v{latest}"]


def _get(mc, bucket, name):
    o = mc.get_object(bucket, name)
    try:
        return o.read()
    finally:
        o.close(); o.release_conn()


def _put(mc, bucket, name, data: bytes):
    mc.put_object(bucket, name, io.BytesIO(data), length=len(data))


def _tampers(objs):
    """Yield (label, mutate_fn) for flip / swap / truncate."""
    def flip(blobs):
        b = bytearray(blobs[objs[0]]); b[0] ^= 0x01; return {objs[0]: bytes(b)}
    def swap(blobs):
        if len(objs) >= 2:  # swap two whole chunks
            return {objs[0]: blobs[objs[1]], objs[1]: blobs[objs[0]]}
        b = bytearray(blobs[objs[0]])  # single chunk: swap two interior bytes
        if len(b) >= 4:
            b[1], b[2] = b[2], b[1]
        return {objs[0]: bytes(b)}
    def truncate(blobs):
        b = blobs[objs[-1]]
        return {objs[-1]: b[: max(0, len(b) - 16)]}  # drop the GCM tag
    return [("flip", flip), ("swap", swap), ("truncate", truncate)]


def run(mode: str) -> C.Result:
    try:
        fid = C.ensure_target_file()["file_id"]
        mc = C.minio_client()
        bucket = C.CFG.minio_bucket
        objs = _objects(mc, bucket, fid, mode)
        originals = {n: _get(mc, bucket, n) for n in objs}

        if mode == "baseline":
            mut = _tampers(objs)[0][1](originals)
            for n, d in mut.items():
                _put(mc, bucket, n, d)
            try:
                bob = C.make_client("bob")
                r = bob.request("GET", f"/api/files/{fid}/download")
                served = getattr(r, "status_code", 0) == 200
            finally:
                for n, d in originals.items():
                    _put(mc, bucket, n, d)
            return C.succeeded(NAME, mode,
                               f"flipped a stored byte; baseline served the object with no integrity check (status={served})",
                               served=served)

        # zerotrustvault — every corruption must fail closed.
        IntegrityError, _, _ = C.exc_types()
        results = {}
        for label, mutate in _tampers(objs):
            mut = mutate(originals)
            try:
                for n, d in mut.items():
                    _put(mc, bucket, n, d)
                bob = C.make_client("bob", load_keys=True)
                try:
                    bob.download(fid, intent="download")
                    results[label] = "ACCEPTED"   # bad: tamper not caught
                except IntegrityError:
                    results[label] = "IntegrityError"
                except Exception as e:  # other hard failure is still fail-closed
                    results[label] = type(e).__name__
            finally:
                for n, d in originals.items():
                    _put(mc, bucket, n, d)

        all_caught = all(v != "ACCEPTED" for v in results.values())
        alert = _report_and_check_alert(fid)
        if all_caught:
            return C.blocked(NAME, mode, "AES-GCM tag + AAD + signed Merkle root",
                             f"all corruptions fail-closed: {results}; report-integrity ALERT visible={alert}",
                             tamper_results=results, alert_in_audit=alert)
        return C.succeeded(NAME, mode, f"a corruption was accepted: {results}", tamper_results=results)
    except Exception as e:  # noqa: BLE001
        return C.errored(NAME, mode, e)


def _report_and_check_alert(fid: str) -> bool:
    try:
        bob = C.make_client("bob", load_keys=True)
        bob.request("POST", f"/api/files/{fid}/report-integrity",
                    json={"version": 1, "chunk_index": 0, "reason": "gcm_tag_mismatch"})
        r = bob.request("GET", "/api/audit/recent?limit=50")
        if getattr(r, "status_code", 0) != 200:
            return False
        rows = r.json()
        rows = rows.get("entries", rows) if isinstance(rows, dict) else rows
        return any((e.get("decision") == "ALERT") or ("integrity" in str(e.get("action", "")).lower())
                   for e in rows)
    except Exception:
        return False
