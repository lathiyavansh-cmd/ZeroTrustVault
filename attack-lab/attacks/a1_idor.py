"""a1 — Cross-tenant IDOR: carol (finance) reads alice's CONFIDENTIAL file by id.

baseline: no PDP, GET /files/{id}/download returns plaintext (marker recovered).
zerotrustvault: POST /files/{id}/access -> 403; and a *leaked* 60-second blob URL
yields only AEAD ciphertext (no marker).
"""
from __future__ import annotations
import common as C

NAME = "a1_idor"
TITLE = "Cross-tenant IDOR"


def run(mode: str) -> C.Result:
    try:
        fid = C.ensure_target_file()["file_id"]

        if mode == "baseline":
            carol = C.make_client("carol")
            r = carol.request("GET", f"/api/files/{fid}/download")
            body = getattr(r, "content", b"")
            if r.status_code == 200 and C.MARKER.encode() in body:
                return C.succeeded(NAME, mode,
                                   f"carol downloaded alice's file by id -> 200, marker recovered",
                                   http_status=200, marker=True)
            return C.blocked(NAME, mode, "unexpected",
                             f"carol /download -> {r.status_code}, no marker", http_status=r.status_code)

        # zerotrustvault
        IntegrityError, AccessDenied, StepUpRequired = C.exc_types()
        carol = C.make_client("carol", load_keys=True)
        try:
            carol.access(fid, intent="view")
            return C.succeeded(NAME, mode, "PDP issued a PERMIT to an unauthorized cross-tenant subject")
        except (AccessDenied, StepUpRequired) as e:
            # Confirm a leaked blob URL (from the authorized owner) is ciphertext-only.
            leaked = _leaked_blob_is_ciphertext(fid)
            return C.blocked(NAME, mode, "PDP default-DENY (no grant, dept/clearance mismatch)",
                             f"carol /access -> 403 ({type(e).__name__}); leaked blob URL = ciphertext only "
                             f"(marker_in_blob={leaked['marker']})", **leaked)
    except Exception as e:  # noqa: BLE001
        return C.errored(NAME, mode, e)


def _leaked_blob_is_ciphertext(fid: str) -> dict:
    try:
        alice = C.make_client("alice", load_keys=True)
        permit = alice.access(fid, intent="download")
        urls = permit.get("chunk_urls") or []
        if not urls:
            return {"marker": False, "note": "no chunk_urls in PERMIT"}
        url = urls[0]
        import httpx
        with httpx.Client(verify=(C.CFG.ca_cert or False), timeout=15.0) as h:
            full = url if url.startswith("http") else f"{C.CFG.api_url}{url}"
            rb = h.get(full)
        return {"marker": C.MARKER.encode() in rb.content, "blob_status": rb.status_code,
                "blob_bytes": len(rb.content)}
    except Exception as e:  # noqa: BLE001
        return {"marker": False, "note": f"blob check skipped: {type(e).__name__}"}
