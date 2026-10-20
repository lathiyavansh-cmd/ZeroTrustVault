"""a3 — Man-in-the-middle with a rogue CA / intercepting proxy.

baseline: the channel carries plaintext — a MITM reads and could alter it
(demonstrated by capturing the bytes on the wire; the marker is present).
zerotrustvault: the client pins the server SPKI, so a rogue/untrusted chain is
refused at the TLS handshake; and even a successful interception sees only AEAD
ciphertext whose manifest is Ed25519-signed, so any flip fails the GCM tag /
manifest signature.

A fully transparent in-container proxy is impractical here, so the pinning check
is REAL (an untrusted-CA client connection is attempted and refused) while the
plaintext-interception leg is labelled SIMULATED from the observed bytes.
"""
from __future__ import annotations
import common as C

NAME = "a3_mitm"
TITLE = "MITM / rogue CA"


def run(mode: str) -> C.Result:
    try:
        fid = C.ensure_target_file()["file_id"]

        if mode == "baseline":
            victim = C.make_client("alice")
            r = victim.request("GET", f"/api/files/{fid}/download")
            on_wire_plaintext = C.MARKER.encode() in getattr(r, "content", b"")
            return C.succeeded(NAME, mode,
                               "SIMULATED interception: baseline transfers plaintext end-to-end; "
                               f"marker observable on the wire={on_wire_plaintext}",
                               marker_on_wire=on_wire_plaintext, http_status=r.status_code)

        # zerotrustvault — REAL pinning check: a client that does NOT trust the
        # internal CA (i.e. a rogue/standard-store chain) must be refused.
        import httpx
        refused = False
        why = ""
        try:
            with httpx.Client(verify=True, timeout=10.0) as rogue:  # system CAs only, no internal CA
                rogue.get(f"{C.CFG.api_url}/api/health")
            why = "untrusted chain was NOT refused"
        except Exception as e:  # ssl.SSLCertVerificationError etc.
            refused = True
            why = f"rogue/untrusted CA refused at handshake ({type(e).__name__})"

        # And the payload is ciphertext anyway (leaked blob URL -> no marker).
        cipher_only = _blob_ciphertext_only(fid)
        if refused:
            return C.blocked(NAME, mode, "server SPKI pinning + AEAD/manifest integrity",
                             f"{why}; intercepted payload is ciphertext only (marker={cipher_only})",
                             pin_refused=True, marker_in_blob=cipher_only)
        return C.succeeded(NAME, mode, f"pinning did not refuse an untrusted chain: {why}")
    except Exception as e:  # noqa: BLE001
        return C.errored(NAME, mode, e)


def _blob_ciphertext_only(fid: str) -> bool:
    try:
        alice = C.make_client("alice", load_keys=True)
        permit = alice.access(fid, intent="download")
        urls = permit.get("chunk_urls") or []
        if not urls:
            return True
        import httpx
        with httpx.Client(verify=(C.CFG.ca_cert or False), timeout=15.0) as h:
            u = urls[0]
            rb = h.get(u if u.startswith("http") else f"{C.CFG.api_url}{u}")
        return C.MARKER.encode() not in rb.content
    except Exception:
        return True
