"""a5 — Request replay.

Capture one legitimate, authorized request and send it again.

baseline: the bearer request is idempotently replayable — a captured /download
re-sends and succeeds.
zerotrustvault: a DPoP-protected request carries a single-use jti and a time-boxed
iat.  Replaying the exact proof -> 401 (jti already seen), and a freshly-signed
proof with a stale iat -> 401 (outside the +/-60 s window).
"""
from __future__ import annotations
import time
import common as C

NAME = "a5_replay"
TITLE = "Request replay"


def run(mode: str) -> C.Result:
    try:
        fid = C.ensure_target_file()["file_id"]

        if mode == "baseline":
            victim = C.make_client("alice")
            token = victim.access_token
            with C.raw_http() as h:
                hdr = {"Authorization": f"Bearer {token}"}
                r1 = h.get(f"/api/files/{fid}/download", headers=hdr)
                r2 = h.get(f"/api/files/{fid}/download", headers=hdr)   # verbatim replay
            replayable = r1.status_code == 200 and r2.status_code == 200
            return C.succeeded(NAME, mode,
                               f"captured bearer request replayed verbatim -> {r1.status_code}, {r2.status_code}",
                               first=r1.status_code, replay=r2.status_code)

        # zerotrustvault
        from ztv_crypto.dpop import make_dpop_proof  # type: ignore
        victim = C.make_client("alice", load_keys=True)
        token = victim.access_token
        path = f"/files/{fid}/access"
        url = f"{C.CFG.api_url}/api{path}"
        now = int(time.time())
        with C.raw_http() as h:
            # 1) A valid request, then the SAME proof replayed (identical jti).
            proof = make_dpop_proof(victim.device_key, "POST", url, access_token=token,
                                    iat=now, jti="replay-fixed-jti-a5")
            first = h.post(f"/api{path}", json={"intent": "view"},
                           headers={"Authorization": f"DPoP {token}", "DPoP": proof})
            replay = h.post(f"/api{path}", json={"intent": "view"},
                            headers={"Authorization": f"DPoP {token}", "DPoP": proof})
            # 2) A fresh proof with a stale iat (10 minutes old).
            old = make_dpop_proof(victim.device_key, "POST", url, access_token=token, iat=now - 600)
            stale = h.post(f"/api{path}", json={"intent": "view"},
                           headers={"Authorization": f"DPoP {token}", "DPoP": old})
        jti_blocked = replay.status_code == 401
        iat_blocked = stale.status_code == 401
        if jti_blocked and iat_blocked:
            return C.blocked(NAME, mode, "single-use DPoP jti + iat window",
                             f"first={first.status_code}; jti replay -> {replay.status_code}; "
                             f"stale iat -> {stale.status_code}",
                             first=first.status_code, jti_replay=replay.status_code, stale_iat=stale.status_code)
        return C.succeeded(NAME, mode,
                           f"replay not fully blocked (jti_replay={replay.status_code}, stale_iat={stale.status_code})")
    except Exception as e:  # noqa: BLE001
        return C.errored(NAME, mode, e)
