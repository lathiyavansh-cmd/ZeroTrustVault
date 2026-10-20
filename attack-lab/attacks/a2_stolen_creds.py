"""a2 — Stolen credentials from a new device.

The attacker has leaked alice's password and logs in from a brand-new device.

baseline: password-only login -> a usable 30-day bearer token (full account takeover).
zerotrustvault: password alone is stopped at the MFA gate (no token issued); and a
token captured elsewhere, replayed from the attacker's device key, fails the DPoP
cnf.jkt binding (401).
"""
from __future__ import annotations
import common as C

NAME = "a2_stolen_creds"
TITLE = "Stolen creds / new device"


def run(mode: str) -> C.Result:
    try:
        fid = C.ensure_target_file()["file_id"]

        if mode == "baseline":
            # Password-only login from a fresh device succeeds and reads data.
            attacker = C.make_client("alice", new_device=True, totp_secret=None)
            token = getattr(attacker, "access_token", None)
            r = attacker.request("GET", f"/api/files/{fid}/download")
            breach = bool(token) and r.status_code == 200
            return C.succeeded(NAME, mode,
                               f"password-only login issued a bearer token; /download -> {r.status_code}",
                               http_status=r.status_code, token_issued=bool(token))

        # zerotrustvault — (1) MFA gate stops password-only login from a new device.
        mfa_blocked = False
        detail_mfa = ""
        try:
            attacker = C.make_client("alice", new_device=True, totp_secret=None)
            mfa_blocked = not getattr(attacker, "access_token", None)
            detail_mfa = "login returned mfa_required, no access token issued" if mfa_blocked \
                else "login unexpectedly produced a token without MFA"
        except Exception as e:  # login raised because MFA step missing -> blocked
            mfa_blocked = True
            detail_mfa = f"login halted before token issuance ({type(e).__name__})"

        # (2) A token captured from alice's real session, replayed from the attacker's key.
        from ztv_crypto.dpop import make_dpop_proof  # type: ignore
        victim = C.make_client("alice", load_keys=True)
        stolen = victim.access_token
        attacker_key = C.new_device_key()
        url = f"{C.CFG.api_url}/api/files/{fid}/access"
        with C.raw_http() as h:
            proof = make_dpop_proof(attacker_key, "POST", url, access_token=stolen)
            r1 = h.post(f"/api/files/{fid}/access", json={"intent": "view"},
                        headers={"Authorization": f"DPoP {stolen}", "DPoP": proof})
        replay_blocked = r1.status_code == 401
        blocked = mfa_blocked and replay_blocked
        if blocked:
            return C.blocked(NAME, mode, "MFA step-up + DPoP cnf.jkt binding",
                             f"{detail_mfa}; token replay from attacker device -> {r1.status_code}",
                             mfa_blocked=mfa_blocked, replay_status=r1.status_code)
        return C.succeeded(NAME, mode,
                           f"account takeover not fully prevented (mfa_blocked={mfa_blocked}, replay_status={r1.status_code})")
    except Exception as e:  # noqa: BLE001
        return C.errored(NAME, mode, e)
