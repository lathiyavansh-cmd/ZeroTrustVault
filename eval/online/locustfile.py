"""Locust load test for the PDP / authz decision path.

Drives POST /files/{id}/access under concurrency: ~80% authorized requests
(alice -> her own file, expect PERMIT) and ~20% denied requests (carol -> alice's
file, expect 403), so the policy engine exercises both the PERMIT and the
deny-overrides paths.  Each ZTVClient carries a real device key, so every request
is a full DPoP round-trip through the nginx edge — this measures the true
end-to-end authz latency, not a bare HTTP ping.

Run (see eval/README-online.md):
    locust -f eval/online/locustfile.py --headless -u 100 -r 20 -t 1m --host https://localhost:8443
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Make the attack-lab helpers importable.
for p in ("/attack-lab", str(Path(__file__).resolve().parents[2] / "attack-lab")):
    if p not in sys.path and Path(p).exists():
        sys.path.insert(0, p)

from locust import User, task, between, events  # type: ignore

import common as C


def _fire(name: str, started: float, exc: Exception | None = None, resp_len: int = 0):
    events.request.fire(
        request_type="PDP", name=name,
        response_time=(time.perf_counter() - started) * 1000.0,
        response_length=resp_len, exception=exc, context={},
    )


import threading  # monkey-patched by locust/gevent -> cooperative lock

_POOL: dict = {"alice": [], "carol": [], "file_id": None, "i": 0}
_POOL_SIZE = 6  # pre-authenticated sessions shared by all simulated users
_POOL_LOCK = threading.Lock()


def _pool():
    """Log in a handful of sessions once and share them across every simulated user.  Login is
    rate-limited (5 failures -> lockout, floods -> 429) as a deliberate control, so a load test of the
    *authorization* path must not re-login per user.  Every request still carries its own fresh DPoP
    proof (unique jti), so this measures the full per-request PEP + PDP chain."""
    with _POOL_LOCK:  # all 100 users start at once: only the first builds the pool
      if _POOL["file_id"] is None:
        _POOL["file_id"] = C.ensure_target_file()["file_id"]
        for _ in range(_POOL_SIZE):
            _POOL["alice"].append(C.make_client("alice", load_keys=True))
        for _ in range(max(1, _POOL_SIZE // 3)):
            try:
                _POOL["carol"].append(C.make_client("carol", load_keys=True))
            except Exception:  # noqa: BLE001
                break
    return _POOL


class PDPUser(User):
    wait_time = between(0.0, 0.2)

    def on_start(self):
        pool = _pool()
        pool["i"] += 1
        self.file_id = pool["file_id"]
        self.alice = pool["alice"][pool["i"] % len(pool["alice"])]
        self.carol = pool["carol"][pool["i"] % len(pool["carol"])] if pool["carol"] else None

    @task(8)
    def authorized_access(self):
        started = time.perf_counter()
        try:
            r = self.alice.request("POST", f"/api/files/{self.file_id}/access", json={"intent": "view"})
            if r.status_code != 200:
                raise RuntimeError(f"expected PERMIT, got {r.status_code}")
            _fire("POST /files/{id}/access [permit] end-to-end", started, resp_len=len(r.content))
            # Server-side timings: the full authorization pipeline (attribute collection from DB + PDP +
            # chained audit write) and the policy-decision evaluation alone (target p95 < 20 ms).
            for hdr, label in (("X-PDP-Time-Ms", "authz pipeline: attrs + PDP + audit (X-PDP-Time-Ms)"),
                               ("X-PDP-Eval-Ms", "PDP decision only (X-PDP-Eval-Ms)")):
                v = r.headers.get(hdr)
                if v is not None:
                    events.request.fire(request_type="PDP", name=label, response_time=float(v),
                                        response_length=0, exception=None, context={})
        except Exception as e:  # noqa: BLE001
            _fire("POST /files/{id}/access [permit] end-to-end", started, exc=e)

    @task(2)
    def denied_access(self):
        if self.carol is None:
            return
        started = time.perf_counter()
        try:
            self.carol.access(self.file_id, intent="view")
            # Reaching here means the PDP wrongly permitted -> record as failure.
            _fire("POST /files/{id}/access [deny]", started,
                  exc=AssertionError("unexpected PERMIT for denied subject"))
        except Exception:
            # Expected 403 — the decision was made, so this is a successful measurement.
            _fire("POST /files/{id}/access [deny]", started)
