# Online evaluation — PDP authz latency under load

Measures the policy-decision-point latency on `POST /api/files/{id}/access` under
100 concurrent users (≈80% authorized PERMIT, ≈20% cross-tenant DENY), each a full
DPoP round-trip through the nginx edge.

Prerequisite: the stack is up and seeded (`make up`).

One-line run (inside the attack-lab container, which has locust + the crypto core):

```bash
docker compose --profile attack run --rm attack-lab \
  locust -f /eval/online/locustfile.py --headless -u 100 -r 20 -t 1m --host https://localhost:8443
```

Or directly on the host (from the repo root, with the venv active):

```bash
locust -f eval/online/locustfile.py --headless -u 100 -r 20 -t 1m --host https://localhost:8443
```

Locust prints p50/p95/p99 per request type. Target: PDP **p95 < 20 ms**. The
`[permit]` and `[deny]` rows should both report decisions (a `[deny]` failure means
the PDP wrongly permitted a cross-tenant subject). Add `--csv eval/results/pdp_load`
to persist the stats.

The same latency number is also computed by `python /eval/run_eval.py --all`
(`authz_latency` metric) without locust, as a quick single-client check.
