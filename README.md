# ZeroTrustVault

A complete, runnable, demo-ready **secure file-sharing and access-control system** built on two
independent planes that fail separately:

1. **Zero-trust control plane** (NIST SP 800-207) — authenticates and authorizes *every single request*
   against user + device + context. Bypassing it yields only ciphertext.
2. **Data-centric cryptographic plane** — every file is encrypted and signed **on the client** before it
   leaves the device. The server only ever stores ciphertext, wrapped keys and signed manifests. A stolen
   key is useless without passing the control plane to fetch the matching ciphertext.

Five principles are enforced throughout: **never trust the network; verify every request explicitly;
least privilege with time-boxed, default-deny grants; assume breach (server untrusted for confidentiality);
log everything tamper-evidently.**

The whole thing runs with one `docker compose up`, and a single `MODE` flag flips between a conventional
**baseline** design and full **ZeroTrustVault** mode so every security claim is shown as
*baseline fails → ZeroTrustVault blocks.*

## Architecture at a glance

```
Client zone (plaintext + private keys ONLY here)  ──TLS 1.3 + DPoP every request──▶  Control plane
  React/TS + Web Crypto (non-extractable keys)                                        Nginx (PEP edge, SPKI pin)
  Web Worker streaming encrypt/decrypt                                                FastAPI gateway (PEP)
                                                                                      RBAC+ABAC PDP (default-deny)
                                                                                      hash-chained audit log
Data plane (ciphertext only):  PostgreSQL 16 · MinIO (chunks) · Redis 7 (nonces/sessions/risk)
Offline:  Ed25519 Org Root (ca-signer) · write-once checkpoint store · live dashboard
```

See `docs/diagrams/` (Mermaid) for system architecture, end-to-end message flow, the per-request
authorization flowchart, and the 4-level key hierarchy. `docs/CONTRACT.md` is the authoritative
API + wire-format spec shared by all components.

## Repository layout

| Path | What |
|---|---|
| `crypto/` | Shared crypto core (`ztv_crypto`): chunked AEAD, Merkle, X25519/HKDF/AES-KW wrap, Ed25519 manifests/grants, Argon2id, offline Org-CA CLI (`ztv-ca`), audit chain + verifier (`ztv-audit-verify`), DPoP, and the headless Python client. Only NIST/IETF primitives. |
| `server/` | FastAPI control plane + data plane, PDP, audit service, seed script, tests. |
| `client/` | React + TypeScript app, Web Crypto engine, Web Worker streaming decryption, live dashboard. |
| `attack-lab/` | The six attacks, baseline-vs-ZTV, one-command runner. |
| `eval/` | Metrics harness, Locust load test, primitive benchmark (RSA vs EC) with CSV + charts. |
| `docs/` | Contract, diagrams, compliance mapping. |
| `infra/` | Docker Compose, Nginx TLS config, dev PKI generator, GitHub Actions. |
| `seed/` | Seed org data + generated dev credentials/keys (never real secrets). |

## Quick start

Requirements: Docker Desktop (Compose v2). Nothing else needs installing to run the stack.

```bash
cp .env.example .env            # MODE=zerotrustvault by default
docker compose up -d --build    # builds api, web, starts postgres/redis/minio, generates dev PKI + offline org root
docker compose run --rm seed    # creates the org, users, keys, certs and sample files
```

Then open:

| | |
|---|---|
| **Web UI** | https://localhost:8443 (self-signed dev cert — accept the warning) |
| **API docs (OpenAPI)** | https://localhost:8443/api/docs |
| **MinIO console** | http://localhost:9001 (`ztv-minio` / `ztv-minio-dev-secret`) |

Seed logins are written to `seed/generated/credentials.json` (dev only). Summary: `alice` (research manager,
owns the files), `bob` (research analyst, Alice shares with him), `carol` (finance — the IDOR attacker),
`dan` (external auditor, 30-day expiry), `admin`. Passwords are of the form `Alice-Pass-123`; TOTP secrets
are generated into that file.

With GNU make (or run the underlying commands from the `Makefile` by hand on Windows):

```bash
make up            # build + start + seed
make attack-demo   # run all six attacks in BOTH modes and print the results table
make eval          # full evaluation harness (metrics + CSV/JSON in eval/results)
make bench         # RSA-3072 vs X25519/Ed25519 + client protection vs upload (CSV + charts)
make audit-verify  # recompute the audit hash chain and pinpoint any broken entry
make down          # stop and wipe volumes
```

## Switching modes

`MODE` picks the whole posture. Set it in `.env` and `docker compose up -d`, **or** switch the running
stack live (enabled by `ALLOW_RUNTIME_MODE_SWITCH=true` for the demo):

```bash
make mode-baseline   # conventional: password-only login, 30-day bearer tokens, server-side encryption, no signatures, plain logs
make mode-ztv        # full ZeroTrustVault
```

The attack runner switches modes itself, so `make attack-demo` shows both columns without any manual step.

## The attack lab

`make attack-demo` runs each attack twice (baseline, then ZeroTrustVault) and prints a table; every row
must read *baseline succeeded → ZeroTrustVault blocked*.

| # | Attack | Baseline | ZeroTrustVault |
|---|---|---|---|
| 1 | Unauthorized file access (IDOR) | another department's file is returned | 403 + alert; a leaked storage URL yields only ciphertext |
| 2 | Stolen credentials | leaked password logs in on a new device | blocked at MFA; a replayed token fails DPoP from another machine |
| 3 | Man-in-the-middle | proxy reads/alters traffic | rogue-CA proxy refused by pinning; ciphertext only; any change fails the GCM tag/signature |
| 4 | File tampering | altered stored file is served and trusted | byte flip / chunk swap / truncation refused by the client + logged |
| 5 | Replay | captured request re-sent succeeds | 401 replayed nonce (DPoP nonce + 60 s window + 5 min token) |
| 6 | Insider / compromised server | DB + bucket dump reveals plaintext; log edited silently | dump is all ciphertext/wrapped keys; edited log row flagged at the exact entry |

## Offline Org CA (simulated)

The Ed25519 organization root lives in `infra/keys/org_root.json` and is **only** read by the `ztv-ca`
CLI / the `ca-signer` container — never by the API. Enrolment uploads a cert request; an admin confirms the
key fingerprint out-of-band (the admin UI, or `POST /api/admin/cert-requests/{id}/confirm`); the offline
signer then issues an Org-root-signed certificate. Sign a request by hand:

```bash
make ca-approve REQ=<request_id> FP="A1B2 C3D4 ...">   # fingerprint shown in the Enrol UI
```

## Evaluation targets

`make eval` / `make bench` measure and report against these targets:

| Metric | Target |
|---|---|
| Attack success rate (baseline → ZTV) | 100% → 0% |
| Tamper detection (≥1000 bit-flips/swaps/truncations) | 100% detected |
| Replay rejection / false rejection | 100% rejected / < 0.1% false |
| Authorization decision latency (p95, 100 concurrent users) | < 20 ms (PDP) |
| Cryptographic overhead (client crypto vs upload, 100 Mbps) | < 5% |
| Revocation effect | denied on the next request |
| Audit integrity (random edits/deletions) | 100% detected, exact position |

## Verified results (clean `docker compose up` + seed, 2026-10-20, laptop Docker Desktop)

`make attack-demo` — every row is *baseline succeeded → ZeroTrustVault blocked*:

| Attack | Baseline | ZeroTrustVault | Blocked by |
|---|---|---|---|
| a1 IDOR | SUCCEEDED | BLOCKED | PDP default-DENY (no grant, dept/clearance) |
| a2 stolen credentials | SUCCEEDED | BLOCKED | MFA step-up + DPoP cnf.jkt binding |
| a3 MITM / rogue CA | SUCCEEDED | BLOCKED | server SPKI pinning + AEAD/manifest integrity |
| a4 tamper (flip/swap/truncate) | SUCCEEDED | BLOCKED | AES-GCM tag + AAD + signed Merkle root, ALERT logged |
| a5 replay | SUCCEEDED | BLOCKED | single-use DPoP jti + 60 s iat window |
| a6 insider dump + log edit | SUCCEEDED | BLOCKED | E2E AEAD at rest + hash-chained signed audit log (exact seq flagged) |

`make eval` (`eval/results/eval_metrics.json`):

| Metric | Result | Target |
|---|---|---|
| Attack success rate | baseline 1.0 → ZTV 0.0 | 100% → 0% |
| Tamper detection (1,000 randomized flips/swaps/truncations/drops) | 100% | 100% |
| Replay rejection / false rejection (1,000 + 1,000) | 100% / 0.000% | 100% / < 0.1% |
| PDP decision latency p50/p95 (`X-PDP-Eval-Ms`) | 0.021 / 0.027 ms | p95 < 20 ms |
| Authz pipeline p95 (attrs + PDP + chained audit write) | 4.2 ms | info |
| End-to-end access p95 (TLS + DPoP + PEP + PDP + audit + URL minting) | 10.7 ms | info |
| Revocation effect | denied on the next request | next request |
| Audit integrity (500 random edits/deletes) | 100% detected, 100% exact position | 100% exact |

Locust, 100 concurrent users for 45 s through the nginx edge with full DPoP round-trips
(`eval/results/locust_stats.csv`): 16,468 measurements, 0 failures, 368 req/s aggregate; the PDP decision
stayed sub-millisecond at that concurrency, while the end-to-end median rose to ~310 ms because every
decision is written through a strictly serialized hash chain on a single API worker (a deliberate
integrity-over-throughput trade-off; scale with more workers and chain batching if needed).

`make bench` (`eval/results/bench_*.csv/png`): X25519/Ed25519 key-gen is ~5,000× faster than RSA-3072
and signing ~30× faster; client-side protection is 1–5% of upload time at 100 Mbps across 1–128 MB.

Test suites: crypto core 11/11, server 26/26 (incl. live e2e), client cross-implementation vectors 18/18.

## Browser-only steps

WebAuthn passkeys and non-extractable Web Crypto keys run in the real browser UI. Where a step can't run
headless, the attack lab and eval harness use the headless Python client (`ztv_crypto.headless_client`) over
TOTP + a file-based device key as a clearly-labelled scripted fallback, while the full passkey flow stays
available in the UI. See `client/README.md` for the Vite dev server and `npm test` cross-implementation vectors.

## Explicitly out of scope

Not solved here, by design: malware on an already-unlocked authorized device; physical attacks; volumetric
DDoS; browser-crypto side channels; screen-photographing (deterred via watermarking + logging only).

## Known limitations & mitigations

| Limitation | Mitigation in this system |
|---|---|
| Forgotten passphrase loses the sealed private keys | optional 2-of-3 Shamir escrow of the KEK blob among recovery officers (design hook) |
| Metadata (file names, sizes, sharing graph) is visible to the server | minimize stored metadata + optional size-bucket padding |
| A revoked user keeps copies they already decrypted | view-only watermarked mode + access logging; hard re-key stops *future* access |
| Large-file crypto in the browser | 4 MiB chunked streaming in Web Workers (keeps overhead < 5%) |
| Client/server clock skew breaks DPoP | ±60 s window + nonce cache + `X-Server-Time` in every response |
| In-process JSON PDP vs a full policy engine | clean `PolicyDecisionPoint` seam; `OpaPDP` drops in Open Policy Agent via `OPA_URL` |

## Security notes

All credentials, keys and certificates in this repo are **dev-only** and generated programmatically
(`infra/keys/`, `infra/certs/`, `seed/generated/`), listed in `.gitignore`. The baseline mode exists only to
demonstrate attacks and must never be used for real data.
