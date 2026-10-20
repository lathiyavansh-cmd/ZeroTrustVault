# ZeroTrustVault — Wire-format & API contract (v1)

This is the single source of truth shared by `/crypto` (Python core + headless client),
`/server` (FastAPI), `/client` (React/TS) and `/attack-lab`.  Both the Python and TypeScript
crypto engines MUST produce byte-identical outputs for the formats below.

## 0. Encoding rules
* `b64u` = base64url **without padding**.
* `canonical_json(obj)` = JSON with keys sorted recursively, no whitespace, UTF-8, no floats
  (ints, strings, bools, null, arrays, objects only). Python: `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`.
  TS: recursive sort + `JSON.stringify`.
* Timestamps: ISO-8601 UTC, seconds precision, `Z` suffix (`2026-10-20T14:03:00Z`).
* UUIDs are lowercase hyphenated strings; where bytes are needed, the 16 raw bytes.
* All signatures use **domain separation**: `sign(domain_bytes || canonical_json(body))`.

| Object | Domain prefix (bytes) | Signer |
|---|---|---|
| user certificate | `ZTV-user-cert-v1\0` | Org root Ed25519 (offline) |
| file manifest | `ZTV-manifest-v1\0` | owner Ed25519 |
| share grant | `ZTV-grant-v1\0` | owner Ed25519 |
| audit checkpoint | `ZTV-audit-checkpoint-v1\0` | audit Ed25519 (server) |

## 1. Key hierarchy
| Level | Key | Where | Format |
|---|---|---|---|
| 0 | Org root, Ed25519 | `infra/keys/org_root.json` — loaded ONLY by `ztv-ca` CLI / `ca-signer` container. Public key pinned in client (`VITE_ORG_ROOT_PK`) and server config. | `{"kty":"Ed25519","sk":b64u(pkcs8),"pk":b64u(raw32)}` |
| 1 | User enc key X25519 + sig key Ed25519 | generated client-side; private halves sealed under `KEK_user` (see §2) and ONLY the blob is uploaded | public: `b64u(raw 32 bytes)` each |
| 1 | Device key ECDSA P-256 | **non-extractable** Web Crypto key in IndexedDB (browser) / PEM file (headless) | public JWK `{"kty":"EC","crv":"P-256","x","y"}` |
| 2 | Per-file-version DEK, 32 random bytes | client memory only; wrapped per recipient | wrap record §3 |
| 3 | Chunk AEAD | AES-256-GCM (default) or CHACHA20-POLY1305 | §4 |

## 2. Sealed private-key blob (`KEK_user = Argon2id`)
Client params **m = 65536 KiB (64 MiB), t = 3, p = 1, hashLen 32**; salt 16 random bytes.
```
{"v":1,"kdf":{"name":"argon2id","m":65536,"t":3,"p":1,"salt":b64u},
 "cipher":"AES-256-GCM","iv":b64u(12 bytes),"ct":b64u}
ct = AES-256-GCM(key=KEK, iv, plaintext=canonical_json({"enc_sk":b64u(pkcs8 DER),"sig_sk":b64u(pkcs8 DER)}), aad="ZTV-keyblob-v1")
```
Server password hashing (separate from KEK): Argon2id m=19456 KiB, t=2, p=1.

## 3. DEK wrapping
Primary (`alg = "X25519-HKDF-SHA256-A256KW"`):
```
esk/epk  = fresh X25519 ephemeral pair (discarded after use)
shared   = X25519(esk, recipient_enc_pk)
KEK_wrap = HKDF-SHA256(ikm=shared, salt=<empty>, info = "ZTV-DEK-wrap-v1" || file_id(16 bytes) || version(u32 BE), L=32)
wrapped  = AES-KW(KEK_wrap, DEK)                       -> 40 bytes
record   = {"alg":"X25519-HKDF-SHA256-A256KW","epk":b64u(epk raw32),"wrapped":b64u(wrapped)}
```
Baseline for benchmarks only: `{"alg":"RSA-OAEP-3072-SHA256","wrapped":b64u}` (OAEP with SHA-256 + MGF1-SHA256).

## 4. Chunk encryption (STREAM)
* `chunk_size = 4194304` (4 MiB). The last chunk may be shorter; an empty file is ONE empty chunk.
* `nonce_prefix` = 8 random bytes per file version. `nonce(i) = nonce_prefix || u32be(i)`.
* `aad(i) = "ZTV1" || file_id(16 raw UUID bytes) || u32be(version) || u32be(i) || u8(final ? 1 : 0)`.
* `ct_i = AEAD.encrypt(key=DEK, nonce(i), plaintext_i, aad(i))` → ciphertext || 16-byte tag (Web Crypto and `cryptography` both append the tag).
* Storage: one object per chunk: `files/{file_id}/v{version}/{i:06d}`.
* Decrypt aborts on the first tag failure; also reject if chunk count ≠ `manifest.chunk_count`.

## 5. Merkle tree & manifest
* `leaf_i = SHA-256(0x00 || ct_i)`; `node = SHA-256(0x01 || left || right)`; odd node promoted unchanged; root of a single leaf is the leaf.
* Manifest body (exact field set, signed by owner Ed25519 with the manifest domain):
```
{"file_id","version"(int),"name","size"(int plaintext bytes),"classification","merkle_root":b64u,
 "chunk_count"(int),"chunk_size"(int),"cipher","nonce_prefix":b64u,"owner_id","timestamp"}
+ "signature": b64u(64 bytes)
```
`classification ∈ {"PUBLIC","INTERNAL","CONFIDENTIAL","SECRET"}` (levels 0..3).

## 6. User certificate (issued offline by Org CA)
```
{"serial","user_id","username","enc_pk":b64u,"sig_pk":b64u,"iat","exp","issuer":"ztv-org-root"} + "signature"
fingerprint = upper-hex SHA-256(enc_pk_raw || sig_pk_raw)[:32] in 8 groups of 4 ("A1B2 C3D4 ...")
```
Clients MUST verify a recipient's cert against the **pinned** org root before wrapping a DEK for them.

## 7. Share grant (signed by owner)
```
{"grant_id","file_id","owner_id","recipient_id","rights":["view"]|["view","download"],
 "expires_at":iso,"max_downloads":int,"required_posture":"any"|"registered"|"trusted","issued_at":iso} + "signature"
```

## 8. Audit chain
`h_0 = SHA-256("ZTV-AUDIT-GENESIS")`; `h_i = SHA-256(h_{i-1} || canonical_json({seq,ts,actor,action,resource,decision,reason,ip,device,details}))`.
Checkpoint `{"seq","hash":b64u,"ts"} + signature` every 100 entries or 5 minutes, written to the DB table AND to the
write-once bucket `audit-checkpoints` (object `cp-{seq:010d}.json`). `decision ∈ {PERMIT, DENY, ALERT, INFO}`.

## 9. DPoP (RFC 9449) and tokens
* Proof JWT: header `{"typ":"dpop+jwt","alg":"ES256","jwk":{...}}`, claims `{"jti","htm","htu","iat","ath"?}`.
  `htu` = `scheme://host[:port]/path` (no query). `ath = b64u(SHA-256(access_token))`.
* Headers on every protected request (ZTV mode): `Authorization: DPoP <access_token>` and `DPoP: <proof>`.
* Server checks (in order, each failure = 401, logged): token signature (EdDSA, server key) → token `exp` (5 min) →
  session alive in Redis (revocable) → proof signature → `htm/htu` → `iat` within ±60 s → `jti` unseen (Redis SETNX, TTL 120 s) → `ath` → `cnf.jkt == proof thumbprint`.
* Access-token claims: `{"iss":"ztv","sub":user_id,"sid":session_id,"dev":device_id,"iat","exp","cnf":{"jkt"},"amr":[...]}`.
* Refresh token: opaque, 8 h, device-bound (stored in Redis with jkt). `POST /api/auth/refresh` requires a DPoP proof with the same key.
* **Baseline mode**: `Authorization: Bearer <opaque token>` valid 30 days, not device-bound, no DPoP, no replay protection.
* Every response carries `X-Server-Time: <unix seconds>` so clients can correct skew.

## 10. HTTP API (prefix `/api`, served at `https://localhost:8443` by nginx → `api:8000` over mTLS)
Error body is always generic for authz failures: `{"error":"forbidden"}` (403) / `{"error":"unauthorized","code":"<short code>"}` (401). The reason is only in the audit log.

### Auth / devices
| Method & path | Body → Response |
|---|---|
| `POST /auth/login` | `{username,password,device:{jwk,name,posture:"registered"|"trusted"}}` → ZTV: `{"status":"mfa_required","login_ticket","methods":["totp","webauthn"]}`; baseline: `{"status":"ok","token_type":"Bearer","access_token","user"}` |
| `POST /auth/mfa/totp` | `{login_ticket,code}` → `{"status":"ok","token_type":"DPoP","access_token","refresh_token","expires_in":300,"user":{id,username,role,department,clearance},"device_id","risk":{score,level}}` |
| `POST /auth/webauthn/register/options` (auth) / `POST /auth/webauthn/register/verify` `{credential}` / `POST /auth/webauthn/login/options` `{login_ticket}` / `POST /auth/webauthn/login/verify` `{login_ticket,credential}` | py_webauthn JSON; login/verify returns the same payload as `/auth/mfa/totp` |
| `POST /auth/refresh` (DPoP proof, no token) | `{refresh_token}` → `{access_token,expires_in}` |
| `POST /auth/step-up` (auth) | `{code}` → `{"elevated_until":iso}` (fresh MFA for high-risk sessions) |
| `POST /auth/logout` (auth) | → 204 (session + refresh token revoked) |
| `GET /auth/me` (auth) | → `{user, device, session:{risk,elevated_until,amr}}` |
| `POST /auth/totp/setup` (auth) → `{secret,otpauth_uri}`; `POST /auth/totp/confirm {code}` → 204 | |
| `GET /devices` (auth) → `[{id,name,jkt,posture,created_at,last_seen}]`; `DELETE /devices/{id}` → 204 (device loss: revokes sessions) | |

### Keys / directory
| | |
|---|---|
| `GET /keys/blob` (auth) → sealed blob or 404; `PUT /keys/blob` `{blob}` → 204 | |
| `POST /keys/cert-request` (auth) `{enc_pk,sig_pk}` → `{request_id,fingerprint,status:"pending"}` | |
| `GET /keys/cert-request/{id}` (auth) → `{status:"pending"|"confirmed"|"issued",fingerprint,cert?}` | |
| `GET /keys/directory` (auth) `?q=` → `[{user_id,username,department,role,has_cert}]` | |
| `GET /keys/directory/{user_id}` (auth) → `{user_id,username,cert}` (404 if none) | |
| `GET /keys/org-root` → `{pk}` (informational; clients compare with their pinned copy and refuse on mismatch) | |

### Files
| | |
|---|---|
| `POST /files` (auth) `{name,classification,size,chunk_count,cipher}` → `{file_id,version:1}` | |
| `PUT /files/{file_id}/versions/{v}/chunks/{i}` (auth, `application/octet-stream`) → 204 | |
| `POST /files/{file_id}/versions/{v}/finalize` (auth) `{manifest,wrapped_dek}` → `{file_id,version,status:"active"}`; server verifies the manifest signature against the owner's issued cert and that `chunk_count` objects exist | |
| `GET /files` (auth) → `[{file_id,name,classification,owner_id,owner_username,version,size,created_at,via:"owner"|"grant"}]` | |
| `GET /files/{file_id}` (auth) → metadata + `manifest` (PDP-checked) | |
| `POST /files/{file_id}/access` (auth) `{"intent":"view"|"download"}` → PERMIT: `{"version","manifest","wrapped_dek","chunk_urls":[...],"expires_in":60}`; DENY: 403 generic; step-up: 401 `{"error":"unauthorized","code":"step_up_required"}` | |
| `GET /blob/{token}` (NO auth: 60-second HMAC-signed URL) → ciphertext bytes of one chunk | |
| `POST /files/{file_id}/report-integrity` (auth) `{version,chunk_index,reason}` → 204, writes an `ALERT` audit entry | |
| `POST /files/{file_id}/versions` (auth, owner) `{size,chunk_count,cipher}` → `{version}` (hard revocation / re-key: upload chunks then finalize with `wrapped_deks:{user_id:record}`; old version chunks are deleted) | |
| `DELETE /files/{file_id}` (owner) → 204 | |
| Baseline only: `POST /files/upload` multipart `{file,name,classification}` → `{file_id}`; `GET /files/{file_id}/download` → plaintext | |

### Shares
| | |
|---|---|
| `POST /shares` (auth, owner) `{grant,wrapped_dek}` → `{grant_id}` (server verifies grant signature against owner cert) | |
| `GET /shares?file_id=` (auth) → `[grant + downloads_used]` | |
| `DELETE /shares/{grant_id}` (owner) → 204 = **soft revocation**: grant + wrapped DEK deleted, recipient's outstanding blob tokens for the file revoked; next request DENY | |

### Policy, admin, dashboard, audit
| | |
|---|---|
| `GET /policy` (auth) → policy JSON; `PUT /policy` (admin) | |
| `POST /admin/users` (admin) `{username,password,role,department,clearance,employment_end?}`; `GET /admin/users` | |
| `GET /admin/cert-requests?status=` ; `GET /admin/cert-requests/{id}` ; `POST /admin/cert-requests/{id}/confirm {fingerprint}` (admin UI = simulated out-of-band confirmation) ; `POST /admin/cert-requests/{id}/publish {cert}` (**X-Admin-Key** header — used by the offline `ca-signer`) | |
| `POST /admin/mode {mode}` (X-Admin-Key, only when `ALLOW_RUNTIME_MODE_SWITCH=true`) → `{mode}` ; `GET /mode` → `{mode}` | |
| `GET /dashboard/summary` (auth) → `{mode,decisions:{permit,deny,alerts},recent:[...],audit:{entries,last_checkpoint_seq,chain_ok,first_bad_seq},sessions_active}` | |
| `GET /audit/recent?limit=50` (auth; non-admins see only their own) ; `GET /audit/export` (X-Admin-Key or admin) → `{entries,checkpoints,audit_pk}` ; `GET /audit/verify` (auth) → ChainReport | |
| `GET /health` → `{status:"ok",mode,time}` | |

Admin auth: role `admin` with a normal session, OR header `X-Admin-Key: <ADMIN_API_KEY>` for the offline tools.

## 11. PDP attributes (collected by the PEP for every file access)
```
subject:     {id, username, role, department, clearance(0-3), employment_end, mfa_fresh(bool)}
device:      {id, posture, jkt, registered(bool)}
resource:    {file_id, owner_id, department, classification, level(0-3)}
environment: {ip, geo, hour_utc, risk_score(0-100), risk_level, mode}
grant:       {present, rights, expired, downloads_left, posture_ok, signature_ok}
```
Policy JSON (`seed/policy.json`) evaluates: deny-overrides, then first PERMIT, else **default DENY**.
Rule shape: `{"id","effect":"PERMIT"|"DENY","description","all":[{"attr":"subject.clearance","op":">=","value":"resource.level"}, ...]}`.
Supported ops: `==, !=, >=, <=, >, <, in, not_in, exists, true, false`; `value` may be a literal or a `"<path>"` reference.
Obligation: `risk_score >= 60` → `step_up_required` (401) unless `subject.mfa_fresh`; `>= 85` → DENY.
Risk signals (+points): new device 25, new IP 20, outside 07:00–21:00 UTC 15, ≥3 failed logins in 15 min 30, geo mismatch 30, `X-Demo-Risk: <n>` header adds `n` (demo only).

## 12. Modes
`MODE=zerotrustvault` (default) | `MODE=baseline`. Baseline = password-only login, 30-day bearer tokens, no DPoP/replay checks,
no PDP (any authenticated user may read any file by id), server-side AES-GCM with a static key from config (`BASELINE_SERVER_KEY`),
no manifest/grant signatures, audit rows without hash chain.

## 13. Seed org (see `seed/seed.json`)
Org **Acme Research Labs**; departments `research`, `finance`, `audit`; classification levels PUBLIC(0) INTERNAL(1) CONFIDENTIAL(2) SECRET(3).
| user | pw | role | dept | clearance | notes |
|---|---|---|---|---|---|
| admin | Admin-Pass-123 | admin | it | 3 | |
| alice | Alice-Pass-123 | manager | research | 3 | owner of research files |
| bob | Bob-Pass-123 | analyst | research | 2 | internal recipient |
| carol | Carol-Pass-123 | manager | finance | 2 | other department (IDOR victim/attacker) |
| dan | Dan-Pass-123 | auditor | audit | 2 | external auditor, employment_end = +30 days |
TOTP secrets are generated by the seed script and written to `seed/generated/credentials.json` (dev only).
Sample files: `q3-results.pdf` (CONFIDENTIAL, alice → shared with bob, view+download), `lab-notes.txt` (INTERNAL, alice),
`payroll.csv` (SECRET, carol). Every plaintext contains the marker string `ZTV-PLAINTEXT-MARKER` used by the attack lab.

## 14. Server implementation notes (additive; v1 contract unchanged)
* `GET /audit/verify` returns the ChainReport plus `unchained_entries`: rows written while the server was in
  baseline mode carry no `prev_hash`/`hash`. The chain state still advances through them, so they are reported
  as unchained rather than as a break; an edit to any row followed by chained rows is pinpointed at its exact seq.
* Policy rules may carry an optional `"any":[...]` group (OR) next to `"all"` (used for "same department OR auditor").
  The PEP also exposes `subject.employment_active`, `subject.cert_revoked`, `subject.has_cert`, `action.intent`.
* `POST /files/{id}/access` responses carry `X-PDP-Time-Ms` (attribute collection + PDP time) for the eval harness;
  `chunk_urls` are built from the request origin (`X-Forwarded-Proto/Host` or the direct API host), so they work
  both through nginx and against `https://api:8000`.
* Extra endpoints: `POST /audit/checkpoint` (admin; force a signed checkpoint), `POST /auth/webauthn/*` per §10.
* Login/MFA responses additionally include `session_id` and `risk.signals`; `GET /auth/me` includes `session.mode`.
* Blob-URL revocation uses per-(file,user) and per-file generation counters in Redis (`blobgen:*`) plus the `blobrev` set.
* `BASELINE_SERVER_KEY` must be 64 hex chars; any other value is hashed with SHA-256 to derive the 32-byte key
  (docker-compose's all-zero value is parsed by YAML as the integer 0 and therefore takes this path).
* Dev TLS certs now carry an Authority Key Identifier (required by OpenSSL 3.5 strict verification on the host).
