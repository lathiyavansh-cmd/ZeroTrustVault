# ZeroTrustVault — attack simulation results

**6/6 attacks PASS** (baseline SUCCEEDS and zerotrustvault BLOCKS).

| Attack | Baseline | ZeroTrustVault | Blocked by | PASS |
|---|---|---|---|---|
| Cross-tenant IDOR (`a1_idor`) | SUCCEEDED | BLOCKED | PDP default-DENY (no grant, dept/clearance mismatch) | ✅ |
| Stolen creds / new device (`a2_stolen_creds`) | SUCCEEDED | BLOCKED | MFA step-up + DPoP cnf.jkt binding | ✅ |
| MITM / rogue CA (`a3_mitm`) | SUCCEEDED | BLOCKED | server SPKI pinning + AEAD/manifest integrity | ✅ |
| Ciphertext tamper (flip/swap/truncate) (`a4_tamper`) | SUCCEEDED | BLOCKED | AES-GCM tag + AAD + signed Merkle root | ✅ |
| Request replay (`a5_replay`) | SUCCEEDED | BLOCKED | single-use DPoP jti + iat window | ✅ |
| Insider DB + store dump (`a6_insider`) | SUCCEEDED | BLOCKED | E2E AEAD at rest + hash-chained signed audit log | ✅ |

## Detail

### Cross-tenant IDOR (`a1_idor`)
- baseline: carol downloaded alice's file by id -> 200, marker recovered
- zerotrustvault: carol /access -> 403 (AccessDenied); leaked blob URL = ciphertext only (marker_in_blob=False)

### Stolen creds / new device (`a2_stolen_creds`)
- baseline: password-only login issued a bearer token; /download -> 200
- zerotrustvault: login returned mfa_required, no access token issued; token replay from attacker device -> 401

### MITM / rogue CA (`a3_mitm`)
- baseline: SIMULATED interception: baseline transfers plaintext end-to-end; marker observable on the wire=True
- zerotrustvault: rogue/untrusted CA refused at handshake (ConnectError); intercepted payload is ciphertext only (marker=True)

### Ciphertext tamper (flip/swap/truncate) (`a4_tamper`)
- baseline: flipped a stored byte; baseline served the object with no integrity check (status=False)
- zerotrustvault: all corruptions fail-closed: {'flip': 'IntegrityError', 'swap': 'IntegrityError', 'truncate': 'IntegrityError'}; report-integrity ALERT visible=True

### Request replay (`a5_replay`)
- baseline: captured bearer request replayed verbatim -> 200, 200
- zerotrustvault: first=200; jti replay -> 401; stale iat -> 401

### Insider DB + store dump (`a6_insider`)
- baseline: plaintext/editable at rest (marker_found=True); audit row edited, verify flagged nothing (undetected=True)
- zerotrustvault: grep over 6 objects found NO marker; edited audit seq 55 -> verify flagged first_bad_seq=55
