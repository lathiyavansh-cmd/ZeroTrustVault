# ZeroTrustVault — Standards & Compliance Mapping

This maps implemented features to the CISA Zero Trust Maturity Model (ZTMM v2.0) pillars, India's
DPDP Rules 2025, and the CERT-In 2022 Directions. It is a design-conformance map for the demo system,
not a legal certification.

## CISA Zero Trust Maturity Model — pillars

| Pillar | ZeroTrustVault implementation | Maturity |
|---|---|---|
| **Identity** | Argon2id passwords; TOTP + WebAuthn passkeys (phishing-resistant); every session bound to a device key via DPoP `cnf.jkt`; short-lived (5 min) access tokens; continuous re-verification each request; risk-based step-up MFA. | Advanced → Optimal |
| **Devices** | Per-device non-extractable key registered at enrolment; device posture (`any`/`registered`/`trusted`) is an ABAC attribute and a share-grant requirement; device loss revokes sessions; new-device access raises the risk score. | Advanced |
| **Networks** | TLS 1.3 only, HSTS, SPKI pinning on the client; mTLS between the Nginx PEP edge and the API; no plaintext ever on the wire; network is never trusted (confidentiality does not depend on it). | Advanced → Optimal |
| **Applications & Workloads** | Single PEP gateway in front of all APIs; default-deny PDP on every request; auto-generated OpenAPI; static analysis (Bandit + Semgrep) and a security test suite in CI; OPA seam for external policy. | Advanced |
| **Data** | Client-side encryption before data leaves the device; per-file-version AES-256 DEK wrapped per recipient (X25519→HKDF→AES-KW); classification labels drive clearance-based ABAC; signed manifests; the server stores only ciphertext, wrapped keys and sealed blobs. | Optimal |
| **Visibility & Analytics** | Tamper-evident hash-chained audit log with signed checkpoints to a write-once store; live dashboard of permits/denials/alerts, chain status and active sessions; every decision (allow and deny) logged with its reason. | Advanced → Optimal |
| **Governance (cross-cutting)** | Least-privilege, time-boxed signed grants with expiry and download limits; NIST SP 800-57 cryptoperiods; policy versioned in `seed/policy.json`. | Advanced |

## DPDP Rules 2025 (Digital Personal Data Protection)

| Obligation | Where satisfied |
|---|---|
| Encryption of personal data (at rest and in transit) | AES-256-GCM client-side at rest in MinIO; TLS 1.3 in transit; private keys sealed under Argon2id. The server never holds plaintext or usable private keys. |
| Access control / authorized processing only | Default-deny RBAC+ABAC PDP; signed, time-boxed share grants; per-request re-verification. |
| Access logs retained ≥ 1 year | `audit_entries` retains who/what/when/decision/reason (never content); retention configurable, default ≥ 365 days; chained and checkpoint-signed so retention is verifiable. |
| Erasure / data-principal rights | Soft revocation (instant grant + wrapped-key removal) and hard revocation (re-key to a new version); passphrase change re-seals only the key blob. |
| Breach containment | "Assume breach": a server or storage compromise yields only ciphertext and wrapped keys (attack #6 demonstrates this). |

## CERT-In 2022 Directions

| Requirement | Where satisfied |
|---|---|
| Logs retained within Indian jurisdiction for 180+ days | Audit log retention default ≥ 180 days (set ≥ 365 for DPDP); stored in the operator-controlled Postgres + write-once bucket. |
| Tamper-evident, integrity-protected logs | SHA-256 hash chain + Ed25519-signed checkpoints every 100 entries / 5 minutes; `ztv-audit-verify` pinpoints the exact altered/deleted entry (attack #6, eval "audit integrity"). |
| Evidence available for 6-hour incident reporting | `GET /api/audit/export` and the verifier produce a signed, position-precise integrity report on demand; the dashboard surfaces alerts in real time. |
| Accurate time | NTP-synced hosts; every API response carries `X-Server-Time`; DPoP enforces a ±60 s window so client/server clocks are reconciled. |

## NIST references
- **SP 800-207** Zero Trust Architecture — PE/PA/PEP split, per-request evaluation, policy inputs (subject, device, resource, environment).
- **SP 800-57** Key Management — cryptoperiods: org root 2 years, user keys 1 year / on device loss, per-file DEK per version.
- **SP 800-63B** Authentication — Argon2id memory-hard hashing, AAL2+ via TOTP/WebAuthn.
- **RFC 9449** DPoP, **RFC 5869** HKDF, **RFC 3394** AES-KW, **RFC 7748** X25519, **RFC 8032** Ed25519, **RFC 7638** JWK thumbprint.
