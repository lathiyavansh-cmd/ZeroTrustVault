# Attack lab

Each attack runs twice: once in baseline mode (a conventional design) and
once in ZeroTrustVault mode. Run all of them with `make attack-demo`.

| # | Attack | Baseline result | ZeroTrustVault result |
|---|--------|-----------------|-----------------------|
| 1 | Unauthorized access (IDOR) | Another department's file is returned | 403 and an alert; storage URL yields only ciphertext |
| 2 | Stolen credentials | Leaked password works on a new device | Blocked at MFA; replayed token fails DPoP |
| 3 | Man-in-the-middle | Proxy reads and alters traffic | Rogue-CA proxy refused by pinning; only ciphertext visible |
| 4 | File tampering | Altered file is served and trusted | Byte flip, chunk swap or truncation refused by the client |
| 5 | Replay | Captured request succeeds when re-sent | 401 replayed nonce |
| 6 | Insider or compromised server | DB and bucket dump reveals plaintext | Dump is all ciphertext; edited log row flagged at exact entry |

## Mode switching
make mode-baseline   # conventional posture
make mode-ztv        # full ZeroTrustVault
