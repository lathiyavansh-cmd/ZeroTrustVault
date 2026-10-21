# Testing and verification

## Test suites
| Suite | Result |
|-------|--------|
| Crypto core | 11/11 passing |
| Server (including live end-to-end) | 26/26 passing |
| Client cross-implementation vectors | 18/18 passing |

## Commands
make up            # build, start and seed the stack
make attack-demo   # run all six attacks in baseline and ZeroTrustVault modes
make eval          # metrics harness, results in eval/results
make bench         # RSA-3072 vs X25519/Ed25519 benchmark
make audit-verify  # recompute the audit hash chain
make down          # stop and wipe volumes

On Windows without GNU make, run the underlying commands from the Makefile by hand.

## Client tests
See client/README.md. Run `npm test` for the cross-implementation vectors.

## Security test goals
- Attack success rate: baseline 100% -> ZeroTrustVault 0%
- Tamper detection: 100% over at least 1,000 randomized attempts
- Replay rejection: 100%, with under 0.1% false rejection
- PDP decision latency: p95 under 20 ms
- Audit integrity: 100% of edits detected at the exact entry
