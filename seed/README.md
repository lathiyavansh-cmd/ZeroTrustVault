# Seed data

This folder holds the seed data used to populate a fresh ZeroTrustVault
environment for development and the attack-lab demo.

## What the seed step creates
Run `docker compose run --rm seed` to create the organization, users, keys,
certificates and sample files.

## Demo users
| User  | Role                | Purpose in the demo                                  |
|-------|---------------------|------------------------------------------------------|
| alice | Research manager    | Owns the sample files                                |
| bob   | Research analyst    | Alice shares files with him                          |
| carol | Finance             | Plays the attacker in the unauthorized-access (IDOR) attack |
| dan   | External auditor    | Time-boxed access, 30-day expiry                     |
| admin | Administrator       | Manages users and policies                           |

## Generated files
Credentials, TOTP secrets and keys are written to `seed/generated/`.
These are dev-only, are listed in `.gitignore`, and must never be committed.
