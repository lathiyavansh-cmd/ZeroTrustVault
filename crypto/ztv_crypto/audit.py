"""Tamper-evident audit log: SHA-256 hash chain + Ed25519-signed checkpoints.

h_0 = SHA-256("ZTV-AUDIT-GENESIS")
h_i = SHA-256(h_{i-1} || canonical_json(entry_i))        (entry_i excludes prev_hash/hash)
checkpoint = {"seq": i, "hash": b64u(h_i), "ts": iso}      signed with the audit Ed25519 key

Entries record who / what / when / decision / reason - never file content.
The verifier recomputes the chain and pinpoints the exact broken entry.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from cryptography.hazmat.primitives.asymmetric import ed25519

from .encoding import b64u, b64u_decode, canonical_json
from .sign import ed25519_sign, ed25519_verify, now_iso

GENESIS_HASH = hashlib.sha256(b"ZTV-AUDIT-GENESIS").digest()
CHECKPOINT_DOMAIN = b"ZTV-audit-checkpoint-v1\x00"
ENTRY_FIELDS = ("seq", "ts", "actor", "action", "resource", "decision", "reason", "ip", "device", "details")
CHECKPOINT_EVERY_ENTRIES = 100
CHECKPOINT_EVERY_SECONDS = 300


def entry_body(entry: dict) -> dict:
    return {f: entry.get(f) for f in ENTRY_FIELDS}


def entry_hash(prev_hash: bytes, entry: dict) -> bytes:
    return hashlib.sha256(prev_hash + canonical_json(entry_body(entry))).digest()


def chain_hash(entries: Iterable[dict]) -> bytes:
    h = GENESIS_HASH
    for e in entries:
        h = entry_hash(h, e)
    return h


def sign_checkpoint(seq: int, h: bytes, audit_sk: ed25519.Ed25519PrivateKey, ts: str | None = None) -> dict:
    body = {"seq": seq, "hash": b64u(h), "ts": ts or now_iso()}
    return {**body, "signature": ed25519_sign(audit_sk, CHECKPOINT_DOMAIN, body)}


def verify_checkpoint(cp: dict, audit_pk_raw: bytes) -> bool:
    try:
        body = {"seq": cp["seq"], "hash": cp["hash"], "ts": cp["ts"]}
        return ed25519_verify(audit_pk_raw, CHECKPOINT_DOMAIN, body, cp["signature"])
    except (KeyError, TypeError):
        return False


@dataclass
class ChainReport:
    ok: bool
    entries_checked: int
    checkpoints_checked: int
    first_bad_seq: int | None = None
    problem: str | None = None
    issues: list[str] = field(default_factory=list)
    last_hash: str | None = None

    def as_dict(self) -> dict:
        return {"ok": self.ok, "entries_checked": self.entries_checked, "checkpoints_checked": self.checkpoints_checked, "first_bad_seq": self.first_bad_seq, "problem": self.problem, "issues": self.issues, "last_hash": self.last_hash}


def verify_chain(entries: Sequence[dict], checkpoints: Sequence[dict] = (), audit_pk_raw: bytes | None = None) -> ChainReport:
    """Recompute the whole chain.  `entries` must be ordered by seq and carry stored `prev_hash`/`hash` (b64u).

    Detects: modified entry (hash mismatch), broken link (prev_hash mismatch), deleted entry
    (seq gap), truncated tail / rewritten history (checkpoint hash mismatch), forged checkpoint.
    """
    issues: list[str] = []
    first_bad: int | None = None
    problem: str | None = None

    def flag(seq: int, msg: str) -> None:
        nonlocal first_bad, problem
        issues.append(f"seq {seq}: {msg}")
        if first_bad is None:
            first_bad, problem = seq, msg

    prev = GENESIS_HASH
    expected_seq = 1
    computed: dict[int, bytes] = {}
    for e in entries:
        seq = int(e["seq"])
        if seq != expected_seq:
            if seq > expected_seq:
                flag(expected_seq, f"entry missing (deleted): expected seq {expected_seq}, found {seq}")
            else:
                flag(seq, f"out-of-order or duplicated seq (expected {expected_seq})")
            expected_seq = seq
        stored_prev = b64u_decode(e["prev_hash"]) if e.get("prev_hash") else None
        if stored_prev is not None and stored_prev != prev:
            flag(seq, "prev_hash does not link to previous entry (chain broken here)")
        h = entry_hash(prev, e)
        stored = b64u_decode(e["hash"]) if e.get("hash") else None
        if stored is None:
            flag(seq, "entry has no stored hash (unchained / baseline log)")
        elif stored != h:
            flag(seq, "stored hash does not match recomputed hash (entry modified)")
        computed[seq] = h
        prev = h
        expected_seq = seq + 1

    cps_checked = 0
    for cp in checkpoints:
        cps_checked += 1
        cseq = int(cp["seq"])
        if audit_pk_raw is not None and not verify_checkpoint(cp, audit_pk_raw):
            flag(cseq, "checkpoint signature invalid (forged checkpoint)")
            continue
        if cseq not in computed:
            flag(cseq, f"checkpoint references seq {cseq} but the log ends at {expected_seq - 1} (tail truncated)")
            continue
        if b64u_decode(cp["hash"]) != computed[cseq]:
            flag(cseq, "checkpoint hash does not match recomputed chain at this seq (history rewritten before checkpoint)")

    return ChainReport(ok=not issues, entries_checked=len(entries), checkpoints_checked=cps_checked, first_bad_seq=first_bad, problem=problem, issues=issues, last_hash=b64u(prev))


class HashChain:
    """In-memory chain builder (used by tests, the eval harness and the baseline comparison)."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.prev = GENESIS_HASH

    def append(self, **fields) -> dict:
        seq = len(self.entries) + 1
        entry = {"seq": seq, "ts": fields.pop("ts", now_iso()), **{f: fields.get(f) for f in ENTRY_FIELDS if f not in ("seq", "ts")}}
        h = entry_hash(self.prev, entry)
        entry["prev_hash"] = b64u(self.prev)
        entry["hash"] = b64u(h)
        self.entries.append(entry)
        self.prev = h
        return entry
