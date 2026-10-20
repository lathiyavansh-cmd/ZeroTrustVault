"""Argon2id: client KEK derivation (m=64 MiB, t=3, p=1) and server password hashing (OWASP m=19 MiB, t=2, p=1)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import hash_secret_raw


@dataclass(frozen=True)
class Argon2Params:
    memory_kib: int
    time_cost: int
    parallelism: int


CLIENT_ARGON2 = Argon2Params(memory_kib=64 * 1024, time_cost=3, parallelism=1)
SERVER_ARGON2 = Argon2Params(memory_kib=19 * 1024, time_cost=2, parallelism=1)


def derive_kek(passphrase: str, salt: bytes, params: Argon2Params = CLIENT_ARGON2) -> bytes:
    """KEK_user = Argon2id(passphrase, salt) -> 32 bytes.  Identical to hash-wasm argon2id in the browser."""
    if len(salt) < 16:
        raise ValueError("salt must be >= 16 bytes")
    return hash_secret_raw(passphrase.encode("utf-8"), salt, time_cost=params.time_cost, memory_cost=params.memory_kib, parallelism=params.parallelism, hash_len=32, type=Type.ID)


_server_hasher = PasswordHasher(time_cost=SERVER_ARGON2.time_cost, memory_cost=SERVER_ARGON2.memory_kib, parallelism=SERVER_ARGON2.parallelism, hash_len=32, salt_len=16, type=Type.ID)


def hash_password(password: str) -> str:
    return _server_hasher.hash(password)


def verify_password(encoded_hash: str, password: str) -> bool:
    try:
        return _server_hasher.verify(encoded_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def new_salt() -> bytes:
    return os.urandom(16)
