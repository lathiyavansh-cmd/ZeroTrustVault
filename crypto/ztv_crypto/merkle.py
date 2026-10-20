"""SHA-256 Merkle tree over ciphertext chunks (domain-separated leaves and nodes)."""
from __future__ import annotations

import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(chunk_ciphertext: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + chunk_ciphertext).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_root_from_leaves(leaves: Sequence[bytes]) -> bytes:
    """Odd nodes are promoted unchanged to the next level (no duplication)."""
    if not leaves:
        raise ValueError("merkle tree needs at least one leaf")
    level = list(leaves)
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def merkle_root(ciphertext_chunks: Sequence[bytes]) -> bytes:
    return merkle_root_from_leaves([leaf_hash(c) for c in ciphertext_chunks])
