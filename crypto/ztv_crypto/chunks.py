"""Level-3 data protection: STREAM-style chunked AEAD.

* chunk size 4 MiB
* AES-256-GCM (default) or ChaCha20-Poly1305 (fallback for CPUs without AES-NI)
* 96-bit nonce = 8-byte random per-file prefix || 4-byte big-endian chunk counter
* associated data binds file-id, version, chunk index and a final-chunk flag so
  that reordering, truncation and cross-file splicing are detected.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 8
AAD_DOMAIN = b"ZTV1"
CIPHERS = {"AES-256-GCM": AESGCM, "CHACHA20-POLY1305": ChaCha20Poly1305}


def nonce_for_chunk(prefix: bytes, index: int) -> bytes:
    if len(prefix) != NONCE_PREFIX_SIZE:
        raise ValueError("nonce prefix must be 8 bytes")
    if not 0 <= index < 2**32:
        raise ValueError("chunk index out of range")
    return prefix + index.to_bytes(4, "big")


def aad_for_chunk(file_id: str, version: int, index: int, final: bool) -> bytes:
    """AAD = 'ZTV1' || file_id (16-byte UUID) || version u32 || index u32 || final u8."""
    return AAD_DOMAIN + uuid.UUID(file_id).bytes + version.to_bytes(4, "big") + index.to_bytes(4, "big") + bytes([1 if final else 0])


@dataclass
class ChunkCipher:
    dek: bytes
    nonce_prefix: bytes
    file_id: str
    version: int
    cipher: str = "AES-256-GCM"
    _aead: object = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self.dek) != 32:
            raise ValueError("DEK must be 256 bits")
        if len(self.nonce_prefix) != NONCE_PREFIX_SIZE:
            raise ValueError("nonce prefix must be 8 bytes")
        if self.cipher not in CIPHERS:
            raise ValueError(f"unsupported cipher {self.cipher}")
        self._aead = CIPHERS[self.cipher](self.dek)

    @classmethod
    def new(cls, file_id: str, version: int, cipher: str = "AES-256-GCM") -> "ChunkCipher":
        return cls(dek=os.urandom(32), nonce_prefix=os.urandom(NONCE_PREFIX_SIZE), file_id=file_id, version=version, cipher=cipher)

    def encrypt_chunk(self, index: int, plaintext: bytes, final: bool) -> bytes:
        return self._aead.encrypt(nonce_for_chunk(self.nonce_prefix, index), plaintext, aad_for_chunk(self.file_id, self.version, index, final))

    def decrypt_chunk(self, index: int, ciphertext: bytes, final: bool) -> bytes:
        """Raises cryptography.exceptions.InvalidTag on any tampering."""
        return self._aead.decrypt(nonce_for_chunk(self.nonce_prefix, index), ciphertext, aad_for_chunk(self.file_id, self.version, index, final))

    def encrypt_stream(self, plaintext_chunks: Iterable[bytes]) -> Iterator[bytes]:
        """Encrypt an iterable of plaintext chunks (each CHUNK_SIZE except the last)."""
        it = iter(plaintext_chunks)
        try:
            cur = next(it)
        except StopIteration:
            yield self.encrypt_chunk(0, b"", True)
            return
        index = 0
        while True:
            try:
                nxt = next(it)
            except StopIteration:
                yield self.encrypt_chunk(index, cur, True)
                return
            yield self.encrypt_chunk(index, cur, False)
            cur = nxt
            index += 1


def split_chunks(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[bytes]:
    if not data:
        return [b""]
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def encrypt_bytes(data: bytes, file_id: str, version: int, cipher: str = "AES-256-GCM", chunk_size: int = CHUNK_SIZE) -> tuple[ChunkCipher, list[bytes]]:
    cc = ChunkCipher.new(file_id, version, cipher)
    return cc, list(cc.encrypt_stream(split_chunks(data, chunk_size)))


def decrypt_chunks(cc: ChunkCipher, ciphertext_chunks: list[bytes], expected_count: int | None = None) -> bytes:
    """Decrypt all chunks; aborts on the first GCM tag failure or on truncation."""
    n = len(ciphertext_chunks)
    if expected_count is not None and n != expected_count:
        raise ValueError(f"truncated or padded file: expected {expected_count} chunks, got {n}")
    out = bytearray()
    for i, ct in enumerate(ciphertext_chunks):
        out += cc.decrypt_chunk(i, ct, final=(i == n - 1))
    return bytes(out)
