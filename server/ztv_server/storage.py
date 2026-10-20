"""MinIO object storage: ciphertext chunks, baseline plaintext-encrypted blobs, audit checkpoints."""
from __future__ import annotations

import asyncio
import io
import json
from typing import Iterator

from minio import Minio
from minio.error import S3Error

from .config import settings


def chunk_key(file_id: str, version: int, index: int) -> str:
    return f"files/{file_id}/v{version}/{index:06d}"


class Storage:
    def __init__(self):
        self.client = Minio(settings.MINIO_ENDPOINT, access_key=settings.MINIO_ACCESS_KEY, secret_key=settings.MINIO_SECRET_KEY, secure=False)
        self.bucket = settings.MINIO_BUCKET
        self.audit_bucket = settings.MINIO_AUDIT_BUCKET

    # -- sync helpers (run in threads) --
    def _ensure_buckets(self) -> None:
        for b in (self.bucket, self.audit_bucket):
            if not self.client.bucket_exists(b):
                self.client.make_bucket(b)

    def _put(self, bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.client.put_object(bucket, key, io.BytesIO(data), len(data), content_type=content_type)

    def _get(self, bucket: str, key: str) -> bytes:
        resp = self.client.get_object(bucket, key)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()

    def _exists(self, bucket: str, key: str) -> bool:
        try:
            self.client.stat_object(bucket, key)
            return True
        except S3Error:
            return False

    def _delete_prefix(self, bucket: str, prefix: str) -> int:
        n = 0
        for obj in list(self.client.list_objects(bucket, prefix=prefix, recursive=True)):
            self.client.remove_object(bucket, obj.object_name)
            n += 1
        return n

    # -- async API --
    async def ensure_buckets(self) -> None:
        await asyncio.to_thread(self._ensure_buckets)

    async def put_chunk(self, file_id: str, version: int, index: int, data: bytes) -> None:
        await asyncio.to_thread(self._put, self.bucket, chunk_key(file_id, version, index), data)

    async def get_chunk(self, file_id: str, version: int, index: int) -> bytes:
        return await asyncio.to_thread(self._get, self.bucket, chunk_key(file_id, version, index))

    async def chunk_exists(self, file_id: str, version: int, index: int) -> bool:
        return await asyncio.to_thread(self._exists, self.bucket, chunk_key(file_id, version, index))

    async def missing_chunks(self, file_id: str, version: int, count: int) -> list[int]:
        return [i for i in range(count) if not await self.chunk_exists(file_id, version, i)]

    async def delete_version(self, file_id: str, version: int) -> int:
        return await asyncio.to_thread(self._delete_prefix, self.bucket, f"files/{file_id}/v{version}/")

    async def delete_file(self, file_id: str) -> int:
        n = await asyncio.to_thread(self._delete_prefix, self.bucket, f"files/{file_id}/")
        n += await asyncio.to_thread(self._delete_prefix, self.bucket, f"baseline/{file_id}")
        return n

    async def put_baseline(self, file_id: str, data: bytes) -> None:
        await asyncio.to_thread(self._put, self.bucket, f"baseline/{file_id}", data)

    async def get_baseline(self, file_id: str) -> bytes:
        return await asyncio.to_thread(self._get, self.bucket, f"baseline/{file_id}")

    async def put_checkpoint(self, cp: dict) -> None:
        key = f"cp-{int(cp['seq']):010d}.json"
        await asyncio.to_thread(self._put, self.audit_bucket, key, json.dumps(cp, sort_keys=True).encode(), "application/json")

    async def list_checkpoints(self) -> list[dict]:
        def _list() -> list[dict]:
            out = []
            for obj in self.client.list_objects(self.audit_bucket, prefix="cp-", recursive=True):
                out.append(json.loads(self._get(self.audit_bucket, obj.object_name)))
            return sorted(out, key=lambda c: int(c["seq"]))

        return await asyncio.to_thread(_list)


_storage: Storage | None = None


def storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage
