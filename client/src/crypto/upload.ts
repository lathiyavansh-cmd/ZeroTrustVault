// Main-thread streaming upload: read the File in 4 MiB slices, encrypt (STREAM), hash leaves, PUT each chunk
// with a freshly minted per-request DPoP proof, then build + sign the manifest and wrap the DEK for the owner.
import { CHUNK_SIZE, chunkCountFor, encryptChunk, importDek } from "./chunks";
import { leafHash, merkleRootFromLeaves } from "./merkle";
import { b64u, nowIso, randomBytes } from "./encoding";
import { signManifest, type Manifest } from "./sign";
import { wrapDek, type WrapRecord } from "./wrap";
import type { UserKeys } from "./keys";
import { api } from "../api/client";

export interface UploadProgress {
  index: number;
  total: number;
  bytes: number;
}

export interface UploadResult {
  file_id: string;
  version: number;
  manifest: Manifest;
  wrapped_dek: WrapRecord;
}

export async function uploadFile(
  file: File,
  classification: string,
  keys: UserKeys,
  ownerId: string,
  onProgress: (p: UploadProgress) => void,
  existing?: { file_id: string },
): Promise<UploadResult> {
  const chunkCount = chunkCountFor(file.size);
  let fileId: string;
  let version: number;
  if (existing) {
    fileId = existing.file_id;
    const r = await api.post<{ version: number }>(`/api/files/${fileId}/versions`, { size: file.size, chunk_count: chunkCount, cipher: "AES-256-GCM" });
    version = r.version;
  } else {
    const r = await api.post<{ file_id: string; version: number }>("/api/files", { name: file.name, classification, size: file.size, chunk_count: chunkCount, cipher: "AES-256-GCM" });
    fileId = r.file_id;
    version = r.version;
  }
  const dekRaw = randomBytes(32);
  const dek = await importDek(dekRaw);
  const prefix = randomBytes(8);
  const leaves: Uint8Array[] = [];
  let sent = 0;
  for (let i = 0; i < chunkCount; i++) {
    const slice = file.slice(i * CHUNK_SIZE, Math.min(file.size, (i + 1) * CHUNK_SIZE));
    const pt = new Uint8Array(await slice.arrayBuffer());
    const ct = await encryptChunk(dek, prefix, fileId, version, i, pt, i === chunkCount - 1);
    leaves.push(await leafHash(ct));
    await api.putBytes(`/api/files/${fileId}/versions/${version}/chunks/${i}`, ct);
    sent += pt.length;
    onProgress({ index: i, total: chunkCount, bytes: sent });
  }
  const root = await merkleRootFromLeaves(leaves);
  const manifest = await signManifest(
    {
      file_id: fileId,
      version,
      name: file.name,
      size: file.size,
      classification,
      merkle_root: b64u(root),
      chunk_count: chunkCount,
      chunk_size: CHUNK_SIZE,
      cipher: "AES-256-GCM",
      nonce_prefix: b64u(prefix),
      owner_id: ownerId,
      timestamp: nowIso(),
    },
    keys.sig,
  );
  const wrapped = await wrapDek(dekRaw, keys.enc.publicKey, fileId, version);
  dekRaw.fill(0);
  return { file_id: fileId, version, manifest, wrapped_dek: wrapped };
}
