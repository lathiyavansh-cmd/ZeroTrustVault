// Streaming decryption worker: fetch chunk -> verify Merkle leaf -> decrypt with AAD -> post plaintext (transferable).
// Aborts on the first GCM failure / merkle mismatch / chunk-count mismatch and reports the failing chunk index.
import { b64uDecode, equalBytes } from "../encoding";
import { decryptChunk, importDek } from "../chunks";
import { leafHash, merkleRootFromLeaves } from "../merkle";
import type { Manifest } from "../sign";

export interface DecryptStart {
  type: "start";
  dek: ArrayBuffer; // raw 32 bytes (transferred)
  manifest: Manifest;
  chunkUrls: string[];
}
export type DecryptMessage =
  | { type: "progress"; index: number; total: number; bytes: number }
  | { type: "chunk"; index: number; data: ArrayBuffer }
  | { type: "done"; merkleOk: true; chunkCount: number; bytes: number }
  | { type: "error"; stage: "fetch" | "count" | "merkle" | "gcm" | "root"; index: number; message: string };

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = async (ev: MessageEvent<DecryptStart>) => {
  const msg = ev.data;
  if (msg.type !== "start") return;
  const { manifest, chunkUrls } = msg;
  const post = (m: DecryptMessage, transfer: Transferable[] = []) => ctx.postMessage(m, transfer);
  try {
    if (chunkUrls.length !== manifest.chunk_count) {
      post({ type: "error", stage: "count", index: -1, message: `chunk count mismatch: manifest ${manifest.chunk_count}, server offered ${chunkUrls.length}` });
      return;
    }
    const dekBytes = new Uint8Array(msg.dek);
    const dek = await importDek(dekBytes);
    dekBytes.fill(0);
    const prefix = b64uDecode(manifest.nonce_prefix);
    const expectedRoot = b64uDecode(manifest.merkle_root);
    const leaves: Uint8Array[] = [];
    let total = 0;
    for (let i = 0; i < chunkUrls.length; i++) {
      let ct: Uint8Array;
      try {
        const r = await fetch(chunkUrls[i], { credentials: "omit" });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        ct = new Uint8Array(await r.arrayBuffer());
      } catch (e) {
        post({ type: "error", stage: "fetch", index: i, message: `chunk ${i} fetch failed: ${(e as Error).message}` });
        return;
      }
      leaves.push(await leafHash(ct));
      // Single-leaf trees: the leaf IS the root -> verify before decrypting.
      if (chunkUrls.length === 1 && !equalBytes(leaves[0], expectedRoot)) {
        post({ type: "error", stage: "merkle", index: i, message: `chunk ${i}: merkle leaf does not match manifest root` });
        return;
      }
      let pt: Uint8Array;
      try {
        pt = await decryptChunk(dek, prefix, manifest.file_id, manifest.version, i, ct, i === chunkUrls.length - 1);
      } catch {
        post({ type: "error", stage: "gcm", index: i, message: `chunk ${i}: AES-GCM authentication failed (tampered, reordered or truncated)` });
        return;
      }
      total += pt.length;
      const buf = pt.buffer as ArrayBuffer;
      post({ type: "chunk", index: i, data: buf }, [buf]);
      post({ type: "progress", index: i, total: chunkUrls.length, bytes: total });
    }
    const root = await merkleRootFromLeaves(leaves);
    if (!equalBytes(root, expectedRoot)) {
      post({ type: "error", stage: "root", index: -1, message: "merkle root does not match the signed manifest" });
      return;
    }
    if (total !== manifest.size) {
      post({ type: "error", stage: "count", index: -1, message: `plaintext size ${total} != manifest size ${manifest.size}` });
      return;
    }
    post({ type: "done", merkleOk: true, chunkCount: chunkUrls.length, bytes: total });
  } catch (e) {
    post({ type: "error", stage: "gcm", index: -1, message: (e as Error).message });
  }
};
