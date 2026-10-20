// STREAM-style chunked AEAD — byte-identical to crypto/ztv_crypto/chunks.py
import { concat, u32be, utf8, uuidBytes, toBuf } from "./encoding";

export const CHUNK_SIZE = 4 * 1024 * 1024;
export const TAG_SIZE = 16;
export const NONCE_PREFIX_SIZE = 8;
const AAD_DOMAIN = utf8("ZTV1");

export function nonceForChunk(prefix: Uint8Array, index: number): Uint8Array {
  if (prefix.length !== NONCE_PREFIX_SIZE) throw new Error("nonce prefix must be 8 bytes");
  return concat(prefix, u32be(index));
}

/** aad(i) = "ZTV1" || file_id(16) || u32be(version) || u32be(index) || u8(final) */
export function aadForChunk(fileId: string, version: number, index: number, final: boolean): Uint8Array {
  return concat(AAD_DOMAIN, uuidBytes(fileId), u32be(version), u32be(index), new Uint8Array([final ? 1 : 0]));
}

export async function importDek(dek: Uint8Array, extractable = false): Promise<CryptoKey> {
  if (dek.length !== 32) throw new Error("DEK must be 32 bytes");
  return crypto.subtle.importKey("raw", toBuf(dek), { name: "AES-GCM", length: 256 }, extractable, ["encrypt", "decrypt"]);
}

export async function encryptChunk(
  dek: CryptoKey,
  prefix: Uint8Array,
  fileId: string,
  version: number,
  index: number,
  plaintext: Uint8Array,
  final: boolean,
): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toBuf(nonceForChunk(prefix, index)), additionalData: toBuf(aadForChunk(fileId, version, index, final)), tagLength: 128 },
    dek,
    toBuf(plaintext),
  );
  return new Uint8Array(ct);
}

/** Throws (OperationError) on any tag failure — callers MUST abort the whole stream. */
export async function decryptChunk(
  dek: CryptoKey,
  prefix: Uint8Array,
  fileId: string,
  version: number,
  index: number,
  ciphertext: Uint8Array,
  final: boolean,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBuf(nonceForChunk(prefix, index)), additionalData: toBuf(aadForChunk(fileId, version, index, final)), tagLength: 128 },
    dek,
    toBuf(ciphertext),
  );
  return new Uint8Array(pt);
}

export function chunkCountFor(size: number, chunkSize = CHUNK_SIZE): number {
  return size === 0 ? 1 : Math.ceil(size / chunkSize);
}
