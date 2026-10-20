// DEK wrapping: X25519 ECDH (ephemeral) -> HKDF-SHA256 (empty salt) -> AES-KW — identical to wrap.py
import { b64u, b64uDecode, concat, u32be, utf8, uuidBytes, toBuf } from "./encoding";
import { ephemeralAgreementKey, type AgreementKey } from "./curves";

export const ALG_X25519 = "X25519-HKDF-SHA256-A256KW";
const HKDF_INFO_DOMAIN = utf8("ZTV-DEK-wrap-v1");

export interface WrapRecord {
  alg: string;
  epk: string;
  wrapped: string;
}

export function hkdfInfo(fileId: string, version: number): Uint8Array {
  return concat(HKDF_INFO_DOMAIN, uuidBytes(fileId), u32be(version));
}

async function kekFromShared(shared: Uint8Array, fileId: string, version: number): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", toBuf(shared), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: toBuf(hkdfInfo(fileId, version)) },
    ikm,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

export async function wrapDek(dek: Uint8Array, recipientPk: Uint8Array, fileId: string, version: number): Promise<WrapRecord> {
  if (dek.length !== 32) throw new Error("DEK must be 32 bytes");
  const eph = await ephemeralAgreementKey();
  const shared = await eph.ecdh(recipientPk);
  const kek = await kekFromShared(shared, fileId, version);
  shared.fill(0);
  const dekKey = await crypto.subtle.importKey("raw", toBuf(dek), { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey("raw", dekKey, kek, "AES-KW"));
  return { alg: ALG_X25519, epk: b64u(eph.publicKey), wrapped: b64u(wrapped) };
}

/** Returns the raw 32-byte DEK (extractable so it can be transferred to the decrypt worker). Throws on tamper. */
export async function unwrapDek(record: WrapRecord, recipient: AgreementKey, fileId: string, version: number): Promise<Uint8Array> {
  if (record.alg !== ALG_X25519) throw new Error(`unexpected wrap alg ${record.alg}`);
  const shared = await recipient.ecdh(b64uDecode(record.epk));
  const kek = await kekFromShared(shared, fileId, version);
  shared.fill(0);
  const dekKey = await crypto.subtle.unwrapKey("raw", toBuf(b64uDecode(record.wrapped)), kek, "AES-KW", { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  return new Uint8Array(await crypto.subtle.exportKey("raw", dekKey));
}
