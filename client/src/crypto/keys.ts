// Level-1 user keys: generate X25519 + Ed25519, seal under Argon2id KEK into the exact blob format of keys.py
import { argon2id } from "hash-wasm";
import { b64u, b64uDecode, canonicalJson, fromUtf8, randomBytes, toBuf, utf8 } from "./encoding";
import { importAgreementKey, importSigningKey, pkcs8FromSeed, type AgreementKey, type SigningKey, type CurveBackend } from "./curves";

export const CLIENT_ARGON2 = { m: 65536, t: 3, p: 1 } as const;
const KEYBLOB_AAD = utf8("ZTV-keyblob-v1");

export interface SealedBlob {
  v: 1;
  kdf: { name: "argon2id"; m: number; t: number; p: number; salt: string };
  cipher: "AES-256-GCM";
  iv: string;
  ct: string;
}

export interface UserKeys {
  enc: AgreementKey;
  sig: SigningKey;
  backend: CurveBackend;
  encPk: string; // b64u raw32
  sigPk: string; // b64u raw32
}

export async function deriveKek(passphrase: string, salt: Uint8Array, p: { m: number; t: number; p: number }): Promise<Uint8Array> {
  return argon2id({ password: passphrase, salt, parallelism: p.p, iterations: p.t, memorySize: p.m, hashLength: 32, outputType: "binary" });
}

/** Generate fresh private keys as PKCS#8 DER (random 32-byte seeds; the DER form is byte-identical to `cryptography`). */
export function generatePrivateKeysPkcs8(): { enc_sk: Uint8Array; sig_sk: Uint8Array } {
  return { enc_sk: pkcs8FromSeed("X25519", randomBytes(32)), sig_sk: pkcs8FromSeed("Ed25519", randomBytes(32)) };
}

export async function sealPrivateKeys(
  sk: { enc_sk: Uint8Array; sig_sk: Uint8Array },
  passphrase: string,
  params: { m: number; t: number; p: number } = CLIENT_ARGON2,
  salt: Uint8Array = randomBytes(16),
): Promise<SealedBlob> {
  const kek = await deriveKek(passphrase, salt, params);
  const key = await crypto.subtle.importKey("raw", toBuf(kek), { name: "AES-GCM" }, false, ["encrypt"]);
  kek.fill(0);
  const iv = randomBytes(12);
  const inner = canonicalJson({ enc_sk: b64u(sk.enc_sk), sig_sk: b64u(sk.sig_sk) });
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: toBuf(iv), additionalData: toBuf(KEYBLOB_AAD) }, key, toBuf(inner)));
  return { v: 1, kdf: { name: "argon2id", m: params.m, t: params.t, p: params.p, salt: b64u(salt) }, cipher: "AES-256-GCM", iv: b64u(iv), ct: b64u(ct) };
}

/** Open a sealed blob and import the keys for the session (non-extractable CryptoKeys when Web Crypto supports the curves). */
export async function openPrivateKeys(blob: SealedBlob, passphrase: string): Promise<UserKeys> {
  if (blob.v !== 1 || blob.kdf.name !== "argon2id" || blob.cipher !== "AES-256-GCM") throw new Error("unsupported blob");
  const kek = await deriveKek(passphrase, b64uDecode(blob.kdf.salt), blob.kdf);
  const key = await crypto.subtle.importKey("raw", toBuf(kek), { name: "AES-GCM" }, false, ["decrypt"]);
  kek.fill(0);
  let inner: Uint8Array;
  try {
    inner = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: toBuf(b64uDecode(blob.iv)), additionalData: toBuf(KEYBLOB_AAD) }, key, toBuf(b64uDecode(blob.ct))));
  } catch {
    throw new Error("wrong passphrase or corrupted key blob");
  }
  const parsed = JSON.parse(fromUtf8(inner)) as { enc_sk: string; sig_sk: string };
  inner.fill(0);
  return importUserKeys({ enc_sk: b64uDecode(parsed.enc_sk), sig_sk: b64uDecode(parsed.sig_sk) });
}

export async function importUserKeys(sk: { enc_sk: Uint8Array; sig_sk: Uint8Array }): Promise<UserKeys> {
  const enc = await importAgreementKey(sk.enc_sk);
  const sig = await importSigningKey(sk.sig_sk);
  return { enc, sig, backend: enc.backend === "webcrypto" && sig.backend === "webcrypto" ? "webcrypto" : "noble", encPk: b64u(enc.publicKey), sigPk: b64u(sig.publicKey) };
}
