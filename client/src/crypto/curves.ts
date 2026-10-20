// Ed25519 / X25519 backend: Web Crypto when the browser supports it (keys imported NON-extractable),
// otherwise @noble/curves with the private seeds held only in a closure (never persisted, never exported).
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { concat, toBuf } from "./encoding";

export type CurveBackend = "webcrypto" | "noble";

// PKCS#8 DER prefixes for 32-byte seeds (RFC 8410). Byte-identical to `cryptography`'s PKCS8 DER output.
const PKCS8_ED25519 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
const PKCS8_X25519 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

export function pkcs8FromSeed(kind: "Ed25519" | "X25519", seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return concat(kind === "Ed25519" ? PKCS8_ED25519 : PKCS8_X25519, seed);
}

export function seedFromPkcs8(kind: "Ed25519" | "X25519", der: Uint8Array): Uint8Array {
  const prefix = kind === "Ed25519" ? PKCS8_ED25519 : PKCS8_X25519;
  if (der.length !== 48) throw new Error(`unexpected ${kind} PKCS#8 length ${der.length}`);
  for (let i = 0; i < prefix.length; i++) if (der[i] !== prefix[i]) throw new Error(`not an ${kind} PKCS#8 key`);
  return der.slice(16);
}

let detected: Promise<{ ed: boolean; x: boolean }> | null = null;
export function detectWebCryptoCurves(): Promise<{ ed: boolean; x: boolean }> {
  if (!detected) {
    detected = (async () => {
      const probe = async (name: string, usages: KeyUsage[]) => {
        try {
          await crypto.subtle.generateKey({ name }, false, usages);
          return true;
        } catch {
          return false;
        }
      };
      return { ed: await probe("Ed25519", ["sign", "verify"]), x: await probe("X25519", ["deriveBits"]) };
    })();
  }
  return detected;
}

export interface SigningKey {
  backend: CurveBackend;
  publicKey: Uint8Array; // raw 32
  sign(message: Uint8Array): Promise<Uint8Array>; // 64 bytes
}
export interface AgreementKey {
  backend: CurveBackend;
  publicKey: Uint8Array; // raw 32
  ecdh(peerPublicKey: Uint8Array): Promise<Uint8Array>; // 32-byte shared secret
}

export async function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const { ed } = await detectWebCryptoCurves();
  if (ed) {
    try {
      const k = await crypto.subtle.importKey("raw", toBuf(publicKey), { name: "Ed25519" }, false, ["verify"]);
      return await crypto.subtle.verify({ name: "Ed25519" }, k, toBuf(signature), toBuf(message));
    } catch {
      return false;
    }
  }
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** Import an Ed25519 PKCS#8 private key for the session (non-extractable in the Web Crypto path). */
export async function importSigningKey(pkcs8: Uint8Array): Promise<SigningKey> {
  const seed = seedFromPkcs8("Ed25519", pkcs8);
  const { ed } = await detectWebCryptoCurves();
  if (ed) {
    const tmp = await crypto.subtle.importKey("pkcs8", toBuf(pkcs8), { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", tmp);
    const key = await crypto.subtle.importKey("pkcs8", toBuf(pkcs8), { name: "Ed25519" }, false, ["sign"]);
    seed.fill(0);
    const publicKey = b64uToBytes(jwk.x!);
    return {
      backend: "webcrypto",
      publicKey,
      sign: async (m) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, toBuf(m))),
    };
  }
  const publicKey = ed25519.getPublicKey(seed);
  return { backend: "noble", publicKey, sign: async (m) => ed25519.sign(m, seed) };
}

/** Import an X25519 PKCS#8 private key for the session (non-extractable in the Web Crypto path). */
export async function importAgreementKey(pkcs8: Uint8Array): Promise<AgreementKey> {
  const seed = seedFromPkcs8("X25519", pkcs8);
  const { x } = await detectWebCryptoCurves();
  if (x) {
    const tmp = await crypto.subtle.importKey("pkcs8", toBuf(pkcs8), { name: "X25519" }, true, ["deriveBits"]);
    const jwk = await crypto.subtle.exportKey("jwk", tmp);
    const key = await crypto.subtle.importKey("pkcs8", toBuf(pkcs8), { name: "X25519" }, false, ["deriveBits"]);
    seed.fill(0);
    return {
      backend: "webcrypto",
      publicKey: b64uToBytes(jwk.x!),
      ecdh: async (peer) => {
        const pub = await crypto.subtle.importKey("raw", toBuf(peer), { name: "X25519" }, false, []);
        return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pub }, key, 256));
      },
    };
  }
  const publicKey = x25519.getPublicKey(seed);
  return { backend: "noble", publicKey, ecdh: async (peer) => x25519.getSharedSecret(seed, peer) };
}

/** Fresh ephemeral X25519 pair (used once for DEK wrapping, then dropped). */
export async function ephemeralAgreementKey(): Promise<AgreementKey> {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return importAgreementKey(pkcs8FromSeed("X25519", seed));
}

function b64uToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
