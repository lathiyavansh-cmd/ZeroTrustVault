// DPoP proofs (RFC 9449): compact JWS, ES256 with the non-extractable device key.
// Web Crypto ECDSA signatures are raw r||s (64 bytes) — exactly the JWS ES256 format.
import { b64u, randomBytes, sha256, utf8, toBuf } from "./encoding";
import type { DeviceKey } from "./device";

export function htuFromUrl(url: string): string {
  const u = new URL(url);
  return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${u.pathname || "/"}`;
}

export async function accessTokenHash(token: string): Promise<string> {
  return b64u(await sha256(utf8(token)));
}

export interface DpopOptions {
  accessToken?: string;
  /** unix seconds; defaults to Date.now()/1000 (apply server skew correction before passing) */
  iat?: number;
  nonce?: string;
}

export async function makeDpopProof(key: DeviceKey, method: string, url: string, opts: DpopOptions = {}): Promise<string> {
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.publicJwk };
  const claims: Record<string, unknown> = {
    jti: b64u(randomBytes(16)),
    htm: method.toUpperCase(),
    htu: htuFromUrl(url),
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
  };
  if (opts.accessToken) claims.ath = await accessTokenHash(opts.accessToken);
  if (opts.nonce) claims.nonce = opts.nonce;
  const signingInput = `${b64u(utf8(JSON.stringify(header)))}.${b64u(utf8(JSON.stringify(claims)))}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, toBuf(utf8(signingInput))));
  if (sig.length !== 64) throw new Error("unexpected ECDSA signature length");
  return `${signingInput}.${b64u(sig)}`;
}
