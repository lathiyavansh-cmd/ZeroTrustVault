// Ed25519 domain-separated signatures over canonical JSON — identical to sign.py / ca.py
import { b64u, b64uDecode, canonicalJson, concat, hexUpper, sha256, utf8 } from "./encoding";
import { ed25519Verify, type SigningKey } from "./curves";

export const MANIFEST_DOMAIN = utf8("ZTV-manifest-v1\0");
export const GRANT_DOMAIN = utf8("ZTV-grant-v1\0");
export const CERT_DOMAIN = utf8("ZTV-user-cert-v1\0");
export const CHECKPOINT_DOMAIN = utf8("ZTV-audit-checkpoint-v1\0");

export const MANIFEST_FIELDS = ["file_id", "version", "name", "size", "classification", "merkle_root", "chunk_count", "chunk_size", "cipher", "nonce_prefix", "owner_id", "timestamp"] as const;
export const GRANT_FIELDS = ["grant_id", "file_id", "owner_id", "recipient_id", "rights", "expires_at", "max_downloads", "required_posture", "issued_at"] as const;
export const CERT_FIELDS = ["serial", "user_id", "username", "enc_pk", "sig_pk", "iat", "exp", "issuer"] as const;
export const CERT_ISSUER = "ztv-org-root";

export interface Manifest {
  file_id: string;
  version: number;
  name: string;
  size: number;
  classification: string;
  merkle_root: string;
  chunk_count: number;
  chunk_size: number;
  cipher: string;
  nonce_prefix: string;
  owner_id: string;
  timestamp: string;
  signature?: string;
}
export interface Grant {
  grant_id: string;
  file_id: string;
  owner_id: string;
  recipient_id: string;
  rights: string[];
  expires_at: string;
  max_downloads: number;
  required_posture: string;
  issued_at: string;
  signature?: string;
}
export interface UserCert {
  serial: string;
  user_id: string;
  username: string;
  enc_pk: string;
  sig_pk: string;
  iat: string;
  exp: string;
  issuer: string;
  signature: string;
}

function strip<T extends object>(obj: T, fields: readonly string[]): Record<string, unknown> {
  const o = obj as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (!(f in o)) throw new Error(`missing field ${f}`);
    out[f] = o[f];
  }
  return out;
}

export async function signObject(key: SigningKey, domain: Uint8Array, body: unknown): Promise<string> {
  return b64u(await key.sign(concat(domain, canonicalJson(body))));
}

export async function verifyObject(pk: Uint8Array, domain: Uint8Array, body: unknown, signature: string): Promise<boolean> {
  try {
    return await ed25519Verify(pk, concat(domain, canonicalJson(body)), b64uDecode(signature));
  } catch {
    return false;
  }
}

export async function signManifest(m: Manifest, key: SigningKey): Promise<Manifest> {
  const body = strip(m, MANIFEST_FIELDS);
  return { ...(body as unknown as Manifest), signature: await signObject(key, MANIFEST_DOMAIN, body) };
}
export async function verifyManifest(m: Manifest, ownerPk: Uint8Array): Promise<boolean> {
  try {
    return await verifyObject(ownerPk, MANIFEST_DOMAIN, strip(m, MANIFEST_FIELDS), m.signature ?? "");
  } catch {
    return false;
  }
}

export async function signGrant(g: Grant, key: SigningKey): Promise<Grant> {
  const body = strip(g, GRANT_FIELDS);
  return { ...(body as unknown as Grant), signature: await signObject(key, GRANT_DOMAIN, body) };
}
export async function verifyGrant(g: Grant, ownerPk: Uint8Array): Promise<boolean> {
  try {
    return await verifyObject(ownerPk, GRANT_DOMAIN, strip(g, GRANT_FIELDS), g.signature ?? "");
  } catch {
    return false;
  }
}

/** Verify a user certificate against the pinned org root (signature, issuer, validity window, optional user id). */
export async function verifyUserCert(cert: UserCert, rootPk: Uint8Array, opts: { now?: Date; expectedUserId?: string } = {}): Promise<boolean> {
  let body: Record<string, unknown>;
  try {
    body = strip(cert, CERT_FIELDS);
  } catch {
    return false;
  }
  if (body.issuer !== CERT_ISSUER) return false;
  if (opts.expectedUserId !== undefined && body.user_id !== opts.expectedUserId) return false;
  if (!(await verifyObject(rootPk, CERT_DOMAIN, body, cert.signature ?? ""))) return false;
  const now = (opts.now ?? new Date()).getTime();
  const iat = Date.parse(cert.iat);
  const exp = Date.parse(cert.exp);
  if (Number.isNaN(iat) || Number.isNaN(exp)) return false;
  return iat - 5 * 60_000 <= now && now <= exp;
}

/** upper-hex SHA-256(enc_pk || sig_pk)[:32] in 8 groups of 4 */
export async function certFingerprint(encPk: Uint8Array, sigPk: Uint8Array): Promise<string> {
  const h = hexUpper(await sha256(concat(encPk, sigPk))).slice(0, 32);
  return h.match(/.{4}/g)!.join(" ");
}
