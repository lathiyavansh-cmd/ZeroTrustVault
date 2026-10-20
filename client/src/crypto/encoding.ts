// Encoding helpers — byte-identical to crypto/ztv_crypto/encoding.py
export type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

const te = new TextEncoder();
const td = new TextDecoder();

export function utf8(s: string): Uint8Array {
  return te.encode(s);
}
export function fromUtf8(b: Uint8Array): string {
  return td.decode(b);
}

export function b64u(data: Uint8Array | ArrayBuffer): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + 0x8000)));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function sortDeep(v: unknown): Json {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new TypeError("floats are not allowed in canonical JSON");
    return v;
  }
  if (typeof v === "string" || typeof v === "boolean") return v;
  if (Array.isArray(v)) return v.map(sortDeep);
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const out: { [k: string]: Json } = {};
    for (const k of Object.keys(o).sort()) {
      if (o[k] === undefined) continue;
      out[k] = sortDeep(o[k]);
    }
    return out;
  }
  throw new TypeError(`unsupported type in canonical JSON: ${typeof v}`);
}

/** Deterministic JSON: recursively sorted keys, no whitespace, UTF-8 (Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)). */
export function canonicalJson(obj: unknown): Uint8Array {
  return utf8(JSON.stringify(sortDeep(obj)));
}
export function canonicalJsonString(obj: unknown): string {
  return JSON.stringify(sortDeep(obj));
}

export function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("invalid uuid");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError("u32 out of range");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Exact ArrayBuffer copy of a view (Web Crypto wants BufferSource; avoids SharedArrayBuffer typing issues). */
export function toBuf(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toBuf(data)));
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function hexUpper(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/** ISO-8601 UTC, seconds precision, Z suffix. */
export function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function uuidv4(): string {
  return crypto.randomUUID();
}
