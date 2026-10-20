// Device key: ECDSA P-256, NON-extractable, generated once and stored as a CryptoKey object in IndexedDB.
import { b64u, sha256, utf8 } from "./encoding";

const DB = "ztv-device";
const STORE = "keys";
const ID = "device-key";

export interface DeviceKey {
  privateKey: CryptoKey;
  publicJwk: JsonWebKey; // {kty, crv, x, y}
  thumbprint: string; // RFC 7638
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const r = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
    r.onsuccess = () => resolve(r.result as T | undefined);
    r.onerror = () => reject(r.error);
  });
}
function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** RFC 7638 thumbprint of an EC JWK: SHA-256 over {"crv","kty","x","y"} in lexicographic order, no whitespace. */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const s = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64u(await sha256(utf8(s)));
}

let cached: DeviceKey | null = null;

export async function getOrCreateDeviceKey(): Promise<DeviceKey> {
  if (cached) return cached;
  const db = await openDb();
  let rec = await idbGet<{ privateKey: CryptoKey; publicJwk: JsonWebKey }>(db, ID);
  if (!rec) {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const full = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const publicJwk: JsonWebKey = { kty: "EC", crv: "P-256", x: full.x, y: full.y };
    rec = { privateKey: pair.privateKey, publicJwk };
    await idbPut(db, ID, rec);
  }
  db.close();
  cached = { privateKey: rec.privateKey, publicJwk: rec.publicJwk, thumbprint: await jwkThumbprint(rec.publicJwk) };
  return cached;
}

export async function hasDeviceKey(): Promise<boolean> {
  try {
    const db = await openDb();
    const rec = await idbGet(db, ID);
    db.close();
    return !!rec;
  } catch {
    return false;
  }
}
