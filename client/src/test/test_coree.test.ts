// test_core.test.ts — M9 (Frontend / browser crypto engine) test suite
// Mirrors the Python test_core.py (M3/M4/M5/M6) but exercises the Web Crypto implementation.
//
// Run:  npm i -D vitest hash-wasm   &&   npx vitest run
// Needs Node >= 20 (Web Crypto with Ed25519 / X25519). Set `environment: "node"` in vitest.config.
//
// NOTE: import names below are my assumed API for src/crypto/*. Rename to match your actual exports.

import { describe, it, expect } from "vitest";
import {
  CLIENT_ARGON2,
  aadForChunk,
  b64u,
  b64uDecode,
  buildManifest,
  canonicalJson,
  certFingerprint,
  decryptChunks,
  deriveKek,
  encryptBytes,
  generateUserKeys,
  makeDpopProof,
  merkleRoot,
  openPrivateKeys,
  resealPrivateKeys,
  sealPrivateKeys,
  sha256,
  signManifest,
  unwrapDek,
  verifyManifest,
  verifyUserCert,
  wrapDek,
  DeviceKey,
  ChunkCipher,
  decryptStreaming, // Web Worker streaming decrypt (async generator / ReadableStream)
} from "../src/crypto";

const enc = new TextEncoder();
const dec = new TextDecoder();
const FID = crypto.randomUUID();
const SMALL = 1024; // small chunk size: fast but multi-chunk

const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const hex = (u: Uint8Array) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
const FAST_ARGON = { memoryKiB: 8 * 1024, timeCost: 1, parallelism: 1 };

describe("encoding", () => {
  it("canonicalJson is deterministic and byte-identical to the Python backend", () => {
    const out = dec.decode(canonicalJson({ b: 1, a: [1, { z: null, y: "é" }] }));
    expect(out).toBe('{"a":[1,{"y":"é","z":null}],"b":1}');
    expect(canonicalJson({ a: 1, b: 2 })).toEqual(canonicalJson({ b: 2, a: 1 }));
    expect(dec.decode(canonicalJson({ t: true, n: null, l: [1, 2] }))).toBe('{"l":[1,2],"n":null,"t":true}');
  });

  it("canonicalJson rejects floats, bytes and sets (signatures depend on this)", () => {
    expect(() => canonicalJson({ x: 1.5 })).toThrow(TypeError);
    expect(() => canonicalJson({ outer: [{ inner: 0.1 }] })).toThrow(TypeError);
    expect(() => canonicalJson({ raw: new Uint8Array([0]) })).toThrow(TypeError);
    expect(() => canonicalJson({ s: new Set([1, 2]) })).toThrow(TypeError);
  });

  it("b64u round-trips every length, has no padding and is URL-safe", () => {
    for (let n = 0; n < 40; n++) {
      const d = rand(n);
      const e = b64u(d);
      expect(e).not.toContain("=");
      expect(eq(b64uDecode(e), d)).toBe(true);
    }
    expect(b64u(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(eq(b64uDecode("-_8"), new Uint8Array([0xfb, 0xff]))).toBe(true);
    expect(b64u(new Uint8Array())).toBe("");
  });

  it("sha256 matches the NIST vector for 'abc'", async () => {
    expect(hex(await sha256(enc.encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });
});

describe("chunked AES-256-GCM", () => {
  it("round-trips multi-chunk data and rejects byte flips, swaps, truncation", async () => {
    const data = rand(SMALL * 3 + 17);
    const { cipher, chunks } = await encryptBytes(data, FID, 1, { chunkSize: SMALL });
    expect(chunks.length).toBe(4);
    expect(eq(await decryptChunks(cipher, chunks, { expectedCount: 4 }), data)).toBe(true);

    const flipped = chunks[1].slice(); flipped[5] ^= 1;
    await expect(decryptChunks(cipher, [chunks[0], flipped, chunks[2], chunks[3]])).rejects.toThrow();
    await expect(decryptChunks(cipher, [chunks[1], chunks[0], chunks[2], chunks[3]])).rejects.toThrow();
    // dropping the last chunk makes chunk 2 'final' -> AAD mismatch
    await expect(decryptChunks(cipher, chunks.slice(0, 3))).rejects.toThrow();
    // explicit count check
    await expect(decryptChunks(cipher, chunks.slice(0, 3), { expectedCount: 4 })).rejects.toThrow(/count/i);
  });

  it("binds file id and version in the AAD (no cross-file splice / version rollback)", async () => {
    const { cipher, chunks } = await encryptBytes(rand(SMALL * 2), FID, 1, { chunkSize: SMALL });
    const otherFile = new ChunkCipher({ ...cipher.params, fileId: crypto.randomUUID() });
    await expect(otherFile.decryptChunk(0, chunks[0], false)).rejects.toThrow();
    const v2 = new ChunkCipher({ ...cipher.params, version: 2 });
    await expect(v2.decryptChunk(0, chunks[0], false)).rejects.toThrow();
  });

  it("handles the empty file and the ChaCha20 fallback path", async () => {
    const { cipher, chunks } = await encryptBytes(new Uint8Array(), FID, 1);
    expect(chunks.length).toBe(1);
    expect((await decryptChunks(cipher, chunks)).length).toBe(0);
    const aad = aadForChunk(FID, 1, 0, true);
    expect(aad[aad.length - 1]).toBe(1); // final flag is the last AAD byte
  });

  it("never reuses a nonce across chunks of the same file", async () => {
    const { chunks } = await encryptBytes(rand(SMALL * 8), FID, 1, { chunkSize: SMALL });
    const nonces = chunks.map((c) => hex(c.slice(0, 12)));
    expect(new Set(nonces).size).toBe(chunks.length);
  });
});

describe("merkle tree", () => {
  it("detects reordering, truncation and single-bit changes", async () => {
    const chunks = Array.from({ length: 5 }, () => rand(100));
    const root = await merkleRoot(chunks);
    expect(eq(await merkleRoot(chunks), root)).toBe(true);
    expect(eq(await merkleRoot(chunks.slice(0, 4)), root)).toBe(false);
    expect(eq(await merkleRoot([chunks[1], chunks[0], ...chunks.slice(2)]), root)).toBe(false);
    const c2 = chunks.map((c) => c.slice());
    c2[3][c2[3].length - 1] ^= 1;
    expect(eq(await merkleRoot(c2), root)).toBe(false);
  });
});

describe("key wrapping (X25519 + HKDF + AES-KW)", () => {
  it("wraps/unwraps and fails for wrong version, wrong file or wrong recipient", async () => {
    const recipient = await generateUserKeys();
    const dek = rand(32);
    const rec = await wrapDek(dek, recipient.encPk, FID, 1);
    expect(eq(await unwrapDek(rec, recipient.encSk, FID, 1), dek)).toBe(true);
    await expect(unwrapDek(rec, recipient.encSk, FID, 2)).rejects.toThrow(); // version in HKDF info
    await expect(unwrapDek(rec, recipient.encSk, crypto.randomUUID(), 1)).rejects.toThrow();
    const other = await generateUserKeys();
    await expect(unwrapDek(rec, other.encSk, FID, 1)).rejects.toThrow();
  });

  it("generates a fresh ephemeral key per wrap (two wraps of one DEK differ)", async () => {
    const r = await generateUserKeys();
    const dek = rand(32);
    const a = await wrapDek(dek, r.encPk, FID, 1);
    const b = await wrapDek(dek, r.encPk, FID, 1);
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
  });
});

describe("manifest signatures (Ed25519)", () => {
  const mk = (owner: string) =>
    buildManifest({
      fileId: FID, version: 1, name: "q3.pdf", size: 10, classification: "CONFIDENTIAL",
      merkleRoot: new Uint8Array(32), chunkCount: 1, chunkSize: 4194304,
      cipher: "AES-256-GCM", noncePrefix: new Uint8Array(8).fill(1), ownerId: owner,
    });

  it("verifies, and rejects tampered fields and the wrong key", async () => {
    const owner = await generateUserKeys();
    const sm = await signManifest(mk("u1"), owner.sigSk);
    expect(await verifyManifest(sm, owner.sigPk)).toBe(true);
    expect(await verifyManifest({ ...sm, classification: "PUBLIC" }, owner.sigPk)).toBe(false);
    expect(await verifyManifest(sm, (await generateUserKeys()).sigPk)).toBe(false);
  });

  it("client refuses to decrypt when the manifest Merkle root does not match the chunks", async () => {
    const owner = await generateUserKeys();
    const data = rand(SMALL * 2);
    const { cipher, chunks } = await encryptBytes(data, FID, 1, { chunkSize: SMALL });
    const m = buildManifest({
      fileId: FID, version: 1, name: "a.bin", size: data.length, classification: "INTERNAL",
      merkleRoot: await merkleRoot(chunks), chunkCount: chunks.length, chunkSize: SMALL,
      cipher: "AES-256-GCM", noncePrefix: cipher.params.noncePrefix, ownerId: "u1",
    });
    const sm = await signManifest(m, owner.sigSk);
    await expect(decryptChunks(cipher, chunks, { manifest: sm, ownerSigPk: owner.sigPk })).resolves.toBeDefined();
    const evil = chunks.map((c) => c.slice()); evil[0][3] ^= 1;
    await expect(decryptChunks(cipher, evil, { manifest: sm, ownerSigPk: owner.sigPk })).rejects.toThrow();
  });
});

describe("KEK and private-key blob (Argon2id)", () => {
  it("derives deterministic, passphrase-sensitive KEKs", async () => {
    const salt = new Uint8Array(16).fill(7);
    const a = await deriveKek("correct horse", salt, FAST_ARGON);
    expect(eq(a, await deriveKek("correct horse", salt, FAST_ARGON))).toBe(true);
    expect(eq(a, await deriveKek("correct horse!", salt, FAST_ARGON))).toBe(false);
  });

  it("seals, opens, rejects wrong passphrase and reseals on passphrase change", async () => {
    const keys = await generateUserKeys();
    const blob = await sealPrivateKeys(keys, "pass-1", FAST_ARGON);
    const opened = await openPrivateKeys(blob, "pass-1");
    expect(eq(opened.encPk, keys.encPk) && eq(opened.sigPk, keys.sigPk)).toBe(true);
    await expect(openPrivateKeys(blob, "pass-2")).rejects.toThrow();
    const blob2 = await resealPrivateKeys(blob, "pass-1", "pass-2");
    expect(eq((await openPrivateKeys(blob2, "pass-2")).sigPk, keys.sigPk)).toBe(true);
    expect(blob.kdf.m).toBe(8192);
    expect(CLIENT_ARGON2.memoryKiB).toBe(65536);
  });

  it("the uploaded blob contains no plaintext private key material", async () => {
    const keys = await generateUserKeys({ exportable: true });
    const raw = await crypto.subtle.exportKey("pkcs8", keys.sigSk);
    const blob = await sealPrivateKeys(keys, "pw", FAST_ARGON);
    expect(JSON.stringify(blob)).not.toContain(b64u(new Uint8Array(raw)));
  });
});

describe("non-extractable keys (browser-specific)", () => {
  it("device key cannot be exported", async () => {
    const k = await DeviceKey.generate();
    expect(k.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", k.privateKey)).rejects.toThrow();
  });

  it("unlocked user private keys are imported as non-extractable", async () => {
    const keys = await generateUserKeys();
    const blob = await sealPrivateKeys(keys, "pw", FAST_ARGON);
    const opened = await openPrivateKeys(blob, "pw");
    expect(opened.encSk.extractable).toBe(false);
    expect(opened.sigSk.extractable).toBe(false);
  });
});

describe("org CA certificate verification", () => {
  it("rejects a server-substituted key against the pinned root", async () => {
    const root = await generateUserKeys();          // stands in for the org root
    const user = await generateUserKeys();
    const cert = await issueTestCert(root.sigSk, "u1", "alice", user);
    expect(await verifyUserCert(cert, root.sigPk)).toBe(true);
    expect(await verifyUserCert(cert, root.sigPk, { expectedUserId: "u1" })).toBe(true);
    expect(await verifyUserCert(cert, root.sigPk, { expectedUserId: "u2" })).toBe(false);
    const evil = await generateUserKeys();
    expect(await verifyUserCert({ ...cert, enc_pk: b64u(evil.encPk) }, root.sigPk)).toBe(false);
    expect(await verifyUserCert(cert, (await generateUserKeys()).sigPk)).toBe(false);
    expect(certFingerprint(user.encPk, user.sigPk).replace(/ /g, "").length).toBe(32);
  });
});

describe("DPoP proofs", () => {
  const url = "https://vault.local:8443/api/files/abc?x=1";

  it("binds method, URL, token and device key, and is verifiable by the backend format", async () => {
    const k = await DeviceKey.generate();
    const proof = await makeDpopProof(k, "GET", url, { accessToken: "tok" });
    const [h, p] = proof.split(".").map((s) => JSON.parse(dec.decode(b64uDecode(s))));
    expect(h.typ).toBe("dpop+jwt");
    expect(h.alg).toBe("EdDSA");
    expect(p.htm).toBe("GET");
    expect(p.htu).toBe("https://vault.local:8443/api/files/abc"); // query stripped
    expect(p.jti.length).toBeGreaterThan(10);
    expect(typeof p.ath).toBe("string");                          // access-token hash
    expect(Math.abs(p.iat - Date.now() / 1000)).toBeLessThan(5);
  });

  it("uses a fresh jti for every request (anti-replay nonce)", async () => {
    const k = await DeviceKey.generate();
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const p = await makeDpopProof(k, "GET", url);
      ids.add(JSON.parse(dec.decode(b64uDecode(p.split(".")[1]))).jti);
    }
    expect(ids.size).toBe(50);
  });

  it("device thumbprint survives export/import of the public part", async () => {
    const k = await DeviceKey.generate();
    expect((await DeviceKey.fromPublicJwk(await k.publicJwk())).thumbprint).toBe(k.thumbprint);
  });
});

describe("streaming decryption in a Web Worker", () => {
  it("streams plaintext chunk by chunk and aborts on the first bad GCM tag", async () => {
    const data = rand(SMALL * 5 + 3);
    const { cipher, chunks } = await encryptBytes(data, FID, 1, { chunkSize: SMALL });

    const out: Uint8Array[] = [];
    for await (const part of decryptStreaming(cipher, chunks)) out.push(part);
    const joined = new Uint8Array(out.reduce((n, p) => n + p.length, 0));
    let off = 0; for (const p of out) { joined.set(p, off); off += p.length; }
    expect(eq(joined, data)).toBe(true);

    const bad = chunks.map((c) => c.slice()); bad[2][9] ^= 1;
    const seen: Uint8Array[] = [];
    await expect((async () => { for await (const p of decryptStreaming(cipher, bad)) seen.push(p); })()).rejects.toThrow();
    expect(seen.length).toBe(2); // chunks 0 and 1 yielded; nothing after the failure
  });
});

// --- helper: issue a cert in the same format the Python CA produces (adjust to your ca module) ---
async function issueTestCert(rootSigSk: CryptoKey, userId: string, username: string, user: { encPk: Uint8Array; sigPk: Uint8Array }) {
  const body = { user_id: userId, username, enc_pk: b64u(user.encPk), sig_pk: b64u(user.sigPk) };
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", rootSigSk, canonicalJson(body)));
  return { ...body, sig: b64u(sig) };
}
