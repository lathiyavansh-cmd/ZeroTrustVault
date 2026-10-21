// test_core.test.ts — M9 (frontend crypto engine) security-property tests.
// TypeScript counterpart of crypto/tests/test_core.py. Uses the real client/src/crypto API.
// Location: client/src/test/test_core.test.ts   Run: cd client && npx vitest run
import { describe, expect, it } from "vitest";
import V from "./vectors.json";
import { b64u, b64uDecode, canonicalJson, canonicalJsonString, equalBytes, sha256, utf8 } from "../crypto/encoding";
import { aadForChunk, decryptChunk, encryptChunk, importDek, nonceForChunk } from "../crypto/chunks";
import { leafHash, merkleRoot } from "../crypto/merkle";
import { unwrapDek, wrapDek } from "../crypto/wrap";
import { importAgreementKey } from "../crypto/curves";
import { openPrivateKeys, sealPrivateKeys, importUserKeys } from "../crypto/keys";
import { signGrant, signManifest, verifyGrant, verifyManifest, verifyUserCert, type Manifest, type Grant, type UserCert } from "../crypto/sign";
import { jwkThumbprint } from "../crypto/device";
import { accessTokenHash, htuFromUrl } from "../crypto/dpop";

const FID = "3f2b8c1e-6a4d-4e0b-9c55-0d7a1b2c3d4e";
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const hex = (u: Uint8Array) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

async function freshX25519(): Promise<Uint8Array> {
  const kp = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
}

/** Encrypt `plains` as consecutive chunks of one file (last one flagged final). */
async function encryptAll(plains: Uint8Array[], version = 1) {
  const dek = await importDek(rand(32));
  const prefix = rand(8);
  const cts: Uint8Array[] = [];
  for (let i = 0; i < plains.length; i++) {
    cts.push(await encryptChunk(dek, prefix, FID, version, i, plains[i], i === plains.length - 1));
  }
  return { dek, prefix, cts };
}

describe("encoding", () => {
  it("canonical JSON is key-order independent and rejects floats", () => {
    expect(equalBytes(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }))).toBe(true);
    expect(canonicalJsonString({ b: 1, a: [1, { z: null, y: "é" }] })).toBe('{"a":[1,{"y":"é","z":null}],"b":1}');
    expect(() => canonicalJsonString({ x: 1.5 })).toThrow();
    expect(() => canonicalJsonString({ outer: [{ inner: 0.1 }] })).toThrow();
  });

  it("b64u round-trips every length, has no padding and is URL-safe", () => {
    for (let n = 0; n < 40; n++) {
      const d = rand(n);
      const e = b64u(d);
      expect(e).not.toContain("=");
      expect(e).not.toMatch(/[+/]/);
      expect(b64uDecode(e)).toEqual(d);
    }
    expect(b64u(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(b64u(new Uint8Array())).toBe("");
  });

  it("sha256 matches the NIST vector for 'abc'", async () => {
    expect(hex(await sha256(utf8("abc")))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("chunked AES-256-GCM", () => {
  it("round-trips multi-chunk data", async () => {
    const plains = [rand(1024), rand(1024), rand(1024), rand(17)];
    const { dek, prefix, cts } = await encryptAll(plains);
    for (let i = 0; i < cts.length; i++) {
      const pt = await decryptChunk(dek, prefix, FID, 1, i, cts[i], i === cts.length - 1);
      expect(pt).toEqual(plains[i]);
    }
  });

  it("detects a flipped byte", async () => {
    const { dek, prefix, cts } = await encryptAll([rand(512), rand(512)]);
    const bad = cts[0].slice();
    bad[5] ^= 1;
    await expect(decryptChunk(dek, prefix, FID, 1, 0, bad, false)).rejects.toThrow();
  });

  it("detects chunk reordering (index is in the AAD)", async () => {
    const { dek, prefix, cts } = await encryptAll([rand(256), rand(256), rand(256)]);
    await expect(decryptChunk(dek, prefix, FID, 1, 0, cts[1], false)).rejects.toThrow();
    await expect(decryptChunk(dek, prefix, FID, 1, 1, cts[0], false)).rejects.toThrow();
  });

  it("detects truncation (final flag is in the AAD)", async () => {
    const { dek, prefix, cts } = await encryptAll([rand(256), rand(256), rand(256), rand(256)]);
    // attacker drops the last chunk: chunk 2 is now treated as final -> must fail
    await expect(decryptChunk(dek, prefix, FID, 1, 2, cts[2], true)).rejects.toThrow();
    // and a genuine final chunk is rejected if presented as non-final
    await expect(decryptChunk(dek, prefix, FID, 1, 3, cts[3], false)).rejects.toThrow();
  });

  it("binds file id and version (no cross-file splice or version rollback)", async () => {
    const { dek, prefix, cts } = await encryptAll([rand(256), rand(256)]);
    await expect(decryptChunk(dek, prefix, "other-file-id", 1, 0, cts[0], false)).rejects.toThrow();
    await expect(decryptChunk(dek, prefix, FID, 2, 0, cts[0], false)).rejects.toThrow();
  });

  it("rejects decryption under a different DEK", async () => {
    const { prefix, cts } = await encryptAll([rand(256)]);
    const otherDek = await importDek(rand(32));
    await expect(decryptChunk(otherDek, prefix, FID, 1, 0, cts[0], true)).rejects.toThrow();
  });

  it("handles the empty file", async () => {
    const { dek, prefix, cts } = await encryptAll([new Uint8Array()]);
    expect(cts.length).toBe(1);
    expect((await decryptChunk(dek, prefix, FID, 1, 0, cts[0], true)).length).toBe(0);
  });

  it("AAD ends with the final flag", () => {
    expect(aadForChunk(FID, 1, 0, true).at(-1)).toBe(1);
    expect(aadForChunk(FID, 1, 0, false).at(-1)).toBe(0);
  });

  it("never reuses a nonce within a file", () => {
    const prefix = rand(8);
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const n = nonceForChunk(prefix, i);
      expect(n.length).toBe(12);
      seen.add(hex(n));
    }
    expect(seen.size).toBe(200);
  });

  it("encrypting the same plaintext twice gives different ciphertext (fresh DEK/prefix)", async () => {
    const p = rand(300);
    const a = await encryptAll([p]);
    const b = await encryptAll([p]);
    expect(equalBytes(a.cts[0], b.cts[0])).toBe(false);
  });
});

describe("merkle tree", () => {
  it("is deterministic and detects reordering, truncation and bit flips", async () => {
    const chunks = Array.from({ length: 5 }, () => rand(100));
    const root = await merkleRoot(chunks);
    expect(equalBytes(await merkleRoot(chunks), root)).toBe(true);
    expect(equalBytes(await merkleRoot(chunks.slice(0, 4)), root)).toBe(false);
    expect(equalBytes(await merkleRoot([chunks[1], chunks[0], ...chunks.slice(2)]), root)).toBe(false);
    const c2 = chunks.map((c) => c.slice());
    c2[3][c2[3].length - 1] ^= 1;
    expect(equalBytes(await merkleRoot(c2), root)).toBe(false);
  });

  it("leaf hashes differ for different chunks", async () => {
    expect(equalBytes(await leafHash(rand(64)), await leafHash(rand(64)))).toBe(false);
  });
});

describe("DEK wrapping (X25519 + HKDF + AES-KW)", () => {
  it("wraps and unwraps; fails for wrong version, wrong file and wrong recipient", async () => {
    const sk = await importAgreementKey(await freshX25519());
    const dek = rand(32);
    const rec = await wrapDek(dek, sk.publicKey, FID, 1);
    expect(await unwrapDek(rec, sk, FID, 1)).toEqual(dek);
    await expect(unwrapDek(rec, sk, FID, 2)).rejects.toThrow();
    await expect(unwrapDek(rec, sk, "other-file-id", 1)).rejects.toThrow();
    const other = await importAgreementKey(await freshX25519());
    await expect(unwrapDek(rec, other, FID, 1)).rejects.toThrow();
  });

  it("uses a fresh ephemeral key per wrap", async () => {
    const sk = await importAgreementKey(await freshX25519());
    const dek = rand(32);
    const a = await wrapDek(dek, sk.publicKey, FID, 1);
    const b = await wrapDek(dek, sk.publicKey, FID, 1);
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
  });
});

describe("manifest and grant signatures (Ed25519)", () => {
  const pk = b64uDecode(V.manifest.owner_sig_pk_b64u);
  const manifest = V.manifest.signed as Manifest;
  const grant = V.grant.signed as Grant;

  it("verifies authentic manifest and grant", async () => {
    expect(await verifyManifest(manifest, pk)).toBe(true);
    expect(await verifyGrant(grant, pk)).toBe(true);
  });

  it("rejects a tampered manifest or grant", async () => {
    expect(await verifyManifest({ ...manifest, size: manifest.size + 1 }, pk)).toBe(false);
    expect(await verifyGrant({ ...grant, rights: ["view", "download", "admin"] } as Grant, pk)).toBe(false);
  });

  it("rejects the wrong signer key", async () => {
    const other = await freshSigner();
    expect(await verifyManifest(manifest, other.sigPk)).toBe(false);
  });

  it("a freshly signed manifest/grant verifies, and breaks when edited", async () => {
    const signer = await freshSigner();
    const { signature: _s, ...mbody } = manifest;
    const sm = await signManifest(mbody as Manifest, signer.keys.sig);
    expect(await verifyManifest(sm, signer.sigPk)).toBe(true);
    expect(await verifyManifest({ ...sm, size: sm.size + 1 }, signer.sigPk)).toBe(false);
    const { signature: _g, ...gbody } = grant;
    const sg = await signGrant(gbody as Grant, signer.keys.sig);
    expect(await verifyGrant(sg, signer.sigPk)).toBe(true);
  });
});

async function freshSigner() {
  const sig = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const sigSk = new Uint8Array(await crypto.subtle.exportKey("pkcs8", sig.privateKey));
  const sigPk = new Uint8Array(await crypto.subtle.exportKey("raw", sig.publicKey));
  const keys = await importUserKeys({ enc_sk: await freshX25519(), sig_sk: sigSk });
  return { keys, sigPk };
}

describe("passphrase-sealed private key blob (Argon2id)", () => {
  const sk = { enc_sk: b64uDecode(V.blob.enc_sk_pkcs8_b64u), sig_sk: b64uDecode(V.blob.sig_sk_pkcs8_b64u) };
  const FAST = { m: 1024, t: 1, p: 1 };

  it("seals and opens, and rejects a wrong passphrase", async () => {
    const blob = await sealPrivateKeys(sk, "pass-1", FAST);
    const keys = await openPrivateKeys(blob, "pass-1");
    expect(keys.encPk).toBe(V.blob.enc_pk_b64u);
    expect(keys.sigPk).toBe(V.blob.sig_pk_b64u);
    await expect(openPrivateKeys(blob, "pass-2")).rejects.toThrow();
  });

  it("the blob contains no plaintext private key", async () => {
    const blob = await sealPrivateKeys(sk, "pass-1", FAST);
    const text = JSON.stringify(blob);
    expect(text).not.toContain(V.blob.enc_sk_pkcs8_b64u);
    expect(text).not.toContain(V.blob.sig_sk_pkcs8_b64u);
  });

  it("sealing twice gives different blobs (random salt/nonce)", async () => {
    const a = await sealPrivateKeys(sk, "pw", FAST);
    const b = await sealPrivateKeys(sk, "pw", FAST);
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
  });
});

describe("org CA certificates", () => {
  const root = b64uDecode(V.cert.root_pk_b64u);
  const cert = V.cert.cert as UserCert;

  it("accepts a valid cert and rejects wrong user id, edited fields and wrong root", async () => {
    expect(await verifyUserCert(cert, root, { expectedUserId: cert.user_id })).toBe(true);
    expect(await verifyUserCert(cert, root, { expectedUserId: "other" })).toBe(false);
    expect(await verifyUserCert({ ...cert, username: "mallory" }, root)).toBe(false);
    expect(await verifyUserCert(cert, b64uDecode(V.manifest.owner_sig_pk_b64u))).toBe(false);
  });

  it("rejects a server-substituted public key", async () => {
    const evil = b64u(rand(32));
    expect(await verifyUserCert({ ...cert, enc_pk: evil }, root)).toBe(false);
    expect(await verifyUserCert({ ...cert, sig_pk: evil }, root)).toBe(false);
  });
});

describe("DPoP helpers", () => {
  it("normalises the htu (lowercase host, no query, no fragment)", () => {
    expect(htuFromUrl("HTTPS://LocalHost:8443/api/files?x=1#f")).toBe("https://localhost:8443/api/files");
    expect(htuFromUrl("https://vault.local:8443/api/files/abc?x=1")).toBe("https://vault.local:8443/api/files/abc");
  });

  it("access-token hash is deterministic and token-specific", async () => {
    expect(await accessTokenHash("tok")).toBe(await accessTokenHash("tok"));
    expect(await accessTokenHash("tok")).not.toBe(await accessTokenHash("stolen-other-token"));
  });

  it("device JWK thumbprint is stable", async () => {
    expect(await jwkThumbprint(V.dpop.jwk)).toBe(V.dpop.jkt);
  });
});
