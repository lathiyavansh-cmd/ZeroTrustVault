// The @noble/curves fallback (used when crypto.subtle lacks Ed25519/X25519) must produce identical bytes.
import { describe, expect, it } from "vitest";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import V from "./vectors.json";
import { b64u, b64uDecode, canonicalJson, concat } from "../crypto/encoding";
import { seedFromPkcs8, type AgreementKey } from "../crypto/curves";
import { MANIFEST_DOMAIN, MANIFEST_FIELDS } from "../crypto/sign";
import { unwrapDek } from "../crypto/wrap";

describe("noble fallback equivalence", () => {
  it("Ed25519 signature over domain||canonical_json equals the python signature", () => {
    const seed = seedFromPkcs8("Ed25519", b64uDecode(V.blob.sig_sk_pkcs8_b64u));
    expect(b64u(ed25519.getPublicKey(seed))).toBe(V.blob.sig_pk_b64u);
    const m = V.manifest.signed as Record<string, unknown>;
    const body: Record<string, unknown> = {};
    for (const f of MANIFEST_FIELDS) body[f] = m[f];
    const sig = ed25519.sign(concat(MANIFEST_DOMAIN, canonicalJson(body)), seed);
    expect(b64u(sig)).toBe(V.manifest.signed.signature);
  });
  it("X25519 ECDH via noble unwraps the python-wrapped DEK", async () => {
    const seed = seedFromPkcs8("X25519", b64uDecode(V.wrap.recipient_sk_pkcs8_b64u));
    const key: AgreementKey = { backend: "noble", publicKey: x25519.getPublicKey(seed), ecdh: async (peer) => x25519.getSharedSecret(seed, peer) };
    expect(b64u(key.publicKey)).toBe(V.wrap.recipient_pk_b64u);
    expect(b64u(await unwrapDek(V.wrap.record, key, V.wrap.file_id, V.wrap.version))).toBe(V.wrap.dek_b64u);
  });
});
