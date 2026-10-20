// py_webauthn JSON options <-> navigator.credentials (base64url fields <-> ArrayBuffers)
import { b64u, b64uDecode, toBuf } from "../crypto/encoding";

type AnyRec = Record<string, unknown>;

function dec(s: string): ArrayBuffer {
  return toBuf(b64uDecode(s));
}

export function parseCreationOptions(o: AnyRec): PublicKeyCredentialCreationOptions {
  const opts = (o.publicKey as AnyRec) ?? o;
  return {
    ...(opts as unknown as PublicKeyCredentialCreationOptions),
    challenge: dec(opts.challenge as string),
    user: { ...(opts.user as AnyRec), id: dec((opts.user as AnyRec).id as string) } as PublicKeyCredentialUserEntity,
    excludeCredentials: ((opts.excludeCredentials as AnyRec[] | undefined) ?? []).map((c) => ({ ...c, id: dec(c.id as string) }) as PublicKeyCredentialDescriptor),
  };
}

export function parseRequestOptions(o: AnyRec): PublicKeyCredentialRequestOptions {
  const opts = (o.publicKey as AnyRec) ?? o;
  return {
    ...(opts as unknown as PublicKeyCredentialRequestOptions),
    challenge: dec(opts.challenge as string),
    allowCredentials: ((opts.allowCredentials as AnyRec[] | undefined) ?? []).map((c) => ({ ...c, id: dec(c.id as string) }) as PublicKeyCredentialDescriptor),
  };
}

export function credentialToJson(cred: PublicKeyCredential): AnyRec {
  const r = cred.response;
  const out: AnyRec = {
    id: cred.id,
    rawId: b64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: (cred as unknown as { authenticatorAttachment?: string }).authenticatorAttachment ?? null,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: { clientDataJSON: b64u(r.clientDataJSON) },
  };
  const resp = out.response as AnyRec;
  if ("attestationObject" in r) {
    const a = r as AuthenticatorAttestationResponse;
    resp.attestationObject = b64u(a.attestationObject);
    resp.transports = typeof a.getTransports === "function" ? a.getTransports() : [];
  } else {
    const a = r as AuthenticatorAssertionResponse;
    resp.authenticatorData = b64u(a.authenticatorData);
    resp.signature = b64u(a.signature);
    resp.userHandle = a.userHandle ? b64u(a.userHandle) : null;
  }
  return out;
}

export async function registerPasskey(options: AnyRec): Promise<AnyRec> {
  const cred = (await navigator.credentials.create({ publicKey: parseCreationOptions(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey registration cancelled");
  return credentialToJson(cred);
}

export async function authenticatePasskey(options: AnyRec): Promise<AnyRec> {
  const cred = (await navigator.credentials.get({ publicKey: parseRequestOptions(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey authentication cancelled");
  return credentialToJson(cred);
}
