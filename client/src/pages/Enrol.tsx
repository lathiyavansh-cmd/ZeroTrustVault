// First login on a device: generate/unlock keys, request a cert (out-of-band fingerprint confirmation), TOTP + passkey setup.
import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, ApiError } from "../api/client";
import { useApp } from "../state";
import { generatePrivateKeysPkcs8, importUserKeys, openPrivateKeys, sealPrivateKeys, type SealedBlob, type UserKeys } from "../crypto/keys";
import { certFingerprint, verifyUserCert, type UserCert } from "../crypto/sign";
import { b64uDecode } from "../crypto/encoding";
import { registerPasskey } from "../api/webauthn";
import { AlertBox, Badge, Button, Card, CopyButton, FingerprintDisplay, Icons, PageHead, Spinner, Stepper, useToast, type StepState } from "../components/ui";

type CertReq = { status: "pending" | "confirmed" | "issued"; fingerprint: string; cert?: UserCert };

export default function Enrol() {
  const { session, keys, setKeys, cert, setCert, orgRoot, mode } = useApp();
  const toast = useToast();
  const user = session.user!;
  const [blob, setBlob] = useState<SealedBlob | null | "loading">("loading");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [reqId, setReqId] = useState<string | null>(() => localStorage.getItem(`ztv.certreq.${user.id}`));
  const [reqStatus, setReqStatus] = useState<CertReq | null>(null);
  const [certVerified, setCertVerified] = useState<boolean | null>(null);
  const [totp, setTotp] = useState<{ secret: string; otpauth_uri: string; qr: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const ztv = mode === "zerotrustvault";

  useEffect(() => {
    api.get<SealedBlob>("/api/keys/blob").then(setBlob).catch((e) => setBlob(e instanceof ApiError && e.status === 404 ? null : null));
  }, []);

  // Load my cert from the directory if issued.
  const loadCert = useCallback(async () => {
    try {
      const r = await api.get<{ cert: UserCert }>(`/api/keys/directory/${user.id}`);
      if (r.cert) {
        setCert(r.cert);
        setCertVerified(orgRoot.pk ? await verifyUserCert(r.cert, orgRoot.pk, { expectedUserId: user.id }) : null);
        setFingerprint(await certFingerprint(b64uDecode(r.cert.enc_pk), b64uDecode(r.cert.sig_pk)));
        return true;
      }
    } catch {
      /* no cert yet */
    }
    return false;
  }, [user.id, orgRoot.pk, setCert]);

  useEffect(() => {
    loadCert();
  }, [loadCert]);

  // Poll the cert request until issued.
  useEffect(() => {
    if (!reqId || cert) return;
    let stop = false;
    const tick = async () => {
      try {
        const r = await api.get<CertReq>(`/api/keys/cert-request/${reqId}`);
        if (stop) return;
        setReqStatus(r);
        setFingerprint(r.fingerprint);
        if (r.status === "issued") {
          if (r.cert) {
            setCert(r.cert);
            setCertVerified(orgRoot.pk ? await verifyUserCert(r.cert, orgRoot.pk, { expectedUserId: user.id }) : null);
          } else await loadCert();
          localStorage.removeItem(`ztv.certreq.${user.id}`);
        }
      } catch {
        /* keep polling */
      }
    };
    tick();
    const h = setInterval(tick, 3000);
    return () => {
      stop = true;
      clearInterval(h);
    };
  }, [reqId, cert, orgRoot.pk, user.id, setCert, loadCert]);

  const afterUnlock = async (k: UserKeys) => {
    setKeys(k);
    setFingerprint(await certFingerprint(k.enc.publicKey, k.sig.publicKey));
  };

  const generate = async () => {
    setErr(null);
    if (pass.length < 8) return setErr("Passphrase must be at least 8 characters.");
    if (pass !== pass2) return setErr("Passphrases do not match.");
    setBusy("Generating keys and sealing with Argon2id (64 MiB)…");
    try {
      const sk = generatePrivateKeysPkcs8();
      const sealed = await sealPrivateKeys(sk, pass);
      const k = await importUserKeys(sk);
      sk.enc_sk.fill(0);
      sk.sig_sk.fill(0);
      await api.put("/api/keys/blob", { blob: sealed });
      setBlob(sealed);
      await afterUnlock(k);
      const r = await api.post<{ request_id: string; fingerprint: string; status: string }>("/api/keys/cert-request", { enc_pk: k.encPk, sig_pk: k.sigPk });
      localStorage.setItem(`ztv.certreq.${user.id}`, r.request_id);
      setReqId(r.request_id);
      setPass("");
      setPass2("");
      toast.success("Keys generated and sealed", "Certificate request submitted — confirm the fingerprint out-of-band.");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const unlock = async () => {
    if (!blob || blob === "loading") return;
    setErr(null);
    setBusy("Deriving KEK (Argon2id) and opening key blob…");
    try {
      const k = await openPrivateKeys(blob, pass);
      await afterUnlock(k);
      setPass("");
      if (cert && (cert.enc_pk !== k.encPk || cert.sig_pk !== k.sigPk)) setErr("WARNING: unlocked keys do not match the issued certificate");
      else toast.success("Keys unlocked", k.backend === "webcrypto" ? "Non-extractable Web Crypto keys for this session." : "@noble fallback — keys held in memory only.");
    } catch (e) {
      setErr(`Could not open the key blob — wrong passphrase? (${(e as Error).message})`);
    } finally {
      setBusy(null);
    }
  };

  const requestCert = async () => {
    if (!keys) return;
    setBusy("Requesting certificate…");
    try {
      const r = await api.post<{ request_id: string }>("/api/keys/cert-request", { enc_pk: keys.encPk, sig_pk: keys.sigPk });
      localStorage.setItem(`ztv.certreq.${user.id}`, r.request_id);
      setReqId(r.request_id);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const totpSetup = async () => {
    setErr(null);
    try {
      const r = await api.post<{ secret: string; otpauth_uri: string }>("/api/auth/totp/setup");
      setTotp({ ...r, qr: await QRCode.toDataURL(r.otpauth_uri, { margin: 1, width: 180 }) });
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const totpConfirm = async () => {
    try {
      await api.post("/api/auth/totp/confirm", { code: totpCode });
      setTotp(null);
      setTotpCode("");
      setMsg("TOTP confirmed.");
      toast.success("TOTP confirmed");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const passkey = async () => {
    setErr(null);
    try {
      const options = await api.post<Record<string, unknown>>("/api/auth/webauthn/register/options");
      const credential = await registerPasskey(options);
      await api.post("/api/auth/webauthn/register/verify", { credential });
      setMsg("Passkey registered.");
      toast.success("Passkey registered");
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  // Stepper state derivation
  const haveBlob = blob !== "loading" && !!blob;
  const stepKeys: StepState = keys ? "done" : haveBlob ? "active" : blob === "loading" ? "todo" : "active";
  const stepBlob: StepState = haveBlob ? "done" : keys ? "active" : "todo";
  const stepReq: StepState = cert || reqId ? "done" : keys ? "active" : "todo";
  const stepWait: StepState = cert ? "done" : reqId ? "waiting" : "todo";
  const stepIssued: StepState = cert ? "done" : "todo";

  return (
    <>
      <PageHead title="Enrol / Keys" sub={ztv ? "Client-side X25519 + Ed25519 keys, sealed under an Argon2id passphrase; the org CA issues your certificate offline." : "Baseline mode: the server encrypts with a static key; client keys are not used."} />
      <div className="grid-2">
        <div className="stack">
          <Card title="Enrolment progress" sub={`${user.username} · ${user.role} · ${user.department}`}>
            <Stepper
              steps={[
                { title: "Generate or unlock keys", state: stepKeys, body: keys ? `Unlocked (${keys.backend === "webcrypto" ? "Web Crypto, non-extractable" : "@noble fallback, in memory"})` : haveBlob ? "A sealed blob exists — unlock it with your passphrase" : "No keys on the server yet" },
                { title: "Upload sealed key blob", state: stepBlob, body: blob !== "loading" && blob ? `Argon2id m=${blob.kdf.m} KiB, t=${blob.kdf.t}, p=${blob.kdf.p} — server only holds ciphertext` : "Private halves are sealed before upload" },
                { title: "Submit certificate request", state: stepReq, body: reqId ? <span className="mono">request {reqId.slice(0, 8)}…</span> : "Public keys are sent to the org CA" },
                {
                  title: "Out-of-band fingerprint confirmation",
                  state: stepWait,
                  body: cert ? "Confirmed" : reqId ? (
                    <span className="row"><Spinner /> {reqStatus?.status === "confirmed" ? "confirmed — waiting for the offline CA signer to publish the cert…" : "waiting for an administrator to confirm your fingerprint…"}</span>
                  ) : "Read your fingerprint to the administrator over a trusted channel",
                },
                { title: "Certificate issued", state: stepIssued, body: cert ? <span>serial <span className="mono">{cert.serial}</span>, expires {cert.exp}</span> : "Needed before you can upload or share" },
              ]}
            />
          </Card>

          <Card title="Encryption keys" actions={keys && <Badge tone="ok">unlocked</Badge>}>
            {blob === "loading" ? (
              <p className="muted row"><Spinner /> Checking for a sealed key blob…</p>
            ) : keys ? (
              <>
                <AlertBox tone="ok">Keys unlocked for this session ({keys.backend === "webcrypto" ? "non-extractable Web Crypto keys" : "@noble fallback, held in memory only"}).</AlertBox>
                <table className="kv mt3">
                  <tbody>
                    <tr><th>enc_pk (X25519)</th><td className="mono small" style={{ wordBreak: "break-all" }}>{keys.encPk}</td></tr>
                    <tr><th>sig_pk (Ed25519)</th><td className="mono small" style={{ wordBreak: "break-all" }}>{keys.sigPk}</td></tr>
                  </tbody>
                </table>
              </>
            ) : blob ? (
              <>
                <p className="small muted mb4">A sealed key blob exists on the server. Unlock it with your key passphrase — the KEK is derived locally and the blob never leaves the browser in the clear.</p>
                <div className="field">
                  <label htmlFor="kp">Key passphrase</label>
                  <input id="kp" type="password" value={pass} autoComplete="current-password" onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === "Enter" && unlock()} />
                </div>
                <div className="row mt3">
                  <Button variant="primary" onClick={unlock} busy={!!busy} icon={Icons.key({ size: 14 })}>Unlock keys</Button>
                </div>
              </>
            ) : (
              <>
                <p className="small muted mb4">No keys yet. Generate an X25519 + Ed25519 pair; the private halves are sealed under an Argon2id-derived KEK before upload. The server only ever sees the sealed blob.</p>
                <div className="field">
                  <label htmlFor="np">Key passphrase (≥ 8 chars)</label>
                  <input id="np" type="password" value={pass} autoComplete="new-password" onChange={(e) => setPass(e.target.value)} />
                </div>
                <div className="field">
                  <label htmlFor="np2">Repeat passphrase</label>
                  <input id="np2" type="password" value={pass2} autoComplete="new-password" onChange={(e) => setPass2(e.target.value)} aria-invalid={!!pass2 && pass !== pass2} />
                </div>
                <div className="row mt3">
                  <Button variant="primary" onClick={generate} busy={!!busy}>Generate &amp; seal</Button>
                </div>
              </>
            )}
            {busy && <p className="muted small mt3 row"><Spinner /> {busy}</p>}
            {err && <div className="mt3"><AlertBox tone="bad">{err}</AlertBox></div>}
          </Card>
        </div>

        <div className="stack">
          <Card title="Certificate" sub="Issued offline by the Org CA" actions={cert ? <Badge tone={certVerified === false ? "bad" : certVerified ? "ok" : "warn"}>{certVerified === null ? "not verified (no root)" : certVerified ? "verified" : "SIGNATURE INVALID"}</Badge> : reqId ? <Badge tone="warn">{reqStatus?.status ?? "pending"}</Badge> : null}>
            <div className="small muted mb4">
              Pinned org root: <span className="mono" style={{ wordBreak: "break-all" }}>{orgRoot.b64u || "—"}</span>{" "}
              {orgRoot.pinned ? <Badge tone="ok">build-time pin</Badge> : <Badge tone="warn">unpinned (dev)</Badge>}
            </div>
            {fingerprint && (
              <div className="mb4">
                <label>Your key fingerprint — confirm it out-of-band with the administrator</label>
                <FingerprintDisplay fp={fingerprint} />
              </div>
            )}
            {cert ? (
              <table className="kv">
                <tbody>
                  <tr><th>serial</th><td className="mono small">{cert.serial}</td></tr>
                  <tr><th>expires</th><td>{cert.exp}</td></tr>
                  <tr><th>verification</th><td>{certVerified === null ? "not verified (no root)" : certVerified ? <span className="okc">verified against pinned org root</span> : <span className="err">SIGNATURE INVALID</span>}</td></tr>
                </tbody>
              </table>
            ) : reqId ? (
              <AlertBox tone="warn">
                Request <span className="mono">{reqId.slice(0, 8)}…</span> is <b>{reqStatus?.status ?? "pending"}</b>. {reqStatus?.status === "confirmed" ? "Waiting for the offline CA signer to publish the certificate." : "Waiting for out-of-band fingerprint confirmation by an administrator."}
              </AlertBox>
            ) : keys ? (
              <Button onClick={requestCert} busy={!!busy}>Request certificate</Button>
            ) : (
              <p className="muted small">Unlock or generate keys first.</p>
            )}
          </Card>

          <Card title="Second factors">
            <div className="row">
              <Button onClick={totpSetup}>Set up TOTP</Button>
              <Button onClick={passkey} disabled={!("credentials" in navigator)} icon={Icons.key({ size: 14 })}>Register passkey (WebAuthn)</Button>
            </div>
            {totp && (
              <div className="mt4">
                <div className="row" style={{ alignItems: "flex-start" }}>
                  <span className="qr"><img src={totp.qr} alt="TOTP QR code" width={180} height={180} style={{ display: "block" }} /></span>
                  <div className="grow">
                    <label>Secret</label>
                    <div className="row"><code>{totp.secret}</code><CopyButton text={totp.secret} /></div>
                    <div className="field mt3">
                      <label htmlFor="totpc">Code from authenticator</label>
                      <input id="totpc" value={totpCode} onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" />
                    </div>
                    <div className="row mt3">
                      <Button variant="primary" onClick={totpConfirm} disabled={totpCode.length < 6}>Confirm</Button>
                      <Button variant="ghost" onClick={() => setTotp(null)}>Cancel</Button>
                    </div>
                  </div>
                </div>
              </div>
            )}
            {msg && <p className="okc small mt3">{msg}</p>}
          </Card>

          <Card title="Session">
            <table className="kv">
              <tbody>
                <tr><th>user</th><td>{user.username} <span className="muted">({user.role}, {user.department}, clearance {user.clearance})</span></td></tr>
                <tr><th>device id</th><td className="mono small">{session.deviceId ?? "—"}</td></tr>
                <tr><th>token</th><td>{session.tokenType}{session.tokenType === "DPoP" ? " · 5-min · auto-refresh" : " · 30-day bearer"}</td></tr>
                <tr><th>clock skew</th><td><span className={Math.abs(api.skewSeconds) > 30 ? "warnc" : ""}>{api.skewSeconds}s</span> <span className="muted">(from X-Server-Time)</span></td></tr>
                <tr><th>elevated until</th><td>{session.elevatedUntil ?? "—"}</td></tr>
              </tbody>
            </table>
          </Card>
        </div>
      </div>
    </>
  );
}
