// First login on a device: generate/unlock keys, request a cert (out-of-band fingerprint confirmation), TOTP + passkey setup.
import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, ApiError } from "../api/client";
import { useApp } from "../state";
import { generatePrivateKeysPkcs8, importUserKeys, openPrivateKeys, sealPrivateKeys, type SealedBlob, type UserKeys } from "../crypto/keys";
import { certFingerprint, verifyUserCert, type UserCert } from "../crypto/sign";
import { b64uDecode } from "../crypto/encoding";
import { registerPasskey } from "../api/webauthn";

type CertReq = { status: "pending" | "confirmed" | "issued"; fingerprint: string; cert?: UserCert };

export default function Enrol() {
  const { session, keys, setKeys, cert, setCert, orgRoot, mode } = useApp();
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
    if (pass.length < 8) return setErr("passphrase must be at least 8 characters");
    if (pass !== pass2) return setErr("passphrases do not match");
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
    } catch (e) {
      setErr((e as Error).message);
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
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const fpGroups = fingerprint ? fingerprint.split(" ") : null;

  return (
    <div className="grid">
      <div className="card">
        <h2>Encryption keys</h2>
        {!ztv && <p className="small muted">Baseline mode: the server encrypts with a static key; client keys are not used.</p>}
        {blob === "loading" ? (
          <p className="muted">Checking for a sealed key blob…</p>
        ) : keys ? (
          <>
            <p className="okc">Keys unlocked for this session ({keys.backend === "webcrypto" ? "non-extractable Web Crypto keys" : "@noble fallback, held in memory only"}).</p>
            <p className="small mono">enc_pk {keys.encPk}<br />sig_pk {keys.sigPk}</p>
          </>
        ) : blob ? (
          <>
            <p className="small">A sealed key blob exists (Argon2id m={blob.kdf.m} KiB, t={blob.kdf.t}, p={blob.kdf.p}). Unlock it with your key passphrase.</p>
            <label>Key passphrase</label>
            <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === "Enter" && unlock()} />
            <div className="row" style={{ marginTop: 8 }}>
              <button className="primary" onClick={unlock} disabled={!!busy}>Unlock</button>
            </div>
          </>
        ) : (
          <>
            <p className="small">No keys yet. Generate an X25519 + Ed25519 pair; the private halves are sealed under an Argon2id-derived KEK before upload. The server only ever sees the sealed blob.</p>
            <label>Key passphrase (≥ 8 chars)</label>
            <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
            <label>Repeat</label>
            <input type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} />
            <div className="row" style={{ marginTop: 8 }}>
              <button className="primary" onClick={generate} disabled={!!busy}>Generate &amp; seal</button>
            </div>
          </>
        )}
        {busy && <p className="muted small">{busy}</p>}
        {err && <p className="err small">{err}</p>}
      </div>

      <div className="card">
        <h2>Certificate (Org CA, offline)</h2>
        <p className="small muted">Pinned root: <span className="mono">{orgRoot.b64u || "—"}</span> {orgRoot.pinned ? "(build-time pin)" : <b className="err">unpinned (dev)</b>}</p>
        {fpGroups && (
          <>
            <p className="small">Your key fingerprint — confirm it out-of-band with the administrator:</p>
            <div className="fp">{fpGroups.map((g, i) => <span key={i}>{g} </span>)}</div>
          </>
        )}
        {cert ? (
          <p style={{ marginTop: 10 }}>
            <span className={`badge ${certVerified === false ? "bad" : certVerified ? "ok" : "warn"}`}>
              cert issued: serial {cert.serial}, exp {cert.exp} — {certVerified === null ? "not verified (no root)" : certVerified ? "verified against pinned root" : "SIGNATURE INVALID"}
            </span>
          </p>
        ) : reqId ? (
          <p style={{ marginTop: 10 }}>
            <span className="badge warn">request {reqId.slice(0, 8)}…: {reqStatus?.status ?? "pending"}</span>{" "}
            <span className="muted small">{reqStatus?.status === "confirmed" ? "confirmed — waiting for the offline CA signer to publish the cert…" : "waiting for out-of-band confirmation…"}</span>
          </p>
        ) : keys ? (
          <button onClick={requestCert} disabled={!!busy}>Request certificate</button>
        ) : (
          <p className="muted small">Unlock or generate keys first.</p>
        )}
      </div>

      <div className="card">
        <h2>Second factors</h2>
        <div className="row">
          <button onClick={totpSetup}>Set up TOTP</button>
          <button onClick={passkey} disabled={!("credentials" in navigator)}>Register passkey (WebAuthn)</button>
        </div>
        {totp && (
          <div style={{ marginTop: 10 }}>
            <img src={totp.qr} alt="TOTP QR" width={180} height={180} />
            <p className="small mono">secret: {totp.secret}</p>
            <label>Code from authenticator</label>
            <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} inputMode="numeric" />
            <div className="row" style={{ marginTop: 8 }}>
              <button className="primary" onClick={totpConfirm}>Confirm</button>
            </div>
          </div>
        )}
        {msg && <p className="okc small">{msg}</p>}
      </div>

      <div className="card">
        <h2>Session</h2>
        <table>
          <tbody>
            <tr><th>user</th><td>{user.username} ({user.role}, {user.department}, clearance {user.clearance})</td></tr>
            <tr><th>device id</th><td className="mono">{session.deviceId ?? "—"}</td></tr>
            <tr><th>token</th><td>{session.tokenType}{session.tokenType === "DPoP" ? ", 5-min, auto-refresh" : ", 30-day bearer"}</td></tr>
            <tr><th>clock skew</th><td>{api.skewSeconds}s (from X-Server-Time)</td></tr>
            <tr><th>elevated until</th><td>{session.elevatedUntil ?? "—"}</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
