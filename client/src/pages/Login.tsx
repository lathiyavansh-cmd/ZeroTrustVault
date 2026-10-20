import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError, type SessionUser } from "../api/client";
import { useApp } from "../state";
import { authenticatePasskey } from "../api/webauthn";

type LoginOk = { token_type: "DPoP" | "Bearer"; access_token: string; refresh_token?: string; expires_in?: number; user: SessionUser; device_id?: string; risk?: { score: number; level: string } };
type LoginResp = ({ status: "mfa_required"; login_ticket: string; methods: string[] } | ({ status: "ok" } & LoginOk));

export default function Login() {
  const { mode, refreshDevice } = useApp();
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [deviceName, setDeviceName] = useState(() => localStorage.getItem("ztv.deviceName") || "browser");
  const [posture, setPosture] = useState<"registered" | "trusted">("registered");
  const [ticket, setTicket] = useState<{ login_ticket: string; methods: string[] } | null>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.loadMode().catch(() => undefined);
  }, []);

  const finish = (j: LoginOk) => {
    api.applyLoginResponse(j);
    refreshDevice();
    nav("/enrol");
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const dk = await api.deviceKey();
      localStorage.setItem("ztv.deviceName", deviceName);
      const r = await api.request<LoginResp>("POST", "/api/auth/login", { auth: false, body: { username, password, device: { jwk: dk.publicJwk, name: deviceName, posture } } });
      setPassword("");
      if (r.status === "ok") finish(r);
      else setTicket({ login_ticket: r.login_ticket, methods: r.methods });
    } catch (e) {
      setErr(e instanceof ApiError ? `login failed (${e.status}${e.code ? " " + e.code : ""})` : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const totp = async (e: FormEvent) => {
    e.preventDefault();
    if (!ticket) return;
    setBusy(true);
    setErr(null);
    try {
      finish(await api.request<LoginOk>("POST", "/api/auth/mfa/totp", { auth: false, body: { login_ticket: ticket.login_ticket, code } }));
    } catch (e) {
      setErr(e instanceof ApiError ? `MFA failed (${e.status}${e.code ? " " + e.code : ""})` : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const passkey = async () => {
    if (!ticket) return;
    setBusy(true);
    setErr(null);
    try {
      const options = await api.request<Record<string, unknown>>("POST", "/api/auth/webauthn/login/options", { auth: false, body: { login_ticket: ticket.login_ticket } });
      const credential = await authenticatePasskey(options);
      finish(await api.request<LoginOk>("POST", "/api/auth/webauthn/login/verify", { auth: false, body: { login_ticket: ticket.login_ticket, credential } }));
    } catch (e) {
      setErr(e instanceof ApiError ? `passkey login failed (${e.status})` : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login card">
      <h2>Sign in</h2>
      <p className="small muted">
        Mode: <b>{mode}</b>. {mode === "baseline" ? "Password only, 30-day bearer token, no device binding." : "Password + MFA, 5-minute DPoP-bound token on this device key."}
      </p>
      {!ticket ? (
        <form onSubmit={submit}>
          <label>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus />
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          <div className="row">
            <div style={{ flex: 1 }}>
              <label>Device name</label>
              <input value={deviceName} onChange={(e) => setDeviceName(e.target.value)} />
            </div>
            <div style={{ flex: 1 }}>
              <label>Device posture</label>
              <select value={posture} onChange={(e) => setPosture(e.target.value as "registered" | "trusted")}>
                <option value="registered">registered</option>
                <option value="trusted">trusted</option>
              </select>
            </div>
          </div>
          {err && <p className="err small">{err}</p>}
          <div className="row" style={{ marginTop: 12 }}>
            <button className="primary" disabled={busy}>Continue</button>
          </div>
        </form>
      ) : (
        <form onSubmit={totp}>
          <p className="small">Password accepted. Second factor required ({ticket.methods.join(", ")}).</p>
          {ticket.methods.includes("totp") && (
            <>
              <label>TOTP code</label>
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoFocus />
            </>
          )}
          {err && <p className="err small">{err}</p>}
          <div className="row" style={{ marginTop: 12 }}>
            {ticket.methods.includes("totp") && <button className="primary" disabled={busy}>Verify TOTP</button>}
            {ticket.methods.includes("webauthn") && (
              <button type="button" disabled={busy} onClick={passkey}>Use passkey</button>
            )}
            <button type="button" onClick={() => setTicket(null)}>Back</button>
          </div>
        </form>
      )}
    </div>
  );
}
