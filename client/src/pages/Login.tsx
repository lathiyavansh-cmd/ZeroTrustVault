import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError, type SessionUser } from "../api/client";
import { useApp } from "../state";
import { authenticatePasskey } from "../api/webauthn";
import { AlertBox, BrandMark, Button, Icons } from "../components/ui";

type LoginOk = { token_type: "DPoP" | "Bearer"; access_token: string; refresh_token?: string; expires_in?: number; user: SessionUser; device_id?: string; risk?: { score: number; level: string } };
type LoginResp = ({ status: "mfa_required"; login_ticket: string; methods: string[] } | ({ status: "ok" } & LoginOk));

function describeError(e: unknown, what: string): string {
  if (e instanceof ApiError) {
    if (e.status === 429) return "Too many attempts — this account is temporarily locked. Wait a few minutes and try again.";
    if (e.status === 401) return `${what} failed: invalid credentials${e.code ? ` (${e.code})` : ""}.`;
    if (e.status === 403) return `${what} refused by policy (403).`;
    return `${what} failed (HTTP ${e.status}${e.code ? " " + e.code : ""}).`;
  }
  return (e as Error).message;
}

/** Six-box TOTP input with auto-advance, paste support and backspace navigation. */
function OtpInput({ value, onChange, onComplete, disabled }: { value: string; onChange: (v: string) => void; onComplete?: (v: string) => void; disabled?: boolean }) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const digits = Array.from({ length: 6 }, (_, i) => value[i] ?? "");
  const set = (next: string) => {
    next = next.replace(/\D/g, "").slice(0, 6);
    onChange(next);
    if (next.length === 6) onComplete?.(next);
  };
  const onKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !digits[i] && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowRight" && i < 5) refs.current[i + 1]?.focus();
  };
  return (
    <div className="otp" role="group" aria-label="One-time code">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => (refs.current[i] = el)}
          value={d}
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          aria-label={`digit ${i + 1}`}
          disabled={disabled}
          autoFocus={i === 0}
          onChange={(e) => {
            const v = e.target.value.replace(/\D/g, "");
            if (v.length > 1) return set(value.slice(0, i) + v);
            const next = digits.slice();
            next[i] = v;
            set(next.join(""));
            if (v && i < 5) refs.current[i + 1]?.focus();
          }}
          onKeyDown={(e) => onKey(i, e)}
          onPaste={(e) => {
            e.preventDefault();
            set(e.clipboardData.getData("text"));
            refs.current[5]?.focus();
          }}
        />
      ))}
    </div>
  );
}

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
  const ztv = mode === "zerotrustvault";

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
    if (!username || !password) return setErr("Enter your username and password.");
    setBusy(true);
    try {
      const dk = await api.deviceKey();
      localStorage.setItem("ztv.deviceName", deviceName);
      const r = await api.request<LoginResp>("POST", "/api/auth/login", { auth: false, body: { username, password, device: { jwk: dk.publicJwk, name: deviceName, posture } } });
      setPassword("");
      if (r.status === "ok") finish(r);
      else setTicket({ login_ticket: r.login_ticket, methods: r.methods });
    } catch (e) {
      setErr(describeError(e, "Sign-in"));
    } finally {
      setBusy(false);
    }
  };

  const totp = async (c?: string) => {
    if (!ticket) return;
    const use = c ?? code;
    if (use.length < 6) return setErr("Enter the 6-digit code.");
    setBusy(true);
    setErr(null);
    try {
      finish(await api.request<LoginOk>("POST", "/api/auth/mfa/totp", { auth: false, body: { login_ticket: ticket.login_ticket, code: use } }));
    } catch (e) {
      setErr(describeError(e, "MFA"));
      setCode("");
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
      setErr(describeError(e, "Passkey sign-in"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="brand">
          <BrandMark size={40} />
          <div>
            <div className="brand-name">ZeroTrustVault</div>
            <div className="brand-sub">Acme Research Labs</div>
          </div>
        </div>
        <div className={`mode-banner ${ztv ? "ok" : "bad"}`}>
          {ztv ? (
            <><b>Zero-trust mode.</b> Password + MFA, 5-minute DPoP-bound token on this device's non-extractable key, client-side encryption.</>
          ) : (
            <><b>BASELINE MODE — insecure.</b> Password only, 30-day bearer token, no device binding, server-side encryption.</>
          )}
        </div>

        {!ticket ? (
          <form onSubmit={submit} noValidate>
            <h2 style={{ marginBottom: 4 }}>Sign in</h2>
            <p className="muted small mb4">Step 1 of {ztv ? 2 : 1} · credentials and device</p>
            <div className="field">
              <label htmlFor="username">Username</label>
              <input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus aria-invalid={!!err && !username} />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" aria-invalid={!!err && !password} />
            </div>
            <div className="split mt3">
              <div className="field">
                <label htmlFor="device">Device name</label>
                <input id="device" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="posture">Device posture</label>
                <select id="posture" value={posture} onChange={(e) => setPosture(e.target.value as "registered" | "trusted")}>
                  <option value="registered">registered</option>
                  <option value="trusted">trusted (managed)</option>
                </select>
              </div>
            </div>
            <p className="hint mt2">The device's ECDSA P-256 key never leaves this browser; its thumbprint is bound to every access token.</p>
            {err && <div className="mt3"><AlertBox tone="bad">{err}</AlertBox></div>}
            <Button type="submit" variant="primary" size="lg" className="block mt4" busy={busy}>Continue</Button>
          </form>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); totp(); }} noValidate>
            <h2 style={{ marginBottom: 4 }}>Second factor</h2>
            <p className="muted small mb4">Step 2 of 2 · password accepted for <b>{username}</b></p>
            {ticket.methods.includes("totp") && (
              <>
                <label>Authenticator code</label>
                <OtpInput value={code} onChange={setCode} onComplete={(v) => totp(v)} disabled={busy} />
                <p className="hint mt2" style={{ textAlign: "center" }}>Codes rotate every 30 s; the server tolerates ±1 step of clock skew.</p>
              </>
            )}
            {err && <div className="mt3"><AlertBox tone="bad">{err}</AlertBox></div>}
            <div className="col mt4">
              {ticket.methods.includes("totp") && <Button type="submit" variant="primary" size="lg" className="block" busy={busy} disabled={code.length < 6}>Verify code</Button>}
              {ticket.methods.includes("webauthn") && (
                <Button type="button" size="lg" className="block" disabled={busy} onClick={passkey} icon={Icons.key({ size: 16 })}>Use a passkey instead</Button>
              )}
              <Button type="button" variant="ghost" onClick={() => { setTicket(null); setErr(null); setCode(""); }}>Back</Button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
