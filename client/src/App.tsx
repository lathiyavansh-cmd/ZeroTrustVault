import { useEffect, useRef, useState, type FormEvent } from "react";
import { Navigate, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { useApp } from "./state";
import { api } from "./api/client";
import Login from "./pages/Login";
import Enrol from "./pages/Enrol";
import Files from "./pages/Files";
import Admin from "./pages/Admin";
import Dashboard from "./pages/Dashboard";
import Grants from "./pages/Grants";
import Settings from "./pages/Settings";
import { Badge, BrandMark, Button, Dot, Icons, Modal, initials } from "./components/ui";

function useCountdown(expiresAt: number) {
  const [left, setLeft] = useState(() => Math.max(0, Math.round((expiresAt - Date.now()) / 1000)));
  useEffect(() => {
    const h = setInterval(() => setLeft(Math.max(0, Math.round((expiresAt - Date.now()) / 1000))), 1000);
    return () => clearInterval(h);
  }, [expiresAt]);
  return left;
}

export function SecurityBar() {
  const { session, keys, cert, deviceKeyPresent, orgRoot, curves, mode } = useApp();
  const ztv = mode === "zerotrustvault";
  const left = useCountdown(session.expiresAt);
  const mm = String(Math.floor(left / 60)).padStart(2, "0");
  const ss = String(left % 60).padStart(2, "0");
  const risk = session.risk;
  const riskTone = !risk ? "neutral" : risk.score >= 85 ? "bad" : risk.score >= 60 ? "warn" : "ok";
  return (
    <div className={`posture ${ztv ? "" : "danger"}`} role="status" aria-label="security posture">
      <span className={`posture-item ${ztv ? "ok" : "bad"}`}>
        <Dot tone={ztv ? "ok" : "bad"} />
        mode <b>{ztv ? "ZeroTrustVault" : "BASELINE (insecure)"}</b>
      </span>
      <span className={`posture-item ${deviceKeyPresent ? "ok" : "warn"}`} title={deviceKeyPresent ? "Non-extractable ECDSA P-256 key in IndexedDB" : "No device key yet"}>
        <Dot tone={deviceKeyPresent ? "ok" : "warn"} />
        device key <b>{deviceKeyPresent ? "present" : "none"}</b>
      </span>
      <span className={`posture-item ${keys ? "ok" : "warn"}`} title={keys ? (keys.backend === "webcrypto" ? "Web Crypto, non-extractable" : "@noble fallback, in-memory") : "Unlock on the Keys page"}>
        <Dot tone={keys ? "ok" : "warn"} />
        keys <b>{keys ? (keys.backend === "webcrypto" ? "unlocked · webcrypto" : "unlocked · noble") : "locked"}</b>
      </span>
      <span className={`posture-item ${cert ? "ok" : "warn"}`} title={cert ? `serial ${cert.serial}` : "No certificate issued"}>
        <Dot tone={cert ? "ok" : "warn"} />
        cert <b>{cert ? `issued ${cert.serial.slice(0, 8)}…` : "none"}</b>
      </span>
      <span className={`posture-item ${orgRoot.pinned ? "ok" : orgRoot.pk ? "warn" : "bad"}`}>
        <Dot tone={orgRoot.pinned ? "ok" : orgRoot.pk ? "warn" : "bad"} />
        org root <b>{orgRoot.pinned ? "pinned" : orgRoot.pk ? "unpinned (dev)" : "unavailable"}</b>
      </span>
      {curves && !(curves.ed && curves.x) && (
        <span className="posture-item warn" title="crypto.subtle lacks the curve; @noble fallback is used">
          <Dot tone="warn" />
          no WebCrypto {!curves.ed ? "Ed25519 " : ""}{!curves.x ? "X25519" : ""}
        </span>
      )}
      {session.accessToken && (
        <>
          {risk && (
            <span className={`posture-item ${riskTone}`}>
              <Dot tone={riskTone} />
              risk <b>{risk.score} · {risk.level}</b>
            </span>
          )}
          <span className={`posture-item ${left === 0 && session.tokenType === "DPoP" ? "warn" : ""}`} title={session.tokenType === "DPoP" ? "5-minute DPoP-bound access token, auto-refreshed" : "30-day bearer token"}>
            <Dot tone={session.tokenType === "DPoP" ? "info" : "bad"} />
            {session.tokenType} <b className="countdown">{session.tokenType === "DPoP" ? `${mm}:${ss}` : "30d"}</b>
          </span>
        </>
      )}
    </div>
  );
}

function StepUpModal() {
  const { stepUpPrompt } = useApp();
  const [code, setCode] = useState("");
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (stepUpPrompt) setCode("");
  }, [stepUpPrompt]);
  if (!stepUpPrompt) return null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (code.length >= 6) stepUpPrompt.resolve(code);
  };
  return (
    <Modal title="Step-up authentication required" onClose={() => stepUpPrompt.resolve(null)}>
      <form onSubmit={submit}>
        <div className="alertbox warn mb4">
          {Icons.alert({ size: 16 })}
          <div>The policy engine flagged this session as high risk (score ≥ 60). A fresh TOTP code is required to continue.</div>
        </div>
        <label htmlFor="stepup-code">TOTP code</label>
        <input id="stepup-code" ref={ref} className="code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
        <div className="row end mt4">
          <Button onClick={() => stepUpPrompt.resolve(null)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={code.length < 6}>Verify</Button>
        </div>
      </form>
    </Modal>
  );
}

function Sidebar() {
  const { session } = useApp();
  const nav = useNavigate();
  const u = session.user!;
  return (
    <aside className="sidebar">
      <div className="brand">
        <BrandMark />
        <div>
          <div className="brand-name">ZeroTrustVault</div>
          <div className="brand-sub">secure file sharing</div>
        </div>
      </div>
      <div className="nav-section">Workspace</div>
      <nav className="nav" aria-label="Main">
        <NavLink to="/files">{Icons.files()} Files</NavLink>
        <NavLink to="/grants">{Icons.share()} Share / Grants</NavLink>
        <NavLink to="/dashboard">{Icons.dashboard()} Dashboard</NavLink>
        {u.role === "admin" && <NavLink to="/admin">{Icons.admin()} Admin</NavLink>}
      </nav>
      <div className="nav-section">Identity</div>
      <nav className="nav" aria-label="Identity">
        <NavLink to="/enrol">{Icons.key()} Enrol / Keys</NavLink>
        <NavLink to="/settings">{Icons.settings()} Settings</NavLink>
      </nav>
      <div className="sidebar-user">
        <div className="row" style={{ flexWrap: "nowrap" }}>
          <span className="avatar" aria-hidden="true">{initials(u.username)}</span>
          <div className="grow user-meta">
            <div style={{ fontWeight: 600 }} className="truncate">{u.username}</div>
            <div className="xs muted truncate">{u.department} · clearance {u.clearance}</div>
          </div>
          <Button variant="ghost" size="sm" aria-label="Sign out" title="Sign out" onClick={() => api.logout().then(() => nav("/login"))} icon={Icons.logout({ size: 16 })} />
        </div>
        <div className="chips mt2">
          <Badge tone="info">{u.role}</Badge>
          <Badge>{u.department}</Badge>
          <Badge tone={u.clearance >= 3 ? "bad" : u.clearance === 2 ? "warn" : "neutral"}>L{u.clearance}</Badge>
        </div>
      </div>
    </aside>
  );
}

export default function App() {
  const { session } = useApp();
  const authed = !!session.accessToken && !!session.user;
  if (!authed) {
    return (
      <>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </>
    );
  }
  return (
    <div className="shell">
      <Sidebar />
      <div className="main">
        <SecurityBar />
        <StepUpModal />
        <main className="page">
          <Routes>
            <Route path="/login" element={<Navigate to="/files" />} />
            <Route path="/enrol" element={<Enrol />} />
            <Route path="/files" element={<Files />} />
            <Route path="/grants" element={<Grants />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/admin" element={<Admin />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="*" element={<Navigate to="/files" />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
