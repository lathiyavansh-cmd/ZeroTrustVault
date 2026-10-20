import { useState } from "react";
import { Navigate, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { useApp } from "./state";
import { api } from "./api/client";
import Login from "./pages/Login";
import Enrol from "./pages/Enrol";
import Files from "./pages/Files";
import Admin from "./pages/Admin";
import Dashboard from "./pages/Dashboard";

export function SecurityBar() {
  const { session, keys, cert, deviceKeyPresent, orgRoot, curves, mode } = useApp();
  const ztv = mode === "zerotrustvault";
  return (
    <div className="secbar">
      <span className={`badge ${ztv ? "ok" : "warn"}`}>mode: {mode}</span>
      <span className={`badge ${deviceKeyPresent ? "ok" : "warn"}`}>device key: {deviceKeyPresent ? "present (non-extractable, IndexedDB)" : "none"}</span>
      <span className={`badge ${session.accessToken ? "ok" : ""}`}>session: {session.accessToken ? `${session.tokenType}${session.user ? " / " + session.user.username : ""}` : "none"}</span>
      <span className={`badge ${keys ? "ok" : "warn"}`}>keys: {keys ? `unlocked (${keys.backend === "webcrypto" ? "Web Crypto, non-extractable" : "noble fallback, in-memory"})` : "locked"}</span>
      <span className={`badge ${cert ? "ok" : "warn"}`}>cert: {cert ? `issued (serial ${cert.serial.slice(0, 8)}…)` : "none"}</span>
      <span className={`badge ${orgRoot.pinned ? "ok" : orgRoot.pk ? "warn" : "bad"}`}>org root: {orgRoot.pinned ? "pinned (build)" : orgRoot.pk ? "unpinned (dev)" : "unavailable"}</span>
      {curves && !(curves.ed && curves.x) && <span className="badge warn">Web Crypto lacks {!curves.ed ? "Ed25519 " : ""}{!curves.x ? "X25519" : ""} → @noble fallback</span>}
      {session.risk && <span className={`badge ${session.risk.score >= 60 ? "bad" : ""}`}>risk: {session.risk.score} ({session.risk.level})</span>}
    </div>
  );
}

function StepUpModal() {
  const { stepUpPrompt } = useApp();
  const [code, setCode] = useState("");
  if (!stepUpPrompt) return null;
  return (
    <div className="modal-bg">
      <div className="modal">
        <h3>Step-up authentication required</h3>
        <p className="small muted">The policy engine flagged this session as high risk (risk score ≥ 60). Enter a fresh TOTP code to continue.</p>
        <label>TOTP code</label>
        <input value={code} onChange={(e) => setCode(e.target.value)} autoFocus inputMode="numeric" />
        <div className="row" style={{ marginTop: 10 }}>
          <button className="primary" onClick={() => stepUpPrompt.resolve(code)}>Verify</button>
          <button onClick={() => stepUpPrompt.resolve(null)}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { session } = useApp();
  const nav = useNavigate();
  const authed = !!session.accessToken && !!session.user;
  return (
    <>
      <div className="topbar">
        <span className="brand">ZeroTrustVault</span>
        <nav>
          <NavLink to="/files">Files</NavLink>
          <NavLink to="/dashboard">Dashboard</NavLink>
          <NavLink to="/enrol">Keys</NavLink>
          {session.user?.role === "admin" && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <span style={{ marginLeft: "auto" }} className="small muted">
          {authed ? (
            <>
              {session.user!.username} ({session.user!.role}, {session.user!.department}, clearance {session.user!.clearance}){" "}
              <button onClick={() => api.logout().then(() => nav("/login"))}>Logout</button>
            </>
          ) : (
            "not signed in"
          )}
        </span>
      </div>
      <SecurityBar />
      <StepUpModal />
      <main>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/enrol" element={authed ? <Enrol /> : <Navigate to="/login" />} />
          <Route path="/files" element={authed ? <Files /> : <Navigate to="/login" />} />
          <Route path="/admin" element={authed ? <Admin /> : <Navigate to="/login" />} />
          <Route path="/dashboard" element={authed ? <Dashboard /> : <Navigate to="/login" />} />
          <Route path="*" element={<Navigate to={authed ? "/files" : "/login"} />} />
        </Routes>
      </main>
    </>
  );
}
