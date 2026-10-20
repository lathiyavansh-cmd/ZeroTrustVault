import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../state";

interface User {
  id: string;
  username: string;
  role: string;
  department: string;
  clearance: number;
  employment_end?: string | null;
}
interface CertReq {
  id?: string;
  request_id?: string;
  user_id: string;
  username?: string;
  fingerprint: string;
  status: string;
  created_at?: string;
}

export default function Admin() {
  const { mode } = useApp();
  const [users, setUsers] = useState<User[]>([]);
  const [reqs, setReqs] = useState<CertReq[]>([]);
  const [policy, setPolicy] = useState("");
  const [policyErr, setPolicyErr] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [nu, setNu] = useState({ username: "", password: "", role: "analyst", department: "research", clearance: 1, employment_end: "" });
  const [confirmFp, setConfirmFp] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    api.get<User[]>("/api/admin/users").then(setUsers).catch((e) => setErr((e as Error).message));
    api.get<CertReq[]>("/api/admin/cert-requests?status=pending").then(setReqs).catch(() => setReqs([]));
    api.get<unknown>("/api/policy").then((p) => setPolicy(JSON.stringify(p, null, 2))).catch(() => undefined);
  }, []);
  useEffect(load, [load]);

  const createUser = async () => {
    setErr(null);
    try {
      const body: Record<string, unknown> = { ...nu, clearance: Number(nu.clearance) };
      if (!nu.employment_end) delete body.employment_end;
      await api.post("/api/admin/users", body);
      setMsg(`user ${nu.username} created`);
      setNu({ ...nu, username: "", password: "" });
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const confirmReq = async (r: CertReq) => {
    const id = r.request_id ?? r.id!;
    const fp = (confirmFp[id] ?? "").trim().toUpperCase();
    if (fp !== r.fingerprint) return setErr("fingerprint typed does not match the request — out-of-band confirmation failed");
    try {
      await api.post(`/api/admin/cert-requests/${id}/confirm`, { fingerprint: fp });
      setMsg(`request ${id.slice(0, 8)}… confirmed; the offline CA signer will publish the certificate`);
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const savePolicy = async () => {
    setPolicyErr(null);
    try {
      const parsed = JSON.parse(policy);
      await api.put("/api/policy", parsed);
      setMsg("policy saved");
    } catch (e) {
      setPolicyErr((e as Error).message);
    }
  };

  return (
    <>
      <div className="row" style={{ marginBottom: 10 }}>
        <span className={`badge ${mode === "zerotrustvault" ? "ok" : "warn"}`}>mode: {mode}</span>
        {msg && <span className="okc small">{msg}</span>}
        {err && <span className="err small">{err}</span>}
      </div>
      <div className="grid">
        <div className="card">
          <h2>Pending certificate requests (out-of-band confirmation)</h2>
          <p className="small muted">Read the fingerprint back from the user over a trusted channel and type it here to confirm.</p>
          {reqs.map((r) => {
            const id = r.request_id ?? r.id!;
            return (
              <div key={id} style={{ marginBottom: 10 }}>
                <div className="small">{r.username ?? r.user_id} — <span className="mono">{id}</span></div>
                <div className="fp">{r.fingerprint}</div>
                <div className="row" style={{ marginTop: 6 }}>
                  <input placeholder="type fingerprint to confirm" value={confirmFp[id] ?? ""} onChange={(e) => setConfirmFp({ ...confirmFp, [id]: e.target.value })} style={{ flex: 1 }} />
                  <button className="primary" onClick={() => confirmReq(r)}>Confirm</button>
                  <button onClick={() => setConfirmFp({ ...confirmFp, [id]: r.fingerprint })} title="demo shortcut">paste</button>
                </div>
              </div>
            );
          })}
          {reqs.length === 0 && <p className="muted small">none pending</p>}
        </div>

        <div className="card">
          <h2>Create user</h2>
          <label>Username</label><input value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} />
          <label>Password</label><input type="password" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} />
          <div className="row">
            <div style={{ flex: 1 }}><label>Role</label>
              <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}><option>analyst</option><option>manager</option><option>auditor</option><option>admin</option></select></div>
            <div style={{ flex: 1 }}><label>Department</label>
              <select value={nu.department} onChange={(e) => setNu({ ...nu, department: e.target.value })}><option>research</option><option>finance</option><option>audit</option><option>it</option></select></div>
            <div style={{ flex: 1 }}><label>Clearance</label>
              <select value={nu.clearance} onChange={(e) => setNu({ ...nu, clearance: Number(e.target.value) })}><option value={0}>0 PUBLIC</option><option value={1}>1 INTERNAL</option><option value={2}>2 CONFIDENTIAL</option><option value={3}>3 SECRET</option></select></div>
          </div>
          <label>Employment end (optional, ISO)</label><input value={nu.employment_end} onChange={(e) => setNu({ ...nu, employment_end: e.target.value })} placeholder="2026-12-31T00:00:00Z" />
          <div className="row" style={{ marginTop: 8 }}><button className="primary" onClick={createUser}>Create</button></div>
        </div>

        <div className="card">
          <h2>Users</h2>
          <table>
            <thead><tr><th>username</th><th>role</th><th>dept</th><th>clr</th><th>end</th></tr></thead>
            <tbody>{users.map((u) => <tr key={u.id}><td>{u.username}</td><td>{u.role}</td><td>{u.department}</td><td>{u.clearance}</td><td>{u.employment_end ?? "—"}</td></tr>)}</tbody>
          </table>
        </div>

        <div className="card" style={{ gridColumn: "1 / -1" }}>
          <h2>Policy (deny-overrides, first PERMIT, default DENY)</h2>
          <textarea className="mono" value={policy} onChange={(e) => setPolicy(e.target.value)} spellCheck={false} />
          {policyErr && <p className="err small">{policyErr}</p>}
          <div className="row" style={{ marginTop: 8 }}><button className="primary" onClick={savePolicy}>Save policy</button><button onClick={load}>Reload</button></div>
        </div>
      </div>
    </>
  );
}
