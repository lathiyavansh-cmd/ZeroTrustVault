import { useCallback, useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import { api, ApiError } from "../api/client";
import { useApp } from "../state";
import { AlertBox, Badge, Button, Card, CopyButton, EmptyState, FingerprintDisplay, Icons, Modal, PageHead, Spinner, fmtDate, useToast } from "../components/ui";

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
interface Device { id: string; name: string; jkt: string; posture: string; created_at: string; last_seen?: string | null }
interface CreatedUser extends User { totp_secret?: string; otpauth_uri?: string }

const CLEARANCE = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"];

function norm(s: string) {
  return s.trim().toUpperCase().replace(/\s+/g, " ");
}

export default function Admin() {
  const { mode } = useApp();
  const toast = useToast();
  const [users, setUsers] = useState<User[] | null>(null);
  const [reqs, setReqs] = useState<CertReq[]>([]);
  const [policy, setPolicy] = useState("");
  const [policyErr, setPolicyErr] = useState<string | null>(null);
  const [policyDirty, setPolicyDirty] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [nu, setNu] = useState({ username: "", password: "", role: "analyst", department: "research", clearance: 1, employment_end: "" });
  const [confirmFp, setConfirmFp] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<{ user: CreatedUser; qr: string | null } | null>(null);
  const [modeSwitch, setModeSwitch] = useState<{ open: boolean; key: string; busy: boolean }>({ open: false, key: "", busy: false });
  const [devices, setDevices] = useState<{ user: User; list: Device[] | "unavailable" } | null>(null);

  const load = useCallback(() => {
    api.get<User[]>("/api/admin/users").then(setUsers).catch((e) => { setUsers([]); setErr((e as Error).message); });
    api.get<CertReq[]>("/api/admin/cert-requests?status=pending").then(setReqs).catch(() => setReqs([]));
    api.get<unknown>("/api/policy").then((p) => { setPolicy(JSON.stringify(p, null, 2)); setPolicyDirty(false); }).catch(() => undefined);
  }, []);
  useEffect(load, [load]);

  const createUser = async () => {
    setErr(null);
    if (!nu.username || !nu.password) return setErr("Username and password are required.");
    try {
      const body: Record<string, unknown> = { ...nu, clearance: Number(nu.clearance) };
      if (!nu.employment_end) delete body.employment_end;
      const r = await api.post<CreatedUser>("/api/admin/users", body);
      const qr = r?.otpauth_uri ? await QRCode.toDataURL(r.otpauth_uri, { margin: 1, width: 200 }) : null;
      setCreated({ user: { ...r, username: r?.username ?? nu.username }, qr });
      toast.success(`User ${nu.username} created`);
      setNu({ ...nu, username: "", password: "" });
      load();
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 409 ? "That username already exists." : (e as Error).message);
    }
  };

  const confirmReq = async (r: CertReq) => {
    const id = r.request_id ?? r.id!;
    const fp = (confirmFp[id] ?? "").trim().toUpperCase();
    if (fp !== r.fingerprint) return setErr("fingerprint typed does not match the request — out-of-band confirmation failed");
    try {
      await api.post(`/api/admin/cert-requests/${id}/confirm`, { fingerprint: fp });
      toast.success("Certificate request confirmed", "The offline CA signer will publish the certificate.");
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const policyParsed = useMemo(() => {
    try {
      const p = JSON.parse(policy) as { rules?: { id?: string; effect?: string; description?: string }[] };
      return { ok: true as const, rules: Array.isArray(p.rules) ? p.rules : [] };
    } catch (e) {
      return { ok: false as const, error: (e as Error).message };
    }
  }, [policy]);

  const savePolicy = async () => {
    setPolicyErr(null);
    try {
      const parsed = JSON.parse(policy);
      await api.put("/api/policy", parsed);
      setPolicyDirty(false);
      toast.success("Policy saved", "Deny-overrides, first PERMIT, default DENY.");
    } catch (e) {
      setPolicyErr((e as Error).message);
    }
  };

  const switchMode = async () => {
    const target = mode === "zerotrustvault" ? "baseline" : "zerotrustvault";
    setModeSwitch((m) => ({ ...m, busy: true }));
    try {
      await api.request<{ mode: string }>("POST", "/api/admin/mode", { body: { mode: target }, headers: modeSwitch.key ? { "X-Admin-Key": modeSwitch.key } : undefined });
      await api.loadMode();
      toast.success(`Mode switched to ${target}`);
      setModeSwitch({ open: false, key: "", busy: false });
    } catch (e) {
      const msg = e instanceof ApiError ? (e.status === 403 || e.status === 401 ? "Refused — runtime mode switching is disabled (ALLOW_RUNTIME_MODE_SWITCH) or the admin key is wrong." : e.message) : (e as Error).message;
      toast.error("Mode switch failed", msg);
      setModeSwitch((m) => ({ ...m, busy: false }));
    }
  };

  const showDevices = async (u: User) => {
    setDevices({ user: u, list: "unavailable" });
    try {
      // The contract exposes only the caller's own devices; try an admin-scoped query and fall back gracefully.
      const list = await api.get<Device[]>(`/api/admin/users/${u.id}/devices`);
      setDevices({ user: u, list });
    } catch {
      setDevices({ user: u, list: "unavailable" });
    }
  };

  return (
    <>
      <PageHead
        title="Admin"
        sub="Users, out-of-band certificate confirmation, policy and runtime mode."
        actions={<>
          {mode === "zerotrustvault" ? <Badge tone="ok" lg>ZeroTrustVault mode</Badge> : <Badge tone="bad" lg>BASELINE mode</Badge>}
          <Button onClick={() => setModeSwitch({ open: true, key: "", busy: false })}>Switch mode…</Button>
          <Button onClick={load} icon={Icons.refresh({ size: 14 })}>Refresh</Button>
        </>}
      />
      {err && <div className="mb4"><AlertBox tone="bad">{err}</AlertBox></div>}

      <div className="grid-2">
        <Card title="Pending certificate requests" sub="Read the fingerprint back from the user over a trusted channel and type it here to confirm" actions={<Badge tone={reqs.length ? "warn" : "neutral"}>{reqs.length} pending</Badge>}>
          {reqs.length === 0 ? <EmptyState title="None pending" icon={Icons.shield({ size: 32 })} /> : reqs.map((r) => {
            const id = r.request_id ?? r.id!;
            const typed = confirmFp[id] ?? "";
            const match = norm(typed) === norm(r.fingerprint);
            const partial = typed.length > 0 && norm(r.fingerprint).startsWith(norm(typed));
            return (
              <div key={id} className="card mb4" style={{ padding: "var(--s4)", boxShadow: "none" }}>
                <div className="row between mb2">
                  <div><b>{r.username ?? r.user_id}</b> <span className="mono xs muted">{id}</span></div>
                  <Badge tone="warn">{r.status}</Badge>
                </div>
                <FingerprintDisplay fp={r.fingerprint} small />
                <div className="field mt3">
                  <label htmlFor={`fp-${id}`}>Type the fingerprint the user read to you</label>
                  <div className="input-row">
                    <input id={`fp-${id}`} className="mono" placeholder="XXXX XXXX XXXX …" value={typed} onChange={(e) => setConfirmFp({ ...confirmFp, [id]: e.target.value })} aria-invalid={typed.length > 0 && !partial && !match} autoComplete="off" spellCheck={false} />
                    <Button variant="primary" onClick={() => confirmReq(r)} disabled={!match} icon={Icons.check({ size: 14 })}>Confirm</Button>
                    <Button variant="ghost" size="sm" onClick={() => setConfirmFp({ ...confirmFp, [id]: r.fingerprint })} title="demo shortcut: simulate out-of-band confirmation">paste</Button>
                  </div>
                  <div className={`xs mt1 ${match ? "okc" : typed && !partial ? "err" : "muted"}`}>{match ? "Matches — ready to confirm" : typed ? (partial ? "Keep typing…" : "Does not match the request") : "Waiting for input"}</div>
                </div>
              </div>
            );
          })}
        </Card>

        <Card title="Create user" sub="TOTP provisioning secret is returned once and shown below">
          <div className="split">
            <div className="field"><label htmlFor="nuu">Username</label><input id="nuu" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} autoComplete="off" /></div>
            <div className="field"><label htmlFor="nup">Password</label><input id="nup" type="password" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" /></div>
            <div className="field"><label htmlFor="nur">Role</label>
              <select id="nur" value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}><option>analyst</option><option>manager</option><option>auditor</option><option>admin</option></select></div>
            <div className="field"><label htmlFor="nud">Department</label>
              <select id="nud" value={nu.department} onChange={(e) => setNu({ ...nu, department: e.target.value })}><option>research</option><option>finance</option><option>audit</option><option>it</option></select></div>
            <div className="field"><label htmlFor="nuc">Clearance</label>
              <select id="nuc" value={nu.clearance} onChange={(e) => setNu({ ...nu, clearance: Number(e.target.value) })}>{CLEARANCE.map((c, i) => <option key={c} value={i}>{i} {c}</option>)}</select></div>
            <div className="field"><label htmlFor="nue">Employment end (optional, ISO)</label><input id="nue" value={nu.employment_end} onChange={(e) => setNu({ ...nu, employment_end: e.target.value })} placeholder="2026-12-31T00:00:00Z" /></div>
          </div>
          <div className="row mt4"><Button variant="primary" onClick={createUser} icon={Icons.admin({ size: 14 })}>Create user</Button></div>
        </Card>

        <Card tight className="span-all" title="Users" sub={users ? `${users.length} accounts` : undefined}>
          {!users ? <div className="empty"><Spinner /></div> : users.length === 0 ? <EmptyState title="No users" /> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Username</th><th>Role</th><th>Department</th><th>Clearance</th><th>Employment end</th><th>Id</th><th></th></tr></thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td><b>{u.username}</b></td>
                      <td><Badge tone={u.role === "admin" ? "info" : "neutral"}>{u.role}</Badge></td>
                      <td>{u.department}</td>
                      <td><Badge tone={u.clearance >= 3 ? "bad" : u.clearance === 2 ? "warn" : "neutral"}>{u.clearance} {CLEARANCE[u.clearance] ?? ""}</Badge></td>
                      <td className="xs muted">{u.employment_end ? fmtDate(u.employment_end) : "—"}</td>
                      <td className="mono xs muted">{u.id.slice(0, 8)}…</td>
                      <td className="right"><Button size="sm" variant="ghost" onClick={() => showDevices(u)}>Devices</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card className="span-all" title="Policy" sub="Deny-overrides → first PERMIT → default DENY. Edit the JSON; it is validated before Save." actions={<>
          {policyDirty && <Badge tone="warn">unsaved</Badge>}
          {policyParsed.ok ? <Badge tone="ok">valid JSON · {policyParsed.rules.length} rules</Badge> : <Badge tone="bad">invalid JSON</Badge>}
        </>}>
          <div className="grid-2">
            <div>
              <textarea className="mono" value={policy} onChange={(e) => { setPolicy(e.target.value); setPolicyDirty(true); }} spellCheck={false} aria-label="Policy JSON" aria-invalid={!policyParsed.ok} />
              {!policyParsed.ok && <p className="err xs mt1">{policyParsed.error}</p>}
              {policyErr && <div className="mt2"><AlertBox tone="bad">{policyErr}</AlertBox></div>}
              <div className="row mt3">
                <Button variant="primary" onClick={savePolicy} disabled={!policyParsed.ok}>Save policy</Button>
                <Button onClick={load}>Reload</Button>
              </div>
            </div>
            <div>
              <label>Rules</label>
              {policyParsed.ok ? (
                policyParsed.rules.length === 0 ? <p className="muted small">no rules array</p> : (
                  <div className="policy-rules">
                    {policyParsed.rules.map((r, i) => (
                      <div key={i} className="rule">
                        <Badge tone={r.effect === "PERMIT" ? "ok" : r.effect === "DENY" ? "bad" : "neutral"}>{r.effect ?? "?"}</Badge>
                        <span className="mono xs">{r.id ?? `rule ${i + 1}`}</span>
                        <span className="muted grow truncate">{r.description ?? ""}</span>
                      </div>
                    ))}
                  </div>
                )
              ) : <p className="muted small">fix the JSON to preview rules</p>}
            </div>
          </div>
        </Card>
      </div>

      {created && (
        <Modal title={`User ${created.user.username} created`} onClose={() => setCreated(null)} footer={<Button variant="primary" onClick={() => setCreated(null)}>I have handed this over</Button>}>
          {created.user.totp_secret ? (
            <>
              <AlertBox tone="warn"><b>Shown only once.</b> Hand this TOTP provisioning secret to {created.user.username} out-of-band. It cannot be retrieved again.</AlertBox>
              <div className="row mt4" style={{ alignItems: "flex-start" }}>
                {created.qr && <span className="qr"><img src={created.qr} alt="TOTP provisioning QR code" width={200} height={200} style={{ display: "block" }} /></span>}
                <div className="grow">
                  <label>Secret (base32)</label>
                  <div className="row"><code style={{ wordBreak: "break-all" }}>{created.user.totp_secret}</code><CopyButton text={created.user.totp_secret} /></div>
                  {created.user.otpauth_uri && (
                    <div className="mt3">
                      <label>otpauth URI</label>
                      <div className="row"><code className="xs" style={{ wordBreak: "break-all" }}>{created.user.otpauth_uri}</code><CopyButton text={created.user.otpauth_uri} /></div>
                    </div>
                  )}
                  <table className="kv small mt3">
                    <tbody>
                      <tr><th>role</th><td>{created.user.role}</td></tr>
                      <tr><th>department</th><td>{created.user.department}</td></tr>
                      <tr><th>clearance</th><td>{created.user.clearance}</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <AlertBox tone="info">User created. The server did not return a TOTP secret; the user can enrol TOTP themselves on the Keys page.</AlertBox>
          )}
        </Modal>
      )}

      {modeSwitch.open && (
        <Modal title="Switch runtime mode" onClose={() => setModeSwitch({ open: false, key: "", busy: false })} footer={<><Button onClick={() => setModeSwitch({ open: false, key: "", busy: false })}>Cancel</Button><Button variant={mode === "zerotrustvault" ? "danger" : "primary"} solid={mode === "zerotrustvault"} busy={modeSwitch.busy} onClick={switchMode}>Switch to {mode === "zerotrustvault" ? "BASELINE" : "ZeroTrustVault"}</Button></>}>
          <AlertBox tone={mode === "zerotrustvault" ? "bad" : "info"}>
            {mode === "zerotrustvault" ? "Baseline disables MFA, DPoP binding, the PDP, signed manifests and the audit hash chain. Only for the attack lab." : "Returns to password + MFA, DPoP-bound tokens, client-side encryption and the PDP."}
          </AlertBox>
          <p className="small muted mt3">POST /api/admin/mode is only honoured when the server runs with <code>ALLOW_RUNTIME_MODE_SWITCH=true</code> and requires the admin key.</p>
          <div className="field mt3"><label htmlFor="adminkey">X-Admin-Key</label><input id="adminkey" type="password" value={modeSwitch.key} onChange={(e) => setModeSwitch({ ...modeSwitch, key: e.target.value })} autoComplete="off" /></div>
        </Modal>
      )}

      {devices && (
        <Modal title={`Devices — ${devices.user.username}`} onClose={() => setDevices(null)} footer={<Button onClick={() => setDevices(null)}>Close</Button>}>
          {devices.list === "unavailable" ? (
            <AlertBox tone="info">The API exposes device lists only to the device owner (<code>GET /devices</code>); there is no admin-scoped device endpoint in contract v1.</AlertBox>
          ) : devices.list.length === 0 ? <EmptyState title="No devices" /> : (
            <table>
              <thead><tr><th>Name</th><th>Posture</th><th>jkt</th><th>Last seen</th></tr></thead>
              <tbody>{devices.list.map((d) => <tr key={d.id}><td>{d.name}</td><td><Badge>{d.posture}</Badge></td><td className="mono xs">{d.jkt.slice(0, 16)}…</td><td className="xs muted">{d.last_seen ? fmtDate(d.last_seen) : "—"}</td></tr>)}</tbody>
            </table>
          )}
        </Modal>
      )}
    </>
  );
}
