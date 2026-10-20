import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../state";

interface Summary {
  mode: string;
  decisions: { permit: number; deny: number; alerts: number };
  recent: AuditEntry[];
  audit: { entries: number; last_checkpoint_seq: number | null; chain_ok: boolean; first_bad_seq: number | null };
  sessions_active: number | { id: string; username?: string; device?: string; risk?: number }[];
}
interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  resource: string;
  decision: string;
  reason: string;
  ip?: string;
  device?: string;
}

export default function Dashboard() {
  const { session } = useApp();
  const [s, setS] = useState<Summary | null>(null);
  const [recent, setRecent] = useState<AuditEntry[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const [sum, rec] = await Promise.all([api.get<Summary>("/api/dashboard/summary"), api.get<AuditEntry[] | { entries: AuditEntry[] }>("/api/audit/recent?limit=50")]);
        if (!alive) return;
        setS(sum);
        setRecent(Array.isArray(rec) ? rec : rec.entries ?? []);
        setErr(null);
        setTick((t) => t + 1);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    poll();
    const h = setInterval(poll, 3000);
    return () => {
      alive = false;
      clearInterval(h);
    };
  }, []);

  const stepUps = recent.filter((e) => /step[-_]?up/i.test(e.action) || /step[-_]?up/i.test(e.reason ?? ""));
  const sessions = s ? (typeof s.sessions_active === "number" ? s.sessions_active : s.sessions_active.length) : 0;

  return (
    <>
      <div className="row" style={{ marginBottom: 10 }}>
        <span className={`badge ${s?.mode === "zerotrustvault" ? "ok" : "warn"}`}>mode: {s?.mode ?? session.mode}</span>
        <span className="badge">live · every 3 s · poll #{tick}</span>
        {s && (
          <span className={`badge ${s.audit.chain_ok ? "ok" : "bad"}`}>
            audit chain: {s.audit.chain_ok ? "INTACT" : `BROKEN at seq ${s.audit.first_bad_seq ?? "?"}`} · {s.audit.entries} entries · last checkpoint seq {s.audit.last_checkpoint_seq ?? "—"}
          </span>
        )}
        {api.stepUpEvents.length > 0 && <span className="badge accent">step-ups this session: {api.stepUpEvents.length}</span>}
        {err && <span className="err small">{err}</span>}
      </div>
      <div className="kpis" style={{ marginBottom: 14 }}>
        <div className="kpi"><div className="n okc">{s?.decisions.permit ?? "—"}</div><div className="l">PERMIT</div></div>
        <div className="kpi"><div className="n err">{s?.decisions.deny ?? "—"}</div><div className="l">DENY</div></div>
        <div className="kpi"><div className="n" style={{ color: "var(--warn)" }}>{s?.decisions.alerts ?? "—"}</div><div className="l">ALERT</div></div>
        <div className="kpi"><div className="n">{sessions}</div><div className="l">active sessions</div></div>
        <div className="kpi"><div className="n">{stepUps.length}</div><div className="l">step-up events (recent)</div></div>
      </div>
      {s && Array.isArray(s.sessions_active) && s.sessions_active.length > 0 && (
        <div className="card">
          <h3>Active sessions</h3>
          <table>
            <thead><tr><th>session</th><th>user</th><th>device</th><th>risk</th></tr></thead>
            <tbody>{s.sessions_active.map((x) => <tr key={x.id}><td className="mono small">{x.id}</td><td>{x.username ?? "—"}</td><td className="mono small">{x.device ?? "—"}</td><td>{x.risk ?? "—"}</td></tr>)}</tbody>
          </table>
        </div>
      )}
      <div className="card">
        <h3>Recent decisions</h3>
        <table>
          <thead><tr><th>seq</th><th>time</th><th>actor</th><th>action</th><th>resource</th><th>decision</th><th>reason</th><th>device</th></tr></thead>
          <tbody>
            {(s?.recent?.length ? s.recent : recent).map((e) => (
              <tr key={e.seq}>
                <td>{e.seq}</td>
                <td className="small">{e.ts}</td>
                <td>{e.actor}</td>
                <td>{e.action}</td>
                <td className="mono small">{e.resource}</td>
                <td><span className={`badge ${e.decision === "PERMIT" ? "ok" : e.decision === "DENY" ? "bad" : e.decision === "ALERT" ? "warn" : ""}`}>{e.decision}</span></td>
                <td className="small">{e.reason}</td>
                <td className="mono small">{e.device ?? ""}</td>
              </tr>
            ))}
            {!s && <tr><td colSpan={8} className="muted">waiting for /api/dashboard/summary…</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}
