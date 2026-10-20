import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../state";
import { AlertBox, Badge, Button, Card, CopyButton, DecisionBadge, EmptyState, Icons, PageHead, Spinner, fmtTime } from "../components/ui";

interface Summary {
  mode: string;
  decisions: { permit: number; deny: number; alerts: number };
  recent: AuditEntry[];
  audit: { entries: number; last_checkpoint_seq: number | null; chain_ok: boolean; first_bad_seq: number | null; head_hash?: string | null };
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
  hash?: string;
}

const MAX_POLLS = 40;
const FILTERS = ["ALL", "PERMIT", "DENY", "ALERT", "INFO"] as const;

/** Inline SVG bars: permits / denies / alerts per poll (deltas of the cumulative counters). */
function Sparkline({ series }: { series: { permit: number; deny: number; alert: number }[] }) {
  const w = 600, h = 72, pad = 2;
  const n = Math.max(series.length, 1);
  const max = Math.max(1, ...series.map((s) => s.permit + s.deny + s.alert));
  const bw = Math.max(2, (w - pad * 2) / MAX_POLLS - 2);
  return (
    <svg className="sparkline" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label={`decisions over the last ${n} polls`}>
      <line x1={0} x2={w} y1={h - 1} y2={h - 1} stroke="var(--border)" />
      {series.map((s, i) => {
        const x = pad + i * ((w - pad * 2) / MAX_POLLS);
        const hp = (s.permit / max) * (h - 6), hd = (s.deny / max) * (h - 6), ha = (s.alert / max) * (h - 6);
        let y = h - 2;
        const rects = [] as JSX.Element[];
        if (s.permit) { y -= hp; rects.push(<rect key="p" x={x} y={y} width={bw} height={hp} fill="var(--permit)" rx={1} />); }
        if (s.deny) { y -= hd; rects.push(<rect key="d" x={x} y={y} width={bw} height={hd} fill="var(--deny)" rx={1} />); }
        if (s.alert) { y -= ha; rects.push(<rect key="a" x={x} y={y} width={bw} height={ha} fill="var(--alert)" rx={1} />); }
        if (!rects.length) rects.push(<rect key="e" x={x} y={h - 4} width={bw} height={2} fill="var(--border-strong)" />);
        return <g key={i}>{rects}</g>;
      })}
    </svg>
  );
}

export default function Dashboard() {
  const { session } = useApp();
  const [s, setS] = useState<Summary | null>(null);
  const [recent, setRecent] = useState<AuditEntry[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("ALL");
  const [series, setSeries] = useState<{ permit: number; deny: number; alert: number }[]>([]);
  const prev = useRef<Summary["decisions"] | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);

  useEffect(() => {
    if (paused) return;
    let alive = true;
    const poll = async () => {
      try {
        const [sum, rec] = await Promise.all([api.get<Summary>("/api/dashboard/summary"), api.get<AuditEntry[] | { entries: AuditEntry[] }>("/api/audit/recent?limit=50")]);
        if (!alive) return;
        setS(sum);
        setRecent(Array.isArray(rec) ? rec : rec.entries ?? []);
        setErr(null);
        setTick((t) => t + 1);
        setLastAt(new Date());
        const p = prev.current;
        const d = sum.decisions;
        const delta = p ? { permit: Math.max(0, d.permit - p.permit), deny: Math.max(0, d.deny - p.deny), alert: Math.max(0, d.alerts - p.alerts) } : { permit: 0, deny: 0, alert: 0 };
        prev.current = d;
        setSeries((xs) => [...xs, delta].slice(-MAX_POLLS));
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
  }, [paused]);

  const rows = s?.recent?.length ? s.recent : recent;
  const stepUps = recent.filter((e) => /step[-_]?up/i.test(e.action) || /step[-_]?up/i.test(e.reason ?? ""));
  const sessions = s ? (typeof s.sessions_active === "number" ? s.sessions_active : s.sessions_active.length) : 0;
  const filtered = useMemo(() => rows.filter((e) => filter === "ALL" ? true : filter === "INFO" ? !["PERMIT", "DENY", "ALERT"].includes(e.decision) : e.decision === filter), [rows, filter]);
  const counts = useMemo(() => ({ ALL: rows.length, PERMIT: rows.filter((e) => e.decision === "PERMIT").length, DENY: rows.filter((e) => e.decision === "DENY").length, ALERT: rows.filter((e) => e.decision === "ALERT").length, INFO: rows.filter((e) => !["PERMIT", "DENY", "ALERT"].includes(e.decision)).length }), [rows]);
  const head = rows.length ? rows.reduce((a, b) => (b.seq > a.seq ? b : a)) : null;
  const headHash = s?.audit.head_hash ?? head?.hash ?? null;
  const ztv = (s?.mode ?? session.mode) === "zerotrustvault";

  return (
    <>
      <PageHead
        title="Dashboard"
        sub={<span className="row">
          {ztv ? <Badge tone="ok" lg>ZeroTrustVault mode</Badge> : <Badge tone="bad" lg>BASELINE mode</Badge>}
          <span className="small muted row">{paused ? "paused" : <><Spinner /> live · every 3 s</>} · poll #{tick}{lastAt ? ` · ${fmtTime(lastAt.toISOString())}` : ""}</span>
        </span>}
        actions={<Button onClick={() => setPaused((p) => !p)} icon={paused ? Icons.play({ size: 14 }) : Icons.pause({ size: 14 })} aria-pressed={paused}>{paused ? "Resume" : "Pause"}</Button>}
      />
      {err && <div className="mb4"><AlertBox tone="bad">{err}</AlertBox></div>}

      <div className="kpis mb4">
        <div className="kpi" style={{ ["--kpi-c" as string]: "var(--permit)" }}><div className="n">{s?.decisions.permit ?? "—"}</div><div className="l">Permits</div></div>
        <div className="kpi" style={{ ["--kpi-c" as string]: "var(--deny)" }}><div className="n">{s?.decisions.deny ?? "—"}</div><div className="l">Denies</div></div>
        <div className="kpi" style={{ ["--kpi-c" as string]: "var(--alert)" }}><div className="n">{s?.decisions.alerts ?? "—"}</div><div className="l">Alerts</div></div>
        <div className="kpi" style={{ ["--kpi-c" as string]: "var(--warn)" }}><div className="n">{stepUps.length + api.stepUpEvents.length}</div><div className="l">Step-ups {api.stepUpEvents.length ? `(${api.stepUpEvents.length} this session)` : "(recent)"}</div></div>
        <div className="kpi" style={{ ["--kpi-c" as string]: "var(--info)" }}><div className="n">{sessions}</div><div className="l">Active sessions</div></div>
      </div>

      <div className="grid-2 mb4">
        <Card title="Audit chain" sub="SHA-256 hash chain with Ed25519-signed checkpoints" tone={s ? (s.audit.chain_ok ? "ok" : "danger") : undefined}>
          {!s ? <div className="row muted"><Spinner /> waiting for /api/dashboard/summary…</div> : (
            <>
              <div className={`verdict-big ${s.audit.chain_ok ? "ok" : "bad"}`}>{s.audit.chain_ok ? "INTACT" : `BROKEN at seq ${s.audit.first_bad_seq ?? "?"}`}</div>
              <table className="kv mt3 small">
                <tbody>
                  <tr><th>entries</th><td className="mono">{s.audit.entries}</td></tr>
                  <tr><th>last checkpoint</th><td className="mono">{s.audit.last_checkpoint_seq ?? "—"}</td></tr>
                  <tr><th>head seq</th><td className="mono">{head?.seq ?? "—"}</td></tr>
                  <tr><th>head hash</th><td>{headHash ? <span className="row"><span className="mono xs" style={{ wordBreak: "break-all" }}>{headHash}</span><CopyButton text={headHash} /></span> : <span className="muted">not exposed by this endpoint</span>}</td></tr>
                </tbody>
              </table>
            </>
          )}
        </Card>
        <Card title="Decisions per poll" sub={`last ${series.length} polls · green permit, red deny, orange alert`}>
          {series.length < 2 ? <div className="muted small row"><Spinner /> collecting…</div> : <Sparkline series={series} />}
          {s && Array.isArray(s.sessions_active) && s.sessions_active.length > 0 && (
            <div className="mt3">
              <label>Active sessions</label>
              <div className="chips">{s.sessions_active.map((x) => <Badge key={x.id} tone={(x.risk ?? 0) >= 60 ? "warn" : "neutral"}>{x.username ?? x.id.slice(0, 8)}{x.risk !== undefined ? ` · risk ${x.risk}` : ""}</Badge>)}</div>
            </div>
          )}
        </Card>
      </div>

      <Card tight title="Recent decisions" sub={session.user?.role === "admin" ? "all actors" : "your own entries only"} actions={
        <div className="chips" role="group" aria-label="Filter decisions">
          {FILTERS.map((f) => <button key={f} className={`chip filter ${filter === f ? "on" : ""}`} onClick={() => setFilter(f)} aria-pressed={filter === f}>{f} <span className="muted">{counts[f]}</span></button>)}
        </div>
      }>
        {!s && rows.length === 0 ? <div className="empty"><Spinner /></div> : filtered.length === 0 ? <EmptyState title="No matching entries" /> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Seq</th><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Decision</th><th>Reason</th><th className="hide-narrow">Device</th></tr></thead>
              <tbody>
                {filtered.map((e) => (
                  <tr key={e.seq}>
                    <td className="mono xs muted">{e.seq}</td>
                    <td className="mono xs nowrap" title={e.ts}>{fmtTime(e.ts)}</td>
                    <td>{e.actor}</td>
                    <td className="mono small">{e.action}</td>
                    <td className="mono xs truncate" style={{ maxWidth: 220 }} title={e.resource}>{e.resource}</td>
                    <td><DecisionBadge d={e.decision} /></td>
                    <td className="small">{e.reason}</td>
                    <td className="mono xs muted hide-narrow">{e.device ? e.device.slice(0, 12) : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
