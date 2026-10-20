// Settings: registered devices (GET/DELETE /devices), session + clock skew, theme preference.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../state";
import { AlertBox, Badge, Button, Card, EmptyState, Icons, PageHead, Spinner, fmtDate, useToast } from "../components/ui";

interface Device { id: string; name: string; jkt: string; posture: string; created_at: string; last_seen?: string | null }

type Theme = "system" | "light" | "dark";

export default function Settings() {
  const { session, mode, keys, cert, orgRoot } = useApp();
  const toast = useToast();
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem("ztv.theme") as Theme) || "system");
  const u = session.user!;

  const load = useCallback(() => {
    api.get<Device[]>("/api/devices").then(setDevices).catch((e) => { setDevices([]); setErr((e as Error).message); });
  }, []);
  useEffect(load, [load]);

  const applyTheme = (t: Theme) => {
    setTheme(t);
    try {
      if (t === "system") { localStorage.removeItem("ztv.theme"); delete document.documentElement.dataset.theme; }
      else { localStorage.setItem("ztv.theme", t); document.documentElement.dataset.theme = t; }
    } catch { /* ignore */ }
  };

  const revokeDevice = async (d: Device) => {
    if (!confirm(`Revoke device “${d.name}”? All of its sessions are terminated.`)) return;
    try {
      await api.del(`/api/devices/${d.id}`);
      toast.success("Device revoked", "Its sessions and refresh tokens are gone.");
      load();
    } catch (e) {
      toast.error("Revoke failed", (e as Error).message);
    }
  };

  return (
    <>
      <PageHead title="Settings" sub="Devices bound to your account, this session, and display preferences." />
      <div className="grid-2">
        <Card tight title="Registered devices" sub="Each device holds a non-extractable P-256 key; its JWK thumbprint (jkt) is bound into every access token" actions={<Button size="sm" onClick={load} icon={Icons.refresh({ size: 13 })}>Refresh</Button>}>
          {!devices ? <div className="empty"><Spinner /></div> : devices.length === 0 ? <EmptyState title="No devices listed" body={err ?? undefined} /> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Name</th><th>Posture</th><th>jkt</th><th>Registered</th><th>Last seen</th><th></th></tr></thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id}>
                      <td><b>{d.name}</b>{d.id === session.deviceId && <Badge tone="info" className="mt1">this device</Badge>}</td>
                      <td><Badge tone={d.posture === "trusted" ? "ok" : "neutral"}>{d.posture}</Badge></td>
                      <td className="mono xs">{d.jkt.slice(0, 16)}…</td>
                      <td className="xs muted">{fmtDate(d.created_at)}</td>
                      <td className="xs muted">{d.last_seen ? fmtDate(d.last_seen) : "—"}</td>
                      <td className="right"><Button size="sm" variant="danger" onClick={() => revokeDevice(d)} disabled={d.id === session.deviceId} title={d.id === session.deviceId ? "Sign out to revoke this device" : "Revoke device (device loss)"}>Revoke</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <div className="stack">
          <Card title="This session">
            <table className="kv">
              <tbody>
                <tr><th>user</th><td>{u.username} <Badge tone="info">{u.role}</Badge> <Badge>{u.department}</Badge> <Badge>clearance {u.clearance}</Badge></td></tr>
                <tr><th>mode</th><td>{mode === "zerotrustvault" ? <Badge tone="ok">ZeroTrustVault</Badge> : <Badge tone="bad">BASELINE</Badge>}</td></tr>
                <tr><th>token</th><td>{session.tokenType}{session.tokenType === "DPoP" ? " · 5-min, auto-refreshed with a proof from this device key" : " · 30-day bearer"}</td></tr>
                <tr><th>device id</th><td className="mono small">{session.deviceId ?? "—"}</td></tr>
                <tr><th>risk</th><td>{session.risk ? `${session.risk.score} (${session.risk.level})` : "—"}</td></tr>
                <tr><th>elevated until</th><td>{session.elevatedUntil ?? "—"}</td></tr>
                <tr><th>clock skew</th><td>{api.skewSeconds}s vs server (X-Server-Time)</td></tr>
                <tr><th>keys</th><td>{keys ? `unlocked · ${keys.backend}` : "locked"}</td></tr>
                <tr><th>certificate</th><td>{cert ? <span className="mono small">{cert.serial}</span> : "none"}</td></tr>
                <tr><th>org root</th><td>{orgRoot.pinned ? <Badge tone="ok">pinned</Badge> : orgRoot.pk ? <Badge tone="warn">unpinned (dev)</Badge> : <Badge tone="bad">unavailable</Badge>}</td></tr>
              </tbody>
            </table>
          </Card>
          <Card title="Appearance">
            <label>Theme</label>
            <div className="row">
              {(["system", "dark", "light"] as Theme[]).map((t) => <Button key={t} size="sm" variant={theme === t ? "primary" : "secondary"} onClick={() => applyTheme(t)} aria-pressed={theme === t}>{t}</Button>)}
            </div>
            <p className="hint mt2">System follows prefers-color-scheme. Stored locally only.</p>
          </Card>
          {mode === "baseline" && <AlertBox tone="bad">Baseline mode: no device binding, so device revocation does not invalidate the 30-day bearer token.</AlertBox>}
        </div>
      </div>
    </>
  );
}
