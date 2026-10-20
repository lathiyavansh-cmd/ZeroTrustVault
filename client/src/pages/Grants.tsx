// Share / Grants overview: every grant on files you own (GET /shares?file_id= per owned file), plus quick share.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../state";
import { AlertBox, Button, Card, ClassBadge, EmptyState, Icons, PageHead, Spinner, useToast } from "../components/ui";
import { GrantsTable, ShareDialog, type FileRow, type GrantRow } from "./Files";

export default function Grants() {
  const { mode, keys, cert } = useApp();
  const toast = useToast();
  const ztv = mode === "zerotrustvault";
  const [files, setFiles] = useState<FileRow[] | null>(null);
  const [grants, setGrants] = useState<Record<string, GrantRow[]>>({});
  const [share, setShare] = useState<FileRow | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const fs = await api.get<FileRow[]>("/api/files");
      setFiles(fs);
      const owned = fs.filter((f) => f.via === "owner");
      const entries = await Promise.all(owned.map(async (f) => [f.file_id, await api.get<GrantRow[]>(`/api/shares?file_id=${encodeURIComponent(f.file_id)}`).catch(() => [] as GrantRow[])] as const));
      setGrants(Object.fromEntries(entries));
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const revoke = async (g: GrantRow) => {
    try {
      await api.del(`/api/shares/${g.grant_id}`);
      toast.success("Grant revoked", "Wrapped DEK deleted; outstanding blob tokens revoked.");
      load();
    } catch (e) {
      toast.error("Revoke failed", (e as Error).message);
    }
  };

  const owned = (files ?? []).filter((f) => f.via === "owner");
  const received = (files ?? []).filter((f) => f.via === "grant");
  const all = owned.flatMap((f) => grants[f.file_id] ?? []);
  const byId = Object.fromEntries((files ?? []).map((f) => [f.file_id, f]));

  return (
    <>
      <PageHead title="Share / Grants" sub="Grants are signed by the owner's Ed25519 key; the DEK is wrapped for the recipient's verified certificate. Revocation is soft (wrapped DEK deleted); rotate a file for a hard re-key." actions={<Button onClick={load} icon={Icons.refresh({ size: 14 })}>Refresh</Button>} />
      {!ztv && <div className="mb4"><AlertBox tone="bad">Baseline mode has no grants: any authenticated user may read any file by id.</AlertBox></div>}
      {err && <div className="mb4"><AlertBox tone="bad">{err}</AlertBox></div>}
      <div className="grid-2">
        <Card tight title="Files you own" sub="Share, or review who has access">
          {!files ? <div className="empty"><Spinner /></div> : owned.length === 0 ? <EmptyState title="You own no files" body="Upload one on the Files page." /> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>File</th><th>Class</th><th>Grants</th><th className="right"></th></tr></thead>
                <tbody>
                  {owned.map((f) => (
                    <tr key={f.file_id}>
                      <td><b>{f.name}</b><div className="xs muted mono">v{f.version}</div></td>
                      <td><ClassBadge c={f.classification} /></td>
                      <td>{(grants[f.file_id] ?? []).length}</td>
                      <td className="right"><Button size="sm" variant="primary" disabled={!ztv || !keys || !cert} onClick={() => setShare(f)} icon={Icons.share({ size: 13 })}>Share</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card tight title="Shared with you" sub="Files you can reach through someone else's grant">
          {!files ? <div className="empty"><Spinner /></div> : received.length === 0 ? <EmptyState title="Nothing shared with you" /> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>File</th><th>Class</th><th>Owner</th></tr></thead>
                <tbody>{received.map((f) => <tr key={f.file_id}><td><b>{f.name}</b></td><td><ClassBadge c={f.classification} /></td><td>{f.owner_username}</td></tr>)}</tbody>
              </table>
            </div>
          )}
        </Card>
        <Card className="span-all" title="Active grants on your files" sub={`${all.length} grant${all.length === 1 ? "" : "s"}`}>
          {(!keys || !cert) && ztv && <div className="mb4"><AlertBox tone="warn">Unlock your keys and hold an issued certificate to sign new grants.</AlertBox></div>}
          <GrantsTable grants={all} onRevoke={revoke} showFile files={byId} />
        </Card>
      </div>
      {share && <ShareDialog file={share} onClose={() => { setShare(null); load(); }} />}
    </>
  );
}
