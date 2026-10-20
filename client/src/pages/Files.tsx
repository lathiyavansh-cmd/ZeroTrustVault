import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { api, ApiError } from "../api/client";
import { useApp } from "../state";
import { uploadFile } from "../crypto/upload";
import { unwrapDek, wrapDek, type WrapRecord } from "../crypto/wrap";
import { certFingerprint, signGrant, verifyManifest, verifyUserCert, type Grant, type Manifest, type UserCert } from "../crypto/sign";
import { b64uDecode, nowIso, toBuf, uuidv4 } from "../crypto/encoding";
import type { DecryptMessage } from "../crypto/worker/decrypt.worker";
import { AlertBox, Badge, Button, Card, ClassBadge, CopyButton, Drawer, EmptyState, FingerprintDisplay, Icons, Modal, PageHead, Progress, Spinner, fmtDate, fmtSize, useToast } from "../components/ui";

export interface FileRow {
  file_id: string;
  name: string;
  classification: string;
  owner_id: string;
  owner_username: string;
  version: number;
  size: number;
  created_at: string;
  via: "owner" | "grant";
}
interface AccessResp {
  version: number;
  manifest: Manifest;
  wrapped_dek: WrapRecord;
  chunk_urls: string[];
  expires_in: number;
}
export interface GrantRow extends Grant {
  downloads_used?: number;
}
interface DirUser {
  user_id: string;
  username: string;
  department: string;
  role: string;
  has_cert: boolean;
}

const CLASSES = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"];

interface UploadState { name: string; pct: number; phase: "encrypt" | "upload" | "finalize" | "done" | "error"; status: string; chunk?: [number, number]; bytes?: number; total: number; result?: { root: string; sig: string; version: number } }
interface DlState { name: string; pct: number; status: string; ok?: boolean; sigOk?: boolean; merkleOk?: boolean; chunks?: [number, number]; abort?: { stage: string; index: number; message: string }; reported?: boolean; version?: number }

export default function Files() {
  const { session, keys, cert, orgRoot, mode } = useApp();
  const toast = useToast();
  const ztv = mode === "zerotrustvault";
  const [files, setFiles] = useState<FileRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [classification, setClassification] = useState("INTERNAL");
  const [upload, setUpload] = useState<UploadState | null>(null);
  const [dl, setDl] = useState<DlState | null>(null);
  const [share, setShare] = useState<FileRow | null>(null);
  const [detail, setDetail] = useState<{ file: FileRow; meta: Record<string, unknown> } | null>(null);
  const [preview, setPreview] = useState<{ file: FileRow; text: string } | null>(null);
  const [confirmDel, setConfirmDel] = useState<FileRow | null>(null);
  const [rotateFor, setRotateFor] = useState<FileRow | null>(null);
  const [over, setOver] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const rotateInput = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    api.get<FileRow[]>("/api/files").then(setFiles).catch((e) => setErr(String((e as Error).message)));
  }, []);
  useEffect(load, [load]);

  const doUpload = async (f: File, rotate?: FileRow) => {
    setErr(null);
    if (!ztv) {
      const fd = new FormData();
      fd.append("file", f);
      fd.append("name", f.name);
      fd.append("classification", classification);
      setUpload({ name: f.name, pct: 50, phase: "upload", status: "uploading plaintext (baseline)", total: f.size });
      try {
        const r = await fetch("/api/files/upload", { method: "POST", headers: { Authorization: `Bearer ${session.accessToken}` }, body: fd });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setUpload({ name: f.name, pct: 100, phase: "done", status: "uploaded in plaintext — no integrity proof (baseline)", total: f.size });
        toast.warn("Uploaded in baseline mode", "Plaintext upload, server-side encryption only.");
        load();
      } catch (e) {
        setErr((e as Error).message);
        setUpload(null);
      }
      return;
    }
    if (!keys) return setErr("Unlock your keys first (Enrol / Keys page).");
    if (!cert) return setErr("No issued certificate yet (Enrol / Keys page) — the server rejects manifests without one.");
    try {
      setUpload({ name: f.name, pct: 0, phase: "encrypt", status: rotate ? "re-keying (new version): fresh DEK, encrypting chunks" : "encrypting chunks with a fresh DEK", total: f.size });
      const res = await uploadFile(
        f,
        rotate ? rotate.classification : classification,
        keys,
        session.user!.id,
        (p) => setUpload({ name: f.name, pct: Math.round(((p.index + 1) / p.total) * 100), phase: "upload", status: `chunk ${p.index + 1}/${p.total} encrypted + PUT with DPoP proof`, chunk: [p.index + 1, p.total], bytes: p.bytes, total: f.size }),
        rotate ? { file_id: rotate.file_id } : undefined,
      );
      setUpload((u) => (u ? { ...u, phase: "finalize", status: "signing manifest, wrapping DEK, finalizing…" } : u));
      if (rotate) {
        // Hard revocation: re-wrap the fresh DEK only for the owner (recipients must be re-shared explicitly).
        await api.post(`/api/files/${res.file_id}/versions/${res.version}/finalize`, { manifest: res.manifest, wrapped_dek: res.wrapped_dek, wrapped_deks: { [session.user!.id]: res.wrapped_dek } });
      } else {
        await api.post(`/api/files/${res.file_id}/versions/${res.version}/finalize`, { manifest: res.manifest, wrapped_dek: res.wrapped_dek });
      }
      setUpload({ name: f.name, pct: 100, phase: "done", status: `finalized v${res.version} — manifest signed, DEK wrapped`, total: f.size, result: { root: res.manifest.merkle_root, sig: res.manifest.signature ?? "", version: res.version } });
      toast.success(rotate ? `Re-keyed ${f.name} → v${res.version}` : `Uploaded ${f.name}`, rotate ? "Old version chunks deleted; recipients must be re-shared." : "Manifest signed, DEK wrapped for you.");
      load();
    } catch (e) {
      setErr(e instanceof ApiError ? `upload failed: ${e.message}` : (e as Error).message);
      setUpload(null);
    }
  };

  const download = async (f: FileRow, intent: "view" | "download") => {
    setErr(null);
    setDl({ name: f.name, pct: 0, status: "requesting access (PDP)" });
    if (!ztv) {
      try {
        const r = await fetch(`/api/files/${f.file_id}/download`, { headers: { Authorization: `Bearer ${session.accessToken}` } });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        saveBlob(await r.blob(), f.name);
        setDl({ name: f.name, pct: 100, status: "downloaded (baseline: server-side decryption, no integrity proof)", ok: true });
      } catch (e) {
        setDl({ name: f.name, pct: 0, status: (e as Error).message, ok: false });
      }
      return;
    }
    if (!keys) return setErr("Unlock your keys first (Enrol / Keys page).");
    try {
      const a = await api.post<AccessResp>(`/api/files/${f.file_id}/access`, { intent });
      // Verify the manifest signature against the owner's cert (fetched from the directory and verified against the pinned root).
      const ownerCert = (await api.get<{ cert: UserCert }>(`/api/keys/directory/${f.owner_id}`)).cert;
      if (orgRoot.pk && !(await verifyUserCert(ownerCert, orgRoot.pk, { expectedUserId: f.owner_id }))) throw new Error("owner certificate does not verify against the pinned org root");
      if (!(await verifyManifest(a.manifest, b64uDecode(ownerCert.sig_pk)))) {
        setDl({ name: f.name, pct: 0, status: "manifest signature INVALID — refusing to decrypt", ok: false, sigOk: false, version: a.version });
        throw new Error("manifest signature INVALID — refusing to decrypt");
      }
      if (a.manifest.file_id !== f.file_id) throw new Error("manifest file_id mismatch");
      setDl({ name: f.name, pct: 0, status: `manifest verified (v${a.version}, ${a.manifest.chunk_count} chunks); unwrapping DEK`, sigOk: true, chunks: [0, a.manifest.chunk_count], version: a.version });
      const dek = await unwrapDek(a.wrapped_dek, keys.enc, f.file_id, a.version);
      const worker = new Worker(new URL("../crypto/worker/decrypt.worker.ts", import.meta.url), { type: "module" });
      const parts: ArrayBuffer[] = [];
      const dekBuf = toBuf(dek);
      dek.fill(0);
      await new Promise<void>((resolve, reject) => {
        worker.onmessage = (ev: MessageEvent<DecryptMessage>) => {
          const m = ev.data;
          if (m.type === "chunk") parts[m.index] = m.data;
          else if (m.type === "progress") setDl({ name: f.name, pct: Math.round(((m.index + 1) / m.total) * 100), status: `chunk ${m.index + 1}/${m.total} verified + decrypted (worker)`, sigOk: true, chunks: [m.index + 1, m.total], version: a.version });
          else if (m.type === "done") {
            setDl({ name: f.name, pct: 100, status: `integrity OK — Merkle root matches signed manifest, ${m.chunkCount} chunks, ${fmtSize(m.bytes)}`, ok: true, sigOk: true, merkleOk: true, chunks: [m.chunkCount, m.chunkCount], version: a.version });
            resolve();
          } else if (m.type === "error") {
            setDl({ name: f.name, pct: 0, status: `INTEGRITY FAILURE (${m.stage}, chunk ${m.index}): ${m.message}`, ok: false, sigOk: true, merkleOk: false, chunks: [m.index, a.manifest.chunk_count], abort: { stage: m.stage, index: m.index, message: m.message }, version: a.version });
            api.post(`/api/files/${f.file_id}/report-integrity`, { version: a.version, chunk_index: m.index, reason: `${m.stage}: ${m.message}` })
              .then(() => setDl((d) => (d ? { ...d, reported: true } : d)))
              .catch(() => undefined);
            reject(new Error(m.message));
          }
        };
        worker.onerror = (e) => reject(new Error(e.message));
        worker.postMessage({ type: "start", dek: dekBuf, manifest: a.manifest, chunkUrls: a.chunk_urls }, [dekBuf]);
      }).finally(() => worker.terminate());
      if (intent === "download") saveBlob(new Blob(parts), f.name);
      else {
        const text = new TextDecoder().decode(new Uint8Array(await new Blob(parts).arrayBuffer()).subarray(0, 4000));
        setPreview({ file: f, text });
      }
    } catch (e) {
      const msg = e instanceof ApiError ? (e.status === 403 ? "DENIED by policy (403)" : e.code === "step_up_required" ? "step-up cancelled" : e.message) : (e as Error).message;
      setDl((d) => (d?.ok === false ? d : { name: f.name, pct: 0, status: msg, ok: false }));
      if (e instanceof ApiError && e.status === 403) toast.error("Access denied", "The policy decision point returned DENY for this request.");
    }
  };

  const showDetail = async (f: FileRow) => {
    try {
      setDetail({ file: f, meta: await api.get<Record<string, unknown>>(`/api/files/${f.file_id}`) });
    } catch (e) {
      setErr((e as Error).message);
      toast.error("Could not load file details", (e as Error).message);
    }
  };

  const remove = async (f: FileRow) => {
    setConfirmDel(null);
    await api.del(`/api/files/${f.file_id}`).then(() => toast.success(`Deleted ${f.name}`)).catch((e) => setErr((e as Error).message));
    load();
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) doUpload(f);
  };

  return (
    <>
      <PageHead title="Files" sub={ztv ? "AES-256-GCM 4 MiB STREAM chunks · Merkle root in an Ed25519-signed manifest · DEK wrapped with X25519-HKDF-AES-KW · one DPoP proof per chunk PUT" : "Baseline: multipart plaintext upload, server-side encryption."} actions={<Button onClick={load} icon={Icons.refresh({ size: 14 })}>Refresh</Button>} />

      <div className="grid-2 mb4">
        <Card title="Upload" sub={ztv ? "Encrypted in this tab before any byte leaves it" : "Plaintext (baseline)"}>
          <div
            className={`dropzone ${over ? "over" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setOver(true); }}
            onDragLeave={() => setOver(false)}
            onDrop={onDrop}
            onClick={() => fileInput.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && fileInput.current?.click()}
            aria-label="Choose a file to upload"
          >
            {Icons.upload({ size: 28 })}
            <div><strong>Drop a file here</strong> or click to browse</div>
            <div className="xs mt1">Will be stored as <b className="mono">{classification}</b></div>
            <input ref={fileInput} type="file" className="sr-only" tabIndex={-1} onChange={(e) => { const f = e.target.files?.[0]; if (f) doUpload(f); e.target.value = ""; }} />
          </div>
          <div className="row mt3">
            <div className="field grow" style={{ maxWidth: 240 }}>
              <label htmlFor="cls">Classification</label>
              <select id="cls" value={classification} onChange={(e) => setClassification(e.target.value)}>
                {CLASSES.map((c) => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div className="chips" style={{ alignSelf: "flex-end" }}>{CLASSES.map((c) => <ClassBadge key={c} c={c} />)}</div>
          </div>
          {!ztv ? null : !keys ? <div className="mt3"><AlertBox tone="warn">Keys are locked — unlock them on the Enrol / Keys page to upload.</AlertBox></div> : !cert ? <div className="mt3"><AlertBox tone="warn">No certificate issued yet — the server rejects unsigned manifests.</AlertBox></div> : null}
          {upload && (
            <div className="mt4">
              <div className="row between small">
                <span className="truncate"><b>{upload.name}</b> · {upload.status}</span>
                <Badge tone={upload.phase === "done" ? "ok" : upload.phase === "error" ? "bad" : "info"}>{upload.phase}</Badge>
              </div>
              <div className="mt2"><Progress pct={upload.pct} tone={upload.phase === "done" ? "ok" : undefined} /></div>
              <div className="row xs muted mt1">
                {upload.chunk && <span>chunk {upload.chunk[0]}/{upload.chunk[1]}</span>}
                {upload.bytes !== undefined && <span>{fmtSize(upload.bytes)} / {fmtSize(upload.total)}</span>}
                {upload.phase === "encrypt" && <span className="row"><Spinner /> encrypt</span>}
              </div>
              {upload.result && (
                <table className="kv mt2 small">
                  <tbody>
                    <tr><th>version</th><td>v{upload.result.version}</td></tr>
                    <tr><th>Merkle root</th><td><span className="mono" style={{ wordBreak: "break-all" }}>{upload.result.root}</span> <CopyButton text={upload.result.root} /></td></tr>
                    <tr><th>manifest signature</th><td><span className="mono" style={{ wordBreak: "break-all" }}>{upload.result.sig.slice(0, 44)}…</span> <CopyButton text={upload.result.sig} /></td></tr>
                  </tbody>
                </table>
              )}
            </div>
          )}
          {err && <div className="mt3"><AlertBox tone="bad">{err}</AlertBox></div>}
        </Card>

        <Card title="Integrity verdict" sub="Download / view run in a worker: every chunk is authenticated against the signed Merkle root">
          {!dl ? (
            <EmptyState title="No transfer yet" body="View or download a file to see the verification result here." icon={Icons.shield({ size: 36 })} />
          ) : (
            <div className={`verdict ${dl.ok === true ? "ok" : dl.ok === false ? "bad" : "pending"}`}>
              <div className="title">
                {dl.ok === true ? Icons.check({ size: 20 }) : dl.ok === false ? Icons.alert({ size: 20 }) : <Spinner />}
                {dl.ok === true ? "INTEGRITY OK" : dl.ok === false ? "INTEGRITY FAILURE" : "Verifying…"}
                <span className="muted small" style={{ fontWeight: 400 }}>· {dl.name}{dl.version ? ` v${dl.version}` : ""}</span>
              </div>
              <ul>
                <li>manifest signature: <b>{dl.sigOk === undefined ? "—" : dl.sigOk ? "OK (owner cert verified against pinned root)" : "INVALID"}</b></li>
                <li>Merkle root: <b>{dl.merkleOk === undefined ? "—" : dl.merkleOk ? "OK" : "MISMATCH"}</b></li>
                <li>chunks: <b>{dl.chunks ? `${dl.chunks[0]}/${dl.chunks[1]}` : "—"}</b></li>
                {dl.abort && <li className="err">aborted at <b>{dl.abort.stage}</b>, chunk index <b>{dl.abort.index}</b>: {dl.abort.message}</li>}
                {dl.abort && <li>ALERT reported to the audit log: <b>{dl.reported ? "yes" : "sending…"}</b></li>}
                <li className="muted">{dl.status}</li>
              </ul>
              <Progress pct={dl.pct} tone={dl.ok === false ? "bad" : dl.ok ? "ok" : undefined} />
            </div>
          )}
        </Card>
      </div>

      <Card tight title="Your files" sub={files ? `${files.length} file${files.length === 1 ? "" : "s"} · owned or shared with you` : undefined}>
        {!files ? (
          <div className="empty"><Spinner /> loading…</div>
        ) : files.length === 0 ? (
          <EmptyState title="No files yet" body="Upload a file above, or ask a colleague to share one with you." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Class</th><th>Owner</th><th>Ver</th><th>Size</th><th>Access</th><th>Created</th><th className="right">Actions</th></tr></thead>
              <tbody>
                {files.map((f) => (
                  <tr key={f.file_id}>
                    <td><div style={{ fontWeight: 600 }}>{f.name}</div><div className="mono xs muted">{f.file_id}</div></td>
                    <td><ClassBadge c={f.classification} /></td>
                    <td>{f.owner_username}</td>
                    <td className="mono">v{f.version}</td>
                    <td className="nowrap">{fmtSize(f.size)}</td>
                    <td>{f.via === "owner" ? <Badge tone="info">owner</Badge> : <Badge tone="warn">via grant</Badge>}</td>
                    <td className="xs muted nowrap">{fmtDate(f.created_at)}</td>
                    <td className="actions right">
                      <Button size="sm" onClick={() => download(f, "view")} icon={Icons.eye({ size: 13 })}>View</Button>
                      <Button size="sm" onClick={() => download(f, "download")} icon={Icons.download({ size: 13 })}>Download</Button>
                      <Button size="sm" variant="ghost" onClick={() => showDetail(f)} icon={Icons.info({ size: 13 })} aria-label={`Details of ${f.name}`}>Info</Button>
                      {f.via === "owner" && ztv && <Button size="sm" onClick={() => setShare(f)} icon={Icons.share({ size: 13 })}>Share</Button>}
                      {f.via === "owner" && ztv && <Button size="sm" variant="ghost" onClick={() => setRotateFor(f)} icon={Icons.rotate({ size: 13 })} title="Hard re-key: new DEK, new version, recipients lose access">Rotate</Button>}
                      {f.via === "owner" && <Button size="sm" variant="danger" onClick={() => setConfirmDel(f)} icon={Icons.trash({ size: 13 })} aria-label={`Delete ${f.name}`} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <input ref={rotateInput} type="file" className="sr-only" tabIndex={-1} onChange={(e) => { const f = e.target.files?.[0]; const r = rotateFor; setRotateFor(null); if (f && r) doUpload(f, r); e.target.value = ""; }} />

      {share && <ShareDialog file={share} onClose={() => setShare(null)} />}

      {rotateFor && (
        <Modal
          title={`Rotate “${rotateFor.name}” (hard re-key)`}
          onClose={() => setRotateFor(null)}
          footer={<><Button onClick={() => setRotateFor(null)}>Cancel</Button><Button variant="primary" onClick={() => rotateInput.current?.click()} icon={Icons.rotate({ size: 14 })}>Choose new content…</Button></>}
        >
          <AlertBox tone="warn">
            This uploads a new version (v{rotateFor.version + 1}) encrypted under a <b>fresh DEK</b>, wrapped only for you. The old version's chunks are deleted on the server and every existing grant stops working — recipients must be re-shared explicitly.
          </AlertBox>
          <p className="small muted mt3">Classification stays <ClassBadge c={rotateFor.classification} />. Pick the (possibly identical) file content to re-key.</p>
        </Modal>
      )}

      {confirmDel && (
        <Modal title="Delete file" onClose={() => setConfirmDel(null)} footer={<><Button onClick={() => setConfirmDel(null)}>Cancel</Button><Button variant="danger" solid onClick={() => remove(confirmDel)} icon={Icons.trash({ size: 14 })}>Delete</Button></>}>
          <p>Delete <b>{confirmDel.name}</b> (<ClassBadge c={confirmDel.classification} />)? All versions, chunks and grants are removed. This cannot be undone.</p>
        </Modal>
      )}

      {preview && (
        <Modal title={`Preview — ${preview.file.name}`} onClose={() => setPreview(null)} wide footer={<Button onClick={() => setPreview(null)}>Close</Button>}>
          <AlertBox tone="ok">Decrypted in a worker after signature + Merkle verification. Showing the first 4000 bytes as text.</AlertBox>
          <pre className="json mt3">{preview.text}</pre>
        </Modal>
      )}

      {detail && (
        <Drawer title={detail.file.name} onClose={() => setDetail(null)}>
          <div className="row mb4">
            <ClassBadge c={detail.file.classification} />
            <Badge>v{detail.file.version}</Badge>
            <Badge tone={detail.file.via === "owner" ? "info" : "warn"}>{detail.file.via}</Badge>
            <Badge>{fmtSize(detail.file.size)}</Badge>
          </div>
          <table className="kv small mb4">
            <tbody>
              <tr><th>file id</th><td className="mono">{detail.file.file_id} <CopyButton text={detail.file.file_id} /></td></tr>
              <tr><th>owner</th><td>{detail.file.owner_username} <span className="mono muted xs">{detail.file.owner_id}</span></td></tr>
              <tr><th>created</th><td>{fmtDate(detail.file.created_at)}</td></tr>
              {Array.isArray((detail.meta as { versions?: unknown[] }).versions) && (
                <tr><th>versions</th><td>{((detail.meta as { versions: { version?: number; status?: string; created_at?: string }[] }).versions).map((v, i) => <Badge key={i} className="mt1" tone={v.status === "active" ? "ok" : "neutral"}>v{v.version ?? i + 1}{v.status ? ` · ${v.status}` : ""}</Badge>)}</td></tr>
              )}
            </tbody>
          </table>
          <label>Metadata + manifest (JSON)</label>
          <pre className="json">{JSON.stringify(detail.meta, null, 2)}</pre>
          <div className="row mt2"><CopyButton text={JSON.stringify(detail.meta, null, 2)} label="Copy JSON" /></div>
        </Drawer>
      )}
    </>
  );
}

function saveBlob(b: Blob, name: string) {
  const url = URL.createObjectURL(b);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function ShareDialog({ file, onClose }: { file: FileRow; onClose: () => void }) {
  const { keys, orgRoot, session } = useApp();
  const toast = useToast();
  const [q, setQ] = useState("");
  const [users, setUsers] = useState<DirUser[]>([]);
  const [recipient, setRecipient] = useState<DirUser | null>(null);
  const [recCert, setRecCert] = useState<{ cert: UserCert; verified: boolean; fingerprint: string } | null>(null);
  const [rights, setRights] = useState<"view" | "view,download">("view,download");
  const [days, setDays] = useState(7);
  const [maxDl, setMaxDl] = useState(3);
  const [posture, setPosture] = useState<"any" | "registered" | "trusted">("registered");
  const [grants, setGrants] = useState<GrantRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadGrants = useCallback(() => {
    api.get<GrantRow[]>(`/api/shares?file_id=${encodeURIComponent(file.file_id)}`).then(setGrants).catch(() => setGrants([]));
  }, [file.file_id]);
  useEffect(loadGrants, [loadGrants]);
  useEffect(() => {
    api.get<DirUser[]>(`/api/keys/directory?q=${encodeURIComponent(q)}`).then(setUsers).catch(() => setUsers([]));
  }, [q]);

  const pick = async (u: DirUser) => {
    setRecipient(u);
    setRecCert(null);
    setErr(null);
    try {
      const r = await api.get<{ cert: UserCert }>(`/api/keys/directory/${u.user_id}`);
      if (!orgRoot.pk) throw new Error("no org root available — cannot verify recipient certificate");
      const verified = await verifyUserCert(r.cert, orgRoot.pk, { expectedUserId: u.user_id });
      setRecCert({ cert: r.cert, verified, fingerprint: await certFingerprint(b64uDecode(r.cert.enc_pk), b64uDecode(r.cert.sig_pk)) });
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 404 ? "recipient has no issued certificate" : (e as Error).message);
    }
  };

  const doShare = async () => {
    if (!keys || !recipient || !recCert) return;
    if (!recCert.verified) return setErr("recipient certificate does NOT verify against the pinned org root — refusing to wrap the DEK");
    setErr(null);
    setBusy(true);
    try {
      // Owner re-obtains the DEK through the normal access path, then wraps it for the recipient.
      const a = await api.post<AccessResp>(`/api/files/${file.file_id}/access`, { intent: "view" });
      const dek = await unwrapDek(a.wrapped_dek, keys.enc, file.file_id, a.version);
      const wrapped = await wrapDek(dek, b64uDecode(recCert.cert.enc_pk), file.file_id, a.version);
      dek.fill(0);
      const exp = new Date(Date.now() + days * 86400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
      const grant = await signGrant(
        { grant_id: uuidv4(), file_id: file.file_id, owner_id: session.user!.id, recipient_id: recipient.user_id, rights: rights.split(","), expires_at: exp, max_downloads: maxDl, required_posture: posture, issued_at: nowIso() },
        keys.sig,
      );
      await api.post("/api/shares", { grant, wrapped_dek: wrapped });
      setMsg(`shared with ${recipient.username} (grant signed, DEK wrapped for ${recCert.fingerprint.slice(0, 9)}…)`);
      toast.success(`Shared with ${recipient.username}`, "Grant signed with your Ed25519 key; DEK wrapped for the recipient's X25519 key.");
      loadGrants();
    } catch (e) {
      setErr(e instanceof ApiError ? `share failed: ${e.message}` : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (g: GrantRow) => {
    try {
      await api.del(`/api/shares/${g.grant_id}`);
      setMsg(`grant ${g.grant_id.slice(0, 8)}… revoked (soft: wrapped DEK deleted, blob tokens revoked)`);
      toast.success("Grant revoked", "Soft revocation: wrapped DEK deleted and outstanding blob tokens revoked.");
      loadGrants();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const candidates = users.filter((u) => u.user_id !== session.user!.id);

  return (
    <Modal title={<span>Share <span className="mono">{file.name}</span> <ClassBadge c={file.classification} /></span>} onClose={onClose} wide footer={<><Button onClick={onClose}>Close</Button><Button variant="primary" onClick={doShare} busy={busy} disabled={!recCert?.verified || !keys} icon={Icons.share({ size: 14 })}>Sign grant &amp; share</Button></>}>
      <div className="field">
        <label htmlFor="recq">Recipient (directory search)</label>
        <input id="recq" value={q} onChange={(e) => setQ(e.target.value)} placeholder="username…" autoFocus />
      </div>
      <div className="row mt2" role="listbox" aria-label="Recipients">
        {candidates.map((u) => (
          <Button key={u.user_id} size="sm" onClick={() => pick(u)} variant={recipient?.user_id === u.user_id ? "primary" : "secondary"} disabled={!u.has_cert} role="option" aria-selected={recipient?.user_id === u.user_id} title={u.has_cert ? `${u.role}, ${u.department}` : "no certificate issued"}>
            {u.username} <span className="xs" style={{ opacity: 0.7 }}>· {u.department}{u.has_cert ? "" : " · no cert"}</span>
          </Button>
        ))}
        {candidates.length === 0 && <span className="muted small">no matching users</span>}
      </div>

      {recipient && !recCert && !err && <p className="muted small mt3 row"><Spinner /> fetching and verifying {recipient.username}'s certificate…</p>}
      {recCert && (
        <div className="mt4">
          <div className={`verdict-big ${recCert.verified ? "ok" : "bad"}`}>{recCert.verified ? "CERTIFICATE VERIFIED against the pinned org root" : "CERTIFICATE INVALID — do not share"}</div>
          <div className="row mt3" style={{ alignItems: "flex-start" }}>
            <div>
              <label>{recipient?.username}'s key fingerprint</label>
              <FingerprintDisplay fp={recCert.fingerprint} small />
            </div>
            <div className="small muted">serial <span className="mono">{recCert.cert.serial}</span><br />expires {recCert.cert.exp}</div>
          </div>
        </div>
      )}

      <div className="split mt4">
        <div className="field">
          <label htmlFor="rights">Rights</label>
          <select id="rights" value={rights} onChange={(e) => setRights(e.target.value as "view" | "view,download")}>
            <option value="view">view</option>
            <option value="view,download">view + download</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="posture2">Required device posture</label>
          <select id="posture2" value={posture} onChange={(e) => setPosture(e.target.value as typeof posture)}>
            <option>any</option><option>registered</option><option>trusted</option>
          </select>
        </div>
        <div className="field"><label htmlFor="days">Expires in (days)</label><input id="days" type="number" min={1} value={days} onChange={(e) => setDays(Number(e.target.value))} /></div>
        <div className="field"><label htmlFor="maxdl">Max downloads</label><input id="maxdl" type="number" min={1} value={maxDl} onChange={(e) => setMaxDl(Number(e.target.value))} /></div>
      </div>
      {err && <div className="mt3"><AlertBox tone="bad">{err}</AlertBox></div>}
      {msg && <div className="mt3"><AlertBox tone="ok">{msg}</AlertBox></div>}

      <h4 className="mt6 mb2">Active grants</h4>
      <GrantsTable grants={grants} onRevoke={revoke} />
    </Modal>
  );
}

export function GrantsTable({ grants, onRevoke, showFile, files }: { grants: GrantRow[]; onRevoke: (g: GrantRow) => void; showFile?: boolean; files?: Record<string, FileRow> }) {
  if (grants.length === 0) return <p className="muted small">No active grants.</p>;
  return (
    <div className="table-wrap" style={{ borderRadius: "var(--r-md)", border: "1px solid var(--border)" }}>
      <table>
        <thead><tr>{showFile && <th>File</th>}<th>Recipient</th><th>Rights</th><th>Expires</th><th>Downloads</th><th>Posture</th><th></th></tr></thead>
        <tbody>
          {grants.map((g) => {
            const expired = new Date(g.expires_at).getTime() < Date.now();
            const exhausted = (g.downloads_used ?? 0) >= g.max_downloads;
            return (
              <tr key={g.grant_id}>
                {showFile && <td>{files?.[g.file_id] ? <span><b>{files[g.file_id].name}</b> <ClassBadge c={files[g.file_id].classification} /></span> : <span className="mono xs">{g.file_id}</span>}</td>}
                <td className="mono xs">{g.recipient_id}</td>
                <td>{g.rights.map((r) => <Badge key={r} tone="info">{r}</Badge>)}</td>
                <td className={expired ? "err" : ""}>{fmtDate(g.expires_at)}{expired && <Badge tone="bad" className="mt1">expired</Badge>}</td>
                <td><span className={exhausted ? "err" : ""}>{g.downloads_used ?? 0}/{g.max_downloads}</span></td>
                <td><Badge tone={g.required_posture === "trusted" ? "warn" : "neutral"}>{g.required_posture}</Badge></td>
                <td className="right"><Button size="sm" variant="danger" onClick={() => onRevoke(g)}>Revoke</Button></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
