import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { useApp } from "../state";
import { uploadFile } from "../crypto/upload";
import { unwrapDek, wrapDek, type WrapRecord } from "../crypto/wrap";
import { certFingerprint, signGrant, verifyManifest, verifyUserCert, type Grant, type Manifest, type UserCert } from "../crypto/sign";
import { b64uDecode, nowIso, toBuf, uuidv4 } from "../crypto/encoding";
import type { DecryptMessage } from "../crypto/worker/decrypt.worker";

interface FileRow {
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
interface GrantRow extends Grant {
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

function fmtSize(n: number) {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
}

export default function Files() {
  const { session, keys, cert, orgRoot, mode } = useApp();
  const ztv = mode === "zerotrustvault";
  const [files, setFiles] = useState<FileRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [classification, setClassification] = useState("INTERNAL");
  const [upload, setUpload] = useState<{ name: string; pct: number; status: string } | null>(null);
  const [dl, setDl] = useState<{ name: string; pct: number; status: string; ok?: boolean } | null>(null);
  const [share, setShare] = useState<FileRow | null>(null);
  const [versions, setVersions] = useState<{ file: FileRow; meta: Record<string, unknown> } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

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
      setUpload({ name: f.name, pct: 50, status: "uploading plaintext (baseline)" });
      try {
        const r = await fetch("/api/files/upload", { method: "POST", headers: { Authorization: `Bearer ${session.accessToken}` }, body: fd });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setUpload({ name: f.name, pct: 100, status: "done" });
        load();
      } catch (e) {
        setErr((e as Error).message);
        setUpload(null);
      }
      return;
    }
    if (!keys) return setErr("unlock your keys first (Keys page)");
    if (!cert) return setErr("no issued certificate yet (Keys page) — the server rejects manifests without one");
    try {
      setUpload({ name: f.name, pct: 0, status: rotate ? "re-keying (new version)" : "encrypting + uploading" });
      const res = await uploadFile(f, rotate ? rotate.classification : classification, keys, session.user!.id, (p) => setUpload({ name: f.name, pct: Math.round(((p.index + 1) / p.total) * 100), status: `chunk ${p.index + 1}/${p.total} (${fmtSize(p.bytes)})` }), rotate ? { file_id: rotate.file_id } : undefined);
      if (rotate) {
        // Hard revocation: re-wrap the fresh DEK only for the owner (recipients must be re-shared explicitly).
        await api.post(`/api/files/${res.file_id}/versions/${res.version}/finalize`, { manifest: res.manifest, wrapped_dek: res.wrapped_dek, wrapped_deks: { [session.user!.id]: res.wrapped_dek } });
      } else {
        await api.post(`/api/files/${res.file_id}/versions/${res.version}/finalize`, { manifest: res.manifest, wrapped_dek: res.wrapped_dek });
      }
      setUpload({ name: f.name, pct: 100, status: `finalized v${res.version} — manifest signed, DEK wrapped` });
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
    if (!keys) return setErr("unlock your keys first (Keys page)");
    try {
      const a = await api.post<AccessResp>(`/api/files/${f.file_id}/access`, { intent });
      // Verify the manifest signature against the owner's cert (fetched from the directory and verified against the pinned root).
      const ownerCert = (await api.get<{ cert: UserCert }>(`/api/keys/directory/${f.owner_id}`)).cert;
      if (orgRoot.pk && !(await verifyUserCert(ownerCert, orgRoot.pk, { expectedUserId: f.owner_id }))) throw new Error("owner certificate does not verify against the pinned org root");
      if (!(await verifyManifest(a.manifest, b64uDecode(ownerCert.sig_pk)))) throw new Error("manifest signature INVALID — refusing to decrypt");
      if (a.manifest.file_id !== f.file_id) throw new Error("manifest file_id mismatch");
      setDl({ name: f.name, pct: 0, status: `manifest verified (v${a.version}, ${a.manifest.chunk_count} chunks); unwrapping DEK` });
      const dek = await unwrapDek(a.wrapped_dek, keys.enc, f.file_id, a.version);
      const worker = new Worker(new URL("../crypto/worker/decrypt.worker.ts", import.meta.url), { type: "module" });
      const parts: ArrayBuffer[] = [];
      const dekBuf = toBuf(dek);
      dek.fill(0);
      await new Promise<void>((resolve, reject) => {
        worker.onmessage = (ev: MessageEvent<DecryptMessage>) => {
          const m = ev.data;
          if (m.type === "chunk") parts[m.index] = m.data;
          else if (m.type === "progress") setDl({ name: f.name, pct: Math.round(((m.index + 1) / m.total) * 100), status: `chunk ${m.index + 1}/${m.total} verified + decrypted` });
          else if (m.type === "done") {
            setDl({ name: f.name, pct: 100, status: `integrity OK — merkle root matches signed manifest, ${m.chunkCount} chunks, ${fmtSize(m.bytes)}`, ok: true });
            resolve();
          } else if (m.type === "error") {
            setDl({ name: f.name, pct: 0, status: `INTEGRITY FAILURE (${m.stage}, chunk ${m.index}): ${m.message}`, ok: false });
            api.post(`/api/files/${f.file_id}/report-integrity`, { version: a.version, chunk_index: m.index, reason: `${m.stage}: ${m.message}` }).catch(() => undefined);
            reject(new Error(m.message));
          }
        };
        worker.onerror = (e) => reject(new Error(e.message));
        worker.postMessage({ type: "start", dek: dekBuf, manifest: a.manifest, chunkUrls: a.chunk_urls }, [dekBuf]);
      }).finally(() => worker.terminate());
      if (intent === "download") saveBlob(new Blob(parts), f.name);
      else {
        const text = new TextDecoder().decode(new Uint8Array(await new Blob(parts).arrayBuffer()).subarray(0, 4000));
        setVersions({ file: f, meta: { preview: text } });
      }
    } catch (e) {
      const msg = e instanceof ApiError ? (e.status === 403 ? "DENIED by policy (403)" : e.code === "step_up_required" ? "step-up cancelled" : e.message) : (e as Error).message;
      setDl((d) => (d?.ok === false ? d : { name: f.name, pct: 0, status: msg, ok: false }));
    }
  };

  const showVersions = async (f: FileRow) => {
    try {
      setVersions({ file: f, meta: await api.get<Record<string, unknown>>(`/api/files/${f.file_id}`) });
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const remove = async (f: FileRow) => {
    if (!confirm(`Delete ${f.name}?`)) return;
    await api.del(`/api/files/${f.file_id}`).catch((e) => setErr((e as Error).message));
    load();
  };

  return (
    <>
      <div className="card">
        <h2>Upload</h2>
        <div className="row">
          <input type="file" ref={fileInput} style={{ width: "auto" }} />
          <select value={classification} onChange={(e) => setClassification(e.target.value)} style={{ width: 160 }}>
            {CLASSES.map((c) => <option key={c}>{c}</option>)}
          </select>
          <button className="primary" onClick={() => fileInput.current?.files?.[0] && doUpload(fileInput.current.files[0])}>Encrypt &amp; upload</button>
          <span className="small muted">{ztv ? "AES-256-GCM 4 MiB STREAM chunks, Merkle root in an Ed25519-signed manifest, DEK wrapped with X25519-HKDF-AES-KW; one DPoP proof per chunk PUT." : "baseline: multipart plaintext upload"}</span>
        </div>
        {upload && (
          <div style={{ marginTop: 8 }}>
            <div className="small">{upload.name}: {upload.status}</div>
            <div className="progress"><div style={{ width: `${upload.pct}%` }} /></div>
          </div>
        )}
        {dl && (
          <div style={{ marginTop: 8 }}>
            <div className={`small ${dl.ok === false ? "err" : dl.ok ? "okc" : ""}`}>{dl.name}: {dl.status}</div>
            <div className="progress"><div style={{ width: `${dl.pct}%`, background: dl.ok === false ? "var(--bad)" : undefined }} /></div>
          </div>
        )}
        {err && <p className="err small">{err}</p>}
      </div>

      <div className="card">
        <h2>Files <button onClick={load} style={{ float: "right" }}>Refresh</button></h2>
        <table>
          <thead><tr><th>name</th><th>class</th><th>owner</th><th>v</th><th>size</th><th>via</th><th>actions</th></tr></thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.file_id}>
                <td>{f.name}<br /><span className="mono muted small">{f.file_id}</span></td>
                <td><span className="badge">{f.classification}</span></td>
                <td>{f.owner_username}</td>
                <td>{f.version}</td>
                <td>{fmtSize(f.size)}</td>
                <td>{f.via}</td>
                <td className="row">
                  <button onClick={() => download(f, "view")}>View</button>
                  <button onClick={() => download(f, "download")}>Download</button>
                  <button onClick={() => showVersions(f)}>Info</button>
                  {f.via === "owner" && ztv && <button onClick={() => setShare(f)}>Share</button>}
                  {f.via === "owner" && ztv && (
                    <label className="badge" style={{ margin: 0, cursor: "pointer" }}>
                      rotate (hard revoke)
                      <input type="file" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && doUpload(e.target.files[0], f)} />
                    </label>
                  )}
                  {f.via === "owner" && <button className="danger" onClick={() => remove(f)}>Delete</button>}
                </td>
              </tr>
            ))}
            {files.length === 0 && <tr><td colSpan={7} className="muted">no files</td></tr>}
          </tbody>
        </table>
      </div>

      {share && <ShareDialog file={share} onClose={() => setShare(null)} />}
      {versions && (
        <div className="modal-bg" onClick={() => setVersions(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{versions.file.name}</h3>
            <pre className="mono small" style={{ whiteSpace: "pre-wrap", maxHeight: 420, overflow: "auto" }}>{JSON.stringify(versions.meta, null, 2)}</pre>
            <button onClick={() => setVersions(null)}>Close</button>
          </div>
        </div>
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

function ShareDialog({ file, onClose }: { file: FileRow; onClose: () => void }) {
  const { keys, orgRoot, session } = useApp();
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
      loadGrants();
    } catch (e) {
      setErr(e instanceof ApiError ? `share failed: ${e.message}` : (e as Error).message);
    }
  };

  const revoke = async (g: GrantRow) => {
    try {
      await api.del(`/api/shares/${g.grant_id}`);
      setMsg(`grant ${g.grant_id.slice(0, 8)}… revoked (soft: wrapped DEK deleted, blob tokens revoked)`);
      loadGrants();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Share “{file.name}”</h3>
        <label>Recipient (directory search)</label>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="username…" />
        <div className="row" style={{ marginTop: 6 }}>
          {users.filter((u) => u.user_id !== session.user!.id).map((u) => (
            <button key={u.user_id} onClick={() => pick(u)} className={recipient?.user_id === u.user_id ? "primary" : ""} disabled={!u.has_cert}>
              {u.username} <span className="small muted">({u.department}{u.has_cert ? "" : ", no cert"})</span>
            </button>
          ))}
        </div>
        {recCert && (
          <div style={{ marginTop: 8 }}>
            <span className={`badge ${recCert.verified ? "ok" : "bad"}`}>{recCert.verified ? "certificate verified against pinned org root" : "CERTIFICATE INVALID"}</span>
            <div className="fp" style={{ marginTop: 6 }}>{recCert.fingerprint}</div>
            <div className="small muted">serial {recCert.cert.serial}, exp {recCert.cert.exp}</div>
          </div>
        )}
        <div className="row">
          <div style={{ flex: 1 }}>
            <label>Rights</label>
            <select value={rights} onChange={(e) => setRights(e.target.value as "view" | "view,download")}>
              <option value="view">view</option>
              <option value="view,download">view + download</option>
            </select>
          </div>
          <div style={{ flex: 1 }}><label>Expires in (days)</label><input type="number" min={1} value={days} onChange={(e) => setDays(Number(e.target.value))} /></div>
          <div style={{ flex: 1 }}><label>Max downloads</label><input type="number" min={1} value={maxDl} onChange={(e) => setMaxDl(Number(e.target.value))} /></div>
          <div style={{ flex: 1 }}>
            <label>Required posture</label>
            <select value={posture} onChange={(e) => setPosture(e.target.value as typeof posture)}>
              <option>any</option><option>registered</option><option>trusted</option>
            </select>
          </div>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <button className="primary" onClick={doShare} disabled={!recCert?.verified || !keys}>Sign grant &amp; share</button>
          <button onClick={onClose}>Close</button>
        </div>
        {err && <p className="err small">{err}</p>}
        {msg && <p className="okc small">{msg}</p>}
        <h3 style={{ marginTop: 14 }}>Active grants</h3>
        <table>
          <thead><tr><th>recipient</th><th>rights</th><th>expires</th><th>downloads</th><th>posture</th><th></th></tr></thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.grant_id}>
                <td className="mono small">{g.recipient_id}</td>
                <td>{g.rights.join("+")}</td>
                <td>{g.expires_at}</td>
                <td>{g.downloads_used ?? 0}/{g.max_downloads}</td>
                <td>{g.required_posture}</td>
                <td><button className="danger" onClick={() => revoke(g)}>Revoke</button></td>
              </tr>
            ))}
            {grants.length === 0 && <tr><td colSpan={6} className="muted">none</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
