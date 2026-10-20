// Presentation primitives: Badge, Button, Card, Modal, Toast, Table helpers, EmptyState, Spinner, CopyButton,
// FingerprintDisplay, Stepper, BrandMark, icons. No logic lives here.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";

/* ---------- icons (inline SVG, stroke-based) ---------- */
const I = ({ d, size = 18, ...rest }: { d: string; size?: number } & Record<string, unknown>) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
    <path d={d} />
  </svg>
);
export const Icons = {
  files: (p?: Record<string, unknown>) => <I d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M9 13h6M9 17h6" {...p} />,
  share: (p?: Record<string, unknown>) => <I d="M4 12v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7M16 6l-4-4-4 4M12 2v13" {...p} />,
  dashboard: (p?: Record<string, unknown>) => <I d="M3 3h8v8H3zM13 3h8v5h-8zM13 12h8v9h-8zM3 15h8v6H3z" {...p} />,
  admin: (p?: Record<string, unknown>) => <I d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M22 11l-3 3-2-2" {...p} />,
  key: (p?: Record<string, unknown>) => <I d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L19 4m-3 3 2.5 2.5" {...p} />,
  settings: (p?: Record<string, unknown>) => <I d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" {...p} />,
  logout: (p?: Record<string, unknown>) => <I d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" {...p} />,
  upload: (p?: Record<string, unknown>) => <I d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12" {...p} />,
  download: (p?: Record<string, unknown>) => <I d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" {...p} />,
  eye: (p?: Record<string, unknown>) => <I d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z" {...p} />,
  info: (p?: Record<string, unknown>) => <I d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01" {...p} />,
  trash: (p?: Record<string, unknown>) => <I d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" {...p} />,
  rotate: (p?: Record<string, unknown>) => <I d="M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15" {...p} />,
  check: (p?: Record<string, unknown>) => <I d="M20 6L9 17l-5-5" {...p} />,
  x: (p?: Record<string, unknown>) => <I d="M18 6L6 18M6 6l12 12" {...p} />,
  copy: (p?: Record<string, unknown>) => <I d="M20 9h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" {...p} />,
  refresh: (p?: Record<string, unknown>) => <I d="M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15" {...p} />,
  pause: (p?: Record<string, unknown>) => <I d="M6 4h4v16H6zM14 4h4v16h-4z" {...p} />,
  play: (p?: Record<string, unknown>) => <I d="M5 3l14 9-14 9V3z" {...p} />,
  alert: (p?: Record<string, unknown>) => <I d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01" {...p} />,
  shield: (p?: Record<string, unknown>) => <I d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" {...p} />,
  inbox: (p?: Record<string, unknown>) => <I d="M22 12h-6l-2 3h-4l-2-3H2M5.5 5.1L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z" {...p} />,
};

export function BrandMark({ size = 32 }: { size?: number }) {
  return (
    <svg className="brand-mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="ztv-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--accent)" />
          <stop offset="1" stopColor="#8a5cff" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 4.5 6.8v8.4c0 7.3 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7 11.5-14.3V6.8L16 2.5z" fill="url(#ztv-g)" />
      <rect x="11" y="14" width="10" height="8" rx="1.8" fill="#06101f" opacity="0.9" />
      <path d="M12.8 14v-2.2a3.2 3.2 0 0 1 6.4 0V14" fill="none" stroke="#06101f" strokeWidth="1.9" opacity="0.9" />
      <circle cx="16" cy="18" r="1.3" fill="var(--accent)" />
    </svg>
  );
}

/* ---------- Badge ---------- */
export type Tone = "ok" | "bad" | "warn" | "alert" | "info" | "neutral";
export function Badge({ tone = "neutral", children, className = "", title, lg }: { tone?: Tone; children: ReactNode; className?: string; title?: string; lg?: boolean }) {
  return <span className={`badge ${tone === "neutral" ? "" : tone} ${lg ? "lg" : ""} ${className}`} title={title}>{children}</span>;
}
export function ClassBadge({ c }: { c: string }) {
  return <span className={`badge cls ${c}`}>{c}</span>;
}
export function DecisionBadge({ d }: { d: string }) {
  const tone: Tone = d === "PERMIT" ? "ok" : d === "DENY" ? "bad" : d === "ALERT" ? "alert" : "info";
  return <Badge tone={tone}>{d}</Badge>;
}
export function Dot({ tone }: { tone: "ok" | "warn" | "bad" | "info" | "neutral" }) {
  return <span className={`dot ${tone === "neutral" ? "" : tone}`} aria-hidden="true" />;
}

/* ---------- Button ---------- */
type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost"; size?: "sm" | "md" | "lg"; busy?: boolean; solid?: boolean; icon?: ReactNode };
export function Button({ variant = "secondary", size = "md", busy, solid, icon, className = "", children, disabled, type = "button", ...rest }: BtnProps) {
  return (
    <button type={type} className={`btn ${variant === "secondary" ? "" : variant} ${size === "md" ? "" : size} ${solid ? "solid" : ""} ${className}`} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy ? <Spinner /> : icon}
      {children}
    </button>
  );
}

/* ---------- Card ---------- */
export function Card({ title, sub, actions, children, className = "", tight, tone }: { title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; tight?: boolean; tone?: "ok" | "danger" }) {
  return (
    <section className={`card ${tight ? "tight" : ""} ${tone ?? ""} ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h3>{title}</h3>}
            {sub && <div className="sub">{sub}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

/* ---------- Modal ---------- */
export function Modal({ title, onClose, children, footer, wide }: { title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-bg" onMouseDown={onClose} role="presentation">
      <div className={`modal ${wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>{title}</h3>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close" icon={Icons.x({ size: 16 })} />
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined}>
        <div className="modal-head">
          <h3>{title}</h3>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close" icon={Icons.x({ size: 16 })} />
        </div>
        <div className="modal-body">{children}</div>
      </aside>
    </>
  );
}

/* ---------- Toasts ---------- */
type Toast = { id: number; kind: "success" | "error" | "warn" | "info"; title: string; body?: string };
const ToastCtx = createContext<{ push: (t: Omit<Toast, "id">) => void } | null>(null);
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs, { ...t, id }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), t.kind === "error" ? 9000 : 5000);
  }, []);
  const value = useMemo(() => ({ push }), [push]);
  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div className="toasts" aria-live="polite" aria-atomic="false">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
            <div className="grow">
              <div className="t">{t.title}</div>
              {t.body && <div className="muted small">{t.body}</div>}
            </div>
            <Button variant="ghost" size="sm" aria-label="Dismiss" onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))} icon={Icons.x({ size: 14 })} />
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
export function useToast() {
  const c = useContext(ToastCtx);
  if (!c) throw new Error("ToastProvider missing");
  return {
    success: (title: string, body?: string) => c.push({ kind: "success", title, body }),
    error: (title: string, body?: string) => c.push({ kind: "error", title, body }),
    warn: (title: string, body?: string) => c.push({ kind: "warn", title, body }),
    info: (title: string, body?: string) => c.push({ kind: "info", title, body }),
  };
}

/* ---------- misc ---------- */
export function Spinner() {
  return <span className="spinner" role="status" aria-label="Loading" />;
}

export function EmptyState({ title, body, icon, action }: { title: string; body?: string; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      {icon ?? Icons.inbox({ size: 36 })}
      <h4>{title}</h4>
      {body && <p className="small">{body}</p>}
      {action}
    </div>
  );
}

export function AlertBox({ tone, children }: { tone: "ok" | "bad" | "warn" | "info"; children: ReactNode }) {
  return (
    <div className={`alertbox ${tone}`} role={tone === "bad" ? "alert" : "status"}>
      {tone === "bad" || tone === "warn" ? Icons.alert({ size: 16 }) : tone === "ok" ? Icons.check({ size: 16 }) : Icons.info({ size: 16 })}
      <div className="grow">{children}</div>
    </div>
  );
}

export function CopyButton({ text, label = "Copy", size = "sm" }: { text: string; label?: string; size?: "sm" | "md" }) {
  const [done, setDone] = useState(false);
  const t = useRef<number | undefined>(undefined);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      window.clearTimeout(t.current);
      t.current = window.setTimeout(() => setDone(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <Button size={size} variant="ghost" onClick={copy} icon={done ? Icons.check({ size: 14 }) : Icons.copy({ size: 14 })} aria-label={`${label} to clipboard`}>
      {done ? "Copied" : label}
    </Button>
  );
}

/** Fingerprint as 8 monospace groups (the server formats it as space-separated groups already). */
export function FingerprintDisplay({ fp, small, copy = true }: { fp: string; small?: boolean; copy?: boolean }) {
  const groups = fp.trim().split(/\s+/);
  return (
    <div className="fp-wrap">
      <div className={`fp ${small ? "sm" : ""}`} aria-label={`fingerprint ${fp}`}>
        {groups.map((g, i) => <span key={i}>{g}</span>)}
      </div>
      {copy && <CopyButton text={fp} label="Copy fingerprint" />}
    </div>
  );
}

export function Progress({ pct, tone }: { pct: number; tone?: "ok" | "bad" | "warn" }) {
  return (
    <div className={`progress ${tone ?? ""}`} role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
      <div style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
    </div>
  );
}

export type StepState = "done" | "active" | "waiting" | "todo";
export function Stepper({ steps }: { steps: { title: string; state: StepState; body?: ReactNode }[] }) {
  return (
    <ol className="stepper" style={{ listStyle: "none", margin: 0, padding: 0 }}>
      {steps.map((s, i) => (
        <li key={i} className={`step ${s.state} ${s.state === "todo" ? "muted-step" : ""}`} aria-current={s.state === "active" ? "step" : undefined}>
          <div className="step-n">{s.state === "done" ? Icons.check({ size: 14 }) : i + 1}</div>
          <div>
            <div className="step-title">{s.title}</div>
            {s.body && <div className="step-body">{s.body}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function fmtSize(n: number) {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
}
export function fmtTime(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}
export function fmtDate(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString([], { hour12: false });
}
export function initials(name: string) {
  return name.slice(0, 2).toUpperCase();
}
