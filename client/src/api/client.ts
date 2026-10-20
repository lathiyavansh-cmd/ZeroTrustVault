// Fetch wrapper: DPoP-bound access tokens (ztv mode) or Bearer (baseline), auto-refresh, step-up handling, clock skew.
// Never logs tokens, proofs or passphrases.
import { getOrCreateDeviceKey, type DeviceKey } from "../crypto/device";
import { makeDpopProof } from "../crypto/dpop";
import { toBuf } from "../crypto/encoding";

export type Mode = "zerotrustvault" | "baseline";

export interface SessionUser {
  id: string;
  username: string;
  role: string;
  department: string;
  clearance: number;
}

export interface SessionState {
  mode: Mode;
  accessToken: string | null;
  refreshToken: string | null;
  tokenType: "DPoP" | "Bearer";
  expiresAt: number; // unix ms
  user: SessionUser | null;
  deviceId: string | null;
  risk?: { score: number; level: string };
  elevatedUntil?: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string | undefined,
    public body: unknown,
  ) {
    super(`HTTP ${status}${code ? ` (${code})` : ""}`);
  }
}

type StepUpHandler = () => Promise<string | null>; // returns TOTP code or null (cancel)

const SESSION_KEY = "ztv.session";

class ApiClient {
  state: SessionState = { mode: "zerotrustvault", accessToken: null, refreshToken: null, tokenType: "DPoP", expiresAt: 0, user: null, deviceId: null };
  skewSeconds = 0; // server_time - local_time
  private device: DeviceKey | null = null;
  private refreshing: Promise<void> | null = null;
  private listeners = new Set<() => void>();
  onStepUp: StepUpHandler | null = null;
  onSessionLost: (() => void) | null = null;
  stepUpEvents: { at: string; ok: boolean }[] = [];

  constructor() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (raw) this.state = { ...this.state, ...(JSON.parse(raw) as SessionState) };
    } catch {
      /* ignore */
    }
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  private emit() {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(this.state));
    } catch {
      /* ignore */
    }
    this.listeners.forEach((l) => l());
  }
  setState(patch: Partial<SessionState>) {
    this.state = { ...this.state, ...patch };
    this.emit();
  }
  get isAuthenticated(): boolean {
    return !!this.state.accessToken && !!this.state.user;
  }

  async deviceKey(): Promise<DeviceKey> {
    if (!this.device) this.device = await getOrCreateDeviceKey();
    return this.device;
  }

  serverNow(): number {
    return Math.floor(Date.now() / 1000) + this.skewSeconds;
  }

  htuBase(): string {
    return import.meta.env.VITE_HTU_ORIGIN || location.origin;
  }

  async loadMode(): Promise<Mode> {
    const r = await fetch("/api/mode");
    this.readServerTime(r);
    if (r.ok) {
      const j = (await r.json()) as { mode: Mode };
      if (j.mode !== this.state.mode) this.setState({ mode: j.mode });
      return j.mode;
    }
    return this.state.mode;
  }

  private readServerTime(r: Response) {
    const t = r.headers.get("X-Server-Time");
    if (t && /^\d+(\.\d+)?$/.test(t)) this.skewSeconds = Math.round(Number(t) - Date.now() / 1000);
  }

  /** Mint a DPoP proof for a request (ztv mode). Exposed so uploads can mint one proof per chunk PUT. */
  async proof(method: string, path: string, withAth = true): Promise<string> {
    const key = await this.deviceKey();
    return makeDpopProof(key, method, this.htuBase() + path, { accessToken: withAth && this.state.accessToken ? this.state.accessToken : undefined, iat: this.serverNow() });
  }

  private async authHeaders(method: string, path: string): Promise<Record<string, string>> {
    const h: Record<string, string> = {};
    const tok = this.state.accessToken;
    if (!tok) return h;
    if (this.state.mode === "baseline" || this.state.tokenType === "Bearer") {
      h.Authorization = `Bearer ${tok}`;
    } else {
      h.Authorization = `DPoP ${tok}`;
      h.DPoP = await this.proof(method, path, true);
    }
    return h;
  }

  async request<T>(method: string, path: string, opts: { body?: unknown; bytes?: Uint8Array; auth?: boolean; headers?: Record<string, string>; retry?: boolean } = {}): Promise<T> {
    const auth = opts.auth ?? true;
    if (auth && this.state.tokenType === "DPoP" && this.state.accessToken && Date.now() > this.state.expiresAt - 15_000) {
      await this.refresh();
    }
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (auth) Object.assign(headers, await this.authHeaders(method, path));
    let body: BodyInit | undefined;
    if (opts.bytes) {
      headers["Content-Type"] = "application/octet-stream";
      body = toBuf(opts.bytes);
    } else if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    const r = await fetch(path, { method, headers, body });
    this.readServerTime(r);
    if (r.status === 204) return undefined as T;
    const text = await r.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = text;
    }
    if (r.ok) return json as T;
    const code = (json as { code?: string } | null)?.code;
    if (r.status === 401 && auth && opts.retry !== false) {
      if (code === "step_up_required" && this.onStepUp) {
        const totp = await this.onStepUp();
        if (totp) {
          try {
            await this.request<{ elevated_until: string }>("POST", "/api/auth/step-up", { body: { code: totp }, retry: false }).then((j) => this.setState({ elevatedUntil: j.elevated_until }));
            this.stepUpEvents.push({ at: new Date().toISOString(), ok: true });
            return this.request<T>(method, path, { ...opts, retry: false });
          } catch {
            this.stepUpEvents.push({ at: new Date().toISOString(), ok: false });
          }
        }
      } else if (this.state.refreshToken && this.state.tokenType === "DPoP" && code !== "step_up_required") {
        try {
          await this.refresh(true);
          return this.request<T>(method, path, { ...opts, retry: false });
        } catch {
          this.logoutLocal();
        }
      }
    }
    throw new ApiError(r.status, code, json);
  }

  get<T>(path: string) {
    return this.request<T>("GET", path);
  }
  post<T>(path: string, body?: unknown, headers?: Record<string, string>) {
    return this.request<T>("POST", path, { body, headers });
  }
  put<T>(path: string, body?: unknown) {
    return this.request<T>("PUT", path, { body });
  }
  del<T>(path: string) {
    return this.request<T>("DELETE", path);
  }
  putBytes(path: string, bytes: Uint8Array) {
    return this.request<void>("PUT", path, { bytes });
  }

  /** Refresh the 5-minute DPoP-bound access token (proof without ath, same device key). */
  async refresh(force = false): Promise<void> {
    if (this.state.tokenType !== "DPoP" || !this.state.refreshToken) return;
    if (!force && Date.now() < this.state.expiresAt - 15_000) return;
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      const path = "/api/auth/refresh";
      const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: await this.proof("POST", path, false) },
        body: JSON.stringify({ refresh_token: this.state.refreshToken }),
      });
      this.readServerTime(r);
      if (!r.ok) {
        this.logoutLocal();
        throw new ApiError(r.status, undefined, null);
      }
      const j = (await r.json()) as { access_token: string; expires_in: number };
      this.setState({ accessToken: j.access_token, expiresAt: Date.now() + j.expires_in * 1000 });
    })().finally(() => (this.refreshing = null));
    return this.refreshing;
  }

  applyLoginResponse(j: { token_type: "DPoP" | "Bearer"; access_token: string; refresh_token?: string; expires_in?: number; user: SessionUser; device_id?: string; risk?: { score: number; level: string } }) {
    this.setState({
      accessToken: j.access_token,
      refreshToken: j.refresh_token ?? null,
      tokenType: j.token_type,
      expiresAt: Date.now() + (j.expires_in ?? 30 * 24 * 3600) * 1000,
      user: j.user,
      deviceId: j.device_id ?? null,
      risk: j.risk,
    });
  }

  async logout() {
    try {
      if (this.state.accessToken) await this.request<void>("POST", "/api/auth/logout", { retry: false });
    } catch {
      /* ignore */
    }
    this.logoutLocal();
  }
  logoutLocal() {
    this.setState({ accessToken: null, refreshToken: null, user: null, deviceId: null, risk: undefined, elevatedUntil: undefined });
    this.onSessionLost?.();
  }
}

export const api = new ApiClient();
