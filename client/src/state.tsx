// App-wide security state: session, unlocked keys (in memory only), cert, device key, pinned org root.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, type Mode, type SessionState } from "./api/client";
import type { UserKeys } from "./crypto/keys";
import type { UserCert } from "./crypto/sign";
import { b64uDecode } from "./crypto/encoding";
import { hasDeviceKey } from "./crypto/device";
import { detectWebCryptoCurves } from "./crypto/curves";

export interface OrgRoot {
  pk: Uint8Array | null;
  pinned: boolean; // true when baked in at build time via VITE_ORG_ROOT_PK
  b64u: string;
}

interface AppState {
  session: SessionState;
  mode: Mode;
  keys: UserKeys | null;
  setKeys: (k: UserKeys | null) => void;
  cert: UserCert | null;
  setCert: (c: UserCert | null) => void;
  deviceKeyPresent: boolean;
  orgRoot: OrgRoot;
  curves: { ed: boolean; x: boolean } | null;
  stepUpPrompt: { resolve: (code: string | null) => void } | null;
  refreshDevice: () => void;
}

const Ctx = createContext<AppState | null>(null);

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState>(api.state);
  const [keys, setKeys] = useState<UserKeys | null>(null);
  const [cert, setCert] = useState<UserCert | null>(null);
  const [deviceKeyPresent, setDevice] = useState(false);
  const [curves, setCurves] = useState<{ ed: boolean; x: boolean } | null>(null);
  const [stepUpPrompt, setStepUp] = useState<AppState["stepUpPrompt"]>(null);
  const envPk = import.meta.env.VITE_ORG_ROOT_PK?.trim() || "";
  const [orgRoot, setOrgRoot] = useState<OrgRoot>(() => (envPk ? { pk: safeDecode(envPk), pinned: true, b64u: envPk } : { pk: null, pinned: false, b64u: "" }));

  const refreshDevice = useCallback(() => {
    hasDeviceKey().then(setDevice);
  }, []);

  useEffect(() => {
    const unsub = api.subscribe(() => setSession({ ...api.state }));
    api.loadMode().catch(() => undefined);
    refreshDevice();
    detectWebCryptoCurves().then(setCurves);
    api.onStepUp = () => new Promise<string | null>((resolve) => setStepUp({ resolve: (c) => { setStepUp(null); resolve(c); } }));
    api.onSessionLost = () => {
      setKeys(null);
      setCert(null);
    };
    if (!envPk) {
      // Unpinned (dev): fetch informational root from the API. Labelled "unpinned (dev)" in the UI.
      fetch("/api/keys/org-root")
        .then((r) => (r.ok ? r.json() : null))
        .then((j: { pk?: string } | null) => {
          if (j?.pk) setOrgRoot({ pk: safeDecode(j.pk), pinned: false, b64u: j.pk });
        })
        .catch(() => undefined);
    } else {
      // Pinned: compare with the server's copy and warn loudly on mismatch.
      fetch("/api/keys/org-root")
        .then((r) => (r.ok ? r.json() : null))
        .then((j: { pk?: string } | null) => {
          if (j?.pk && j.pk !== envPk) console.warn("org root mismatch: server-advertised root differs from the pinned key (refusing to use server copy)");
        })
        .catch(() => undefined);
    }
    return unsub;
  }, [envPk, refreshDevice]);

  const value = useMemo<AppState>(
    () => ({ session, mode: session.mode, keys, setKeys, cert, setCert, deviceKeyPresent, orgRoot, curves, stepUpPrompt, refreshDevice }),
    [session, keys, cert, deviceKeyPresent, orgRoot, curves, stepUpPrompt, refreshDevice],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("AppStateProvider missing");
  return v;
}

function safeDecode(s: string): Uint8Array | null {
  try {
    const b = b64uDecode(s);
    return b.length === 32 ? b : null;
  } catch {
    return null;
  }
}
