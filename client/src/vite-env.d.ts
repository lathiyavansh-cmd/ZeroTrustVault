/// <reference types="vite/client" />
interface ImportMetaEnv {
  readonly VITE_ORG_ROOT_PK?: string;
  readonly VITE_HTU_ORIGIN?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
