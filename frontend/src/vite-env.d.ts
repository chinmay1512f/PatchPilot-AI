/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend origin when the UI is hosted separately (e.g. https://patchpilot-api.onrender.com). Empty = same origin. */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
