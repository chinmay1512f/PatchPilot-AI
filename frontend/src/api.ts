import type { Health, Job, JobSummary, Sample, Stats } from "./types";

// Empty = same origin (local: FastAPI serves the UI, or the Vite dev proxy). On Vercel, set
// VITE_API_BASE to the backend URL, e.g. https://patchpilot-api.onrender.com
const BASE = (import.meta.env.VITE_API_BASE ?? "").trim().replace(/\/+$/, "");

/** Absolute URL for an API path; use for fetches and for download links. */
export const apiUrl = (path: string) => `${BASE}${path}`;

async function errorText(r: Response, fallback: string): Promise<string> {
  const body = await r.json().catch(() => ({}));
  return body.detail ?? fallback;
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(apiUrl(path));
  if (!r.ok) throw new Error(await errorText(r, r.statusText));
  return r.json() as Promise<T>;
}

export const api = {
  health: () => get<Health>("/api/health"),
  stats: () => get<Stats>("/api/stats"),
  jobs: () => get<JobSummary[]>("/api/jobs"),
  job: (id: string) => get<Job>(`/api/jobs/${id}`),
  samples: () => get<Sample[]>("/api/samples"),
  file: async (id: string, path: string, version = "original") => {
    const r = await fetch(apiUrl(`/api/jobs/${id}/file?path=${encodeURIComponent(path)}&version=${version}`));
    if (!r.ok) throw new Error("File not available");
    return r.text();
  },
  sampleZip: async (name: string, part = "repo") => {
    const r = await fetch(apiUrl(`/api/samples/${name}/download?part=${part}`));
    if (!r.ok) throw new Error("Sample not available");
    return new File([await r.blob()], `${name}-${part}.zip`, { type: "application/zip" });
  },
  createJob: async (form: FormData) => {
    const r = await fetch(apiUrl("/api/jobs"), { method: "POST", body: form });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.detail ?? `Upload failed (${r.status})`);
    return body as JobSummary;
  },
  rerun: async (id: string) => {
    const r = await fetch(apiUrl(`/api/jobs/${id}/rerun`), { method: "POST" });
    if (!r.ok) throw new Error(await errorText(r, "Re-run failed"));
    return (await r.json()) as JobSummary;
  },
  deleteJob: async (id: string) => {
    const r = await fetch(apiUrl(`/api/jobs/${id}`), { method: "DELETE" });
    if (!r.ok) throw new Error(await errorText(r, `Delete failed (${r.status})`));
  },
};
