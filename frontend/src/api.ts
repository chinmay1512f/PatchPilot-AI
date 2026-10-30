import type { Health, Job, JobSummary, Sample, Stats } from "./types";

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error((await r.json().catch(() => ({ detail: r.statusText }))).detail ?? r.statusText);
  return r.json() as Promise<T>;
}

export const api = {
  health: () => get<Health>("/api/health"),
  stats: () => get<Stats>("/api/stats"),
  jobs: () => get<JobSummary[]>("/api/jobs"),
  job: (id: string) => get<Job>(`/api/jobs/${id}`),
  samples: () => get<Sample[]>("/api/samples"),
  file: async (id: string, path: string, version = "original") => {
    const r = await fetch(`/api/jobs/${id}/file?path=${encodeURIComponent(path)}&version=${version}`);
    if (!r.ok) throw new Error("File not available");
    return r.text();
  },
  sampleZip: async (name: string, part = "repo") => {
    const r = await fetch(`/api/samples/${name}/download?part=${part}`);
    if (!r.ok) throw new Error("Sample not available");
    return new File([await r.blob()], `${name}-${part}.zip`, { type: "application/zip" });
  },
  createJob: async (form: FormData) => {
    const r = await fetch("/api/jobs", { method: "POST", body: form });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.detail ?? `Upload failed (${r.status})`);
    return body as JobSummary;
  },
  rerun: async (id: string) => {
    const r = await fetch(`/api/jobs/${id}/rerun`, { method: "POST" });
    if (!r.ok) throw new Error("Re-run failed");
    return (await r.json()) as JobSummary;
  },
  deleteJob: async (id: string) => {
    const r = await fetch(`/api/jobs/${id}`, { method: "DELETE" });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? `Delete failed (${r.status})`);
  },
};
