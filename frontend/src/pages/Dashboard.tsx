import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { BarChart, DonutChart, type Datum } from "../charts";
import type { JobSummary, Stats } from "../types";
import { ANALYSIS_LABEL, Empty, Icon, type IconName, StatusBadge, fmtTime, label } from "../ui";

const SEVERITY: [string, string, string][] = [
  ["critical", "Critical", "var(--sev-critical)"],
  ["high", "High", "var(--sev-high)"],
  ["medium", "Medium", "var(--sev-medium)"],
  ["low", "Low", "var(--sev-low)"],
  ["info", "Info", "var(--sev-info)"],
];
const OUTCOMES: [string, string, string][] = [
  ["verified", "Patch verified", "var(--st-verified)"],
  ["completed", "Completed (scan / review)", "var(--st-completed)"],
  ["inconclusive", "Inconclusive / blocked", "var(--st-inconclusive)"],
  ["failed", "Failed", "var(--st-failed)"],
  ["running", "Running", "var(--st-running)"],
];

function StatCard({ label: l, value, sub, icon, tone }: { label: string; value: string | number; sub?: string; icon: IconName; tone: string }) {
  return (
    <div className={`stat-card tone-${tone}`}>
      <div className="stat-text">
        <span className="label">{l}</span>
        <span className="value">{value}</span>
        {sub && <span className="sub">{sub}</span>}
      </div>
      <div className="stat-icon"><Icon name={icon} size={22} /></div>
    </div>
  );
}

function Insight({ k, v, d, danger }: { k: string; v: string; d?: string; danger?: boolean }) {
  return (
    <div className="insight">
      <div className="k">{k}</div>
      <div className={`v ${danger ? "danger" : ""}`}>{v}</div>
      {d && <div className="d">{d}</div>}
    </div>
  );
}

export function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [jobs, setJobs] = useState<JobSummary[] | null>(null);
  const [err, setErr] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<string[] | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteErr, setDeleteErr] = useState("");

  const load = useCallback(async () => {
    try {
      const [s, j] = await Promise.all([api.stats(), api.jobs()]);
      setStats(s);
      setJobs(j);
      setErr("");
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const deletable = (jobs ?? []).filter((j) => j.status !== "running" && j.status !== "pending");
  const toggle = (id: string) => setSelected((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  async function doDelete() {
    if (!confirm) return;
    setDeleting(true);
    setDeleteErr("");
    const failed: string[] = [];
    for (const id of confirm) {
      try {
        await api.deleteJob(id);
      } catch (e) {
        failed.push(`${id}: ${(e as Error).message}`);
      }
    }
    setSelected((prev) => new Set([...prev].filter((id) => !confirm.includes(id) || failed.some((f) => f.startsWith(id)))));
    setConfirm(null);
    setDeleting(false);
    if (failed.length) setDeleteErr(`Could not delete: ${failed.join("; ")}`);
    await load();
  }

  const severity: Datum[] = SEVERITY.map(([k, l, c]) => ({ key: k, label: l, value: stats?.severity_counts?.[k] ?? 0, color: c }));
  const outcomes: Datum[] = OUTCOMES.map(([k, l, c]) => ({ key: k, label: l, value: stats?.outcomes?.[k] ?? 0, color: c })).filter((d) => d.value > 0 || d.key !== "running");
  const totalSev = severity.reduce((a, d) => a + d.value, 0);
  const pct = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${v}%`);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Global Dashboard</h1>
          <p>Overview of every analysis on this server — all numbers come from real runs, never sample data.</p>
        </div>
        <div className="row">
          <a className="btn primary" href="#/new"><Icon name="plus" /> New analysis</a>
          <button className="btn soft" disabled={refreshing} onClick={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
            <Icon name="refresh" /> {refreshing ? "Refreshing…" : "Refresh data"}
          </button>
        </div>
      </div>

      {err && <div className="alert bad" style={{ marginBottom: 16 }}>Could not load data: {err}</div>}

      <div className="grid grid-4">
        <StatCard label="Projects analyzed" value={stats?.projects_analyzed ?? "—"} sub={`${stats?.jobs_total ?? 0} analyses run`} icon="folder" tone="blue" />
        <StatCard label="Bugs identified" value={stats?.bugs_identified ?? "—"} sub="AI findings, locations verified" icon="bug" tone="violet" />
        <StatCard label="Patches verified" value={stats?.patches_verified ?? "—"} sub="failing test → passing, no regressions" icon="check" tone="green" />
        <StatCard label="Security findings" value={stats?.security_findings ?? "—"} sub={`${stats?.severity_counts?.critical ?? 0} critical · ${stats?.severity_counts?.high ?? 0} high`} icon="shield" tone="red" />
      </div>

      <div className="grid grid-2 section-gap" style={{ alignItems: "stretch" }}>
        <div className="card">
          <div className="card-head"><h2>Security findings by severity</h2><span className="head-icon"><Icon name="chart" size={18} /></span></div>
          {totalSev > 0 ? <BarChart data={severity} caption="Security findings by severity" /> : <div className="chart-empty">No security findings yet.<br />Run a security scan to populate this chart.</div>}
        </div>
        <div className="card">
          <div className="card-head"><h2>Analysis outcomes</h2><span className="head-icon"><Icon name="pie" size={18} /></span></div>
          {(stats?.jobs_total ?? 0) > 0 ? <DonutChart data={outcomes} caption="Analysis outcomes" centerLabel="analyses" /> : <div className="chart-empty">No analyses yet.</div>}
        </div>
      </div>

      <div className="card section-gap">
        <div className="card-head"><h2>Key insights</h2><span className="head-icon"><Icon name="sparkle" size={18} /></span></div>
        <div className="grid grid-3">
          <Insight k="Projects with high-risk findings" v={stats ? `${stats.projects_with_high_risk} / ${stats.projects_analyzed}` : "—"} d="critical or high severity" />
          <Insight k="Highest-risk project" v={stats?.highest_risk_project?.name ?? "None"} d={stats?.highest_risk_project ? `${stats.highest_risk_project.critical_high} critical/high findings` : "no critical/high findings"} danger={!!stats?.highest_risk_project} />
          <Insight k="Critical findings ratio" v={pct(stats?.critical_ratio)} d="of all security findings" />
          <Insight k="Patch verification rate" v={pct(stats?.verification_rate)} d="of repairs that reached verification" />
          <Insight k="Tests executed by PatchPilot" v={String(stats?.tests_executed ?? "—")} d="real runs in the sandbox — never predicted" />
          <Insight k="Avg. findings per scan" v={stats?.avg_findings_per_scan === null || stats?.avg_findings_per_scan === undefined ? "—" : String(stats.avg_findings_per_scan)} d={`Claude spend so far: $${(stats?.llm_cost_usd ?? 0).toFixed(2)} (est.)`} />
        </div>
      </div>

      <div className="card section-gap">
        <div className="card-head">
          <h2>Recent analyses</h2>
          <span className="muted small">{stats?.running ? `${stats.running} running` : ""}</span>
          {selected.size > 0 && (
            <button className="btn small danger" onClick={() => setConfirm([...selected])}><Icon name="trash" size={14} /> Delete selected ({selected.size})</button>
          )}
          <span className="head-icon"><Icon name="list" size={18} /></span>
        </div>
        {deleteErr && <div className="alert bad" style={{ marginBottom: 12 }}>{deleteErr}</div>}
        {jobs && jobs.length === 0 ? (
          <Empty title="No analyses yet" icon="upload">
            <p>Upload a repository ZIP or start from a bundled demo repository.</p>
            <a className="btn primary" href="#/new"><Icon name="plus" /> Start an analysis</a>
          </Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr>
                <th style={{ width: 34 }}>
                  <input type="checkbox" aria-label="Select all finished analyses" checked={deletable.length > 0 && deletable.every((j) => selected.has(j.id))}
                    onChange={(e) => setSelected(e.target.checked ? new Set(deletable.map((j) => j.id)) : new Set())} />
                </th>
                <th>Project</th><th>Type</th><th>Status</th><th>Stage</th><th>Bugs</th><th>Security</th><th>Verification</th><th>Created</th><th />
              </tr></thead>
              <tbody>
                {(jobs ?? []).map((j) => {
                  const running = j.status === "running" || j.status === "pending";
                  return (
                  <tr key={j.id} className={`clickable ${selected.has(j.id) ? "row-selected" : ""}`} onClick={() => (window.location.hash = `#/jobs/${j.id}`)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" aria-label={`Select ${j.project_name}`} disabled={running} checked={selected.has(j.id)} onChange={() => toggle(j.id)} />
                    </td>
                    <td><strong>{j.project_name}</strong><div className="muted mono small">{j.id}</div>{j.llm_mode === "replay" && <span className="badge violet">replay</span>}</td>
                    <td>{ANALYSIS_LABEL[j.analysis_type]}</td>
                    <td><StatusBadge status={j.status} /></td>
                    <td className="muted">{j.current_stage ? label(j.current_stage) : "—"}</td>
                    <td>{j.bugs}</td>
                    <td>{j.security_findings}</td>
                    <td>{j.verification_status ? <StatusBadge status={j.verification_status} /> : <span className="muted">—</span>}</td>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(j.created_at)}</td>
                    <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                      <button className="icon-btn" title={running ? "Wait for this analysis to finish before deleting it" : "Delete this analysis"}
                        aria-label={`Delete ${j.project_name}`} disabled={running} onClick={() => setConfirm([j.id])}>
                        <Icon name="trash" size={16} />
                      </button>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {confirm && (
        <div className="modal-back" onClick={() => !deleting && setConfirm(null)}>
          <div className="modal" style={{ width: "min(480px, 100%)" }} role="alertdialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head"><span style={{ color: "var(--bad)", display: "inline-flex" }}><Icon name="trash" size={18} /></span>
              <h3>Delete {confirm.length === 1 ? "this analysis" : `${confirm.length} analyses`}?</h3></div>
            <div className="modal-body stack" style={{ gap: 10 }}>
              <div>
                {confirm.length === 1
                  ? <><strong>{jobs?.find((j) => j.id === confirm[0])?.project_name}</strong> <span className="mono muted small">{confirm[0]}</span></>
                  : <span>{confirm.map((id) => jobs?.find((j) => j.id === id)?.project_name ?? id).join(", ")}</span>}
              </div>
              <div className="small muted">This permanently removes the results, report, PatchPilot's copy of the code and any replay recording. It cannot be undone. Your original repository (on GitHub or your computer) is not affected.</div>
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <button className="btn" disabled={deleting} onClick={() => setConfirm(null)}>Cancel</button>
                <button className="btn danger-solid" disabled={deleting} onClick={doDelete}><Icon name="trash" size={14} /> {deleting ? "Deleting…" : "Delete permanently"}</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
