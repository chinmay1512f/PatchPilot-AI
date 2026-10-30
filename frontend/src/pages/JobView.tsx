import { useEffect, useMemo, useState } from "react";
import { api, apiUrl } from "../api";
import type { Job } from "../types";
import { ANALYSIS_LABEL, Badge, Icon, StatusBadge, fmtTime } from "../ui";
import { ActivityTab, BugsTab, OverviewTab, PatchTab, ReportTab, ScopeTab, SecurityTab, TestsTab } from "./JobTabs";

const ORDER = ["repo_understanding", "bug_investigation", "reproduction", "repair", "verification", "reporting"];

export function JobView({ id }: { id: string }) {
  const [job, setJob] = useState<Job | null>(null);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState("overview");

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const load = async () => {
      try {
        const j = await api.job(id);
        if (!alive) return;
        setJob(j);
        setErr("");
        if (j.status === "running" || j.status === "pending") timer = window.setTimeout(load, 1500);
      } catch (e) {
        if (alive) setErr(String((e as Error).message));
      }
    };
    load();
    return () => { alive = false; window.clearTimeout(timer); };
  }, [id]);

  const tabs = useMemo(() => {
    if (!job) return [];
    const r = job.results;
    const t: [string, string, number | null][] = [["overview", "Overview", null]];
    const repairish = job.analysis_type === "full_repair" || job.analysis_type === "investigate_only" || job.analysis_type === "full_analysis";
    if (repairish) {
      t.push(["bugs", "Bugs", r.diagnosis?.findings.length ?? null]);
      t.push(["tests", "Reproduction & tests", null]);
    }
    if (job.analysis_type === "full_repair" || (job.analysis_type === "full_analysis" && repairish)) t.push(["patch", "Patch review", r.patches.length || null]);
    t.push(["security", "Security center", r.security?.findings.length ?? null]);
    if (job.analysis_type === "full_repair" || job.analysis_type === "patch_review" || (job.analysis_type === "full_analysis" && (repairish || job.has_modified_upload))) {
      const n = (r.patch_scope?.findings.length ?? 0) + (r.supplied_patch_scope?.findings.length ?? 0);
      t.push(["scope", "Unnecessary changes", r.patch_scope || r.supplied_patch_scope ? n : null]);
    }
    t.push(["report", "Final report", null]);
    t.push(["activity", "Activity", job.audit.length]);
    return t;
  }, [job]);

  if (err && !job) return <div className="alert bad">{err}</div>;
  if (!job) return <div className="muted">Loading…</div>;

  const running = job.status === "running" || job.status === "pending";
  async function rerun() {
    const j = await api.rerun(job!.id);
    window.location.hash = `#/jobs/${j.id}`;
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 8 }}>
            <a href="#/" className="muted small">Dashboard</a><span className="muted small">/</span>
            <span className="small mono muted">{job.id}</span>
          </div>
          <div className="row" style={{ marginTop: 4 }}>
            <h1>{job.project_name}</h1>
            <StatusBadge status={job.status} />
            <Badge tone="accent">{ANALYSIS_LABEL[job.analysis_type]}</Badge>
          </div>
          <p>
            {job.source?.startsWith("github:") ? <>From <a href={`https://github.com/${job.source.slice(7).split("@")[0]}`} target="_blank" rel="noreferrer noopener" className="mono">GitHub {job.source.slice(7)}</a> · </> : null}
            Started {fmtTime(job.created_at)} · model <span className="mono">{job.model}</span> · sandbox <strong>{job.execution_backend}</strong>
            {job.usage.llm_calls > 0 && <> · {job.usage.llm_calls} Claude calls · {(job.usage.input_tokens + job.usage.output_tokens).toLocaleString()} tokens · est. ${job.usage.estimated_cost_usd.toFixed(3)}</>}
            {!!job.usage.fast_calls && <> · <span className="fast-tag">⚡ fast mode ({job.usage.fast_calls}/{job.usage.llm_calls} calls)</span></>}
          </p>
        </div>
        <div className="row">
          {job.results.report && <a className="btn" href={apiUrl(`/api/jobs/${job.id}/report.md`)}><Icon name="download" size={14} /> Report</a>}
          {!running && <button className="btn" onClick={rerun}><Icon name="refresh" size={14} /> Re-run</button>}
        </div>
      </div>

      {job.llm_mode === "replay" && (
        <div className="alert info" style={{ marginBottom: 12 }}>
          <strong>Replay mode.</strong>&nbsp;Claude's reasoning in this run is replayed from a recording of an earlier real run. Test execution, scanners and verification ran live.
        </div>
      )}
      {job.execution_backend === "blocked" && (job.analysis_type === "full_repair" || job.analysis_type === "investigate_only" || job.analysis_type === "full_analysis") && (
        <div className="alert warn" style={{ marginBottom: 12 }}>
          <span>Code execution was blocked for safety: {job.execution_backend_detail}</span>
        </div>
      )}
      {job.execution_backend === "local" && (job.analysis_type === "full_repair" || job.analysis_type === "investigate_only" || job.analysis_type === "full_analysis") && (
        <div className="alert info" style={{ marginBottom: 12 }}>Tests ran with restricted local execution (user-approved): {job.execution_backend_detail}</div>
      )}
      {job.error && <div className="alert bad" style={{ marginBottom: 12 }}>{job.error}</div>}

      <div className="pipeline">
        {ORDER.map((name, i) => {
          const a = job.agents[name];
          if (!a) return null;
          return (
            <div key={name} className={`stage ${a.status}`}>
              <div className="row" style={{ gap: 6 }}><span className="num">AGENT {i + 1}</span>{a.lane === "parallel" && <span className="lane-tag" title="Ran at the same time as the other agents">⇉ parallel</span>}<span className="spacer" /><StatusBadge status={a.status} /></div>
              <div className="name">{a.title}</div>
              <div className="msg" title={a.message}>{a.message || (a.status === "pending" ? "Waiting" : a.status === "running" ? "Working…" : "")}</div>
              {a.llm_calls > 0 && <div className="tokens">{a.llm_calls} call{a.llm_calls > 1 ? "s" : ""} · {(a.input_tokens + a.output_tokens).toLocaleString()} tok</div>}
            </div>
          );
        })}
      </div>

      <div className="tabs">
        {tabs.map(([key, title, count]) => (
          <button key={key} className={`tab ${tab === key ? "active" : ""}`} onClick={() => setTab(key)}>
            {title}{count !== null && count !== undefined && <span className="count">{count}</span>}
          </button>
        ))}
      </div>

      {tab === "overview" && <OverviewTab job={job} />}
      {tab === "bugs" && <BugsTab job={job} />}
      {tab === "tests" && <TestsTab job={job} />}
      {tab === "patch" && <PatchTab job={job} />}
      {tab === "security" && <SecurityTab job={job} />}
      {tab === "scope" && <ScopeTab job={job} />}
      {tab === "report" && <ReportTab job={job} />}
      {tab === "activity" && <ActivityTab job={job} />}
    </>
  );
}
