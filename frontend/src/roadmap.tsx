import type { AgentRun, Job } from "./types";
import { Icon } from "./ui";
import type { IconName } from "./ui";

/** Live analysis roadmap: the pipeline as one straight line of 8 steps.
 *
 * Everything is derived from the job state the page already polls (agent statuses, results and the
 * activity log). Some steps really run at the same time — the security scan and dependency check
 * run alongside bug detection — so more than one step can show "running" at once. */

export type StepStatus = "pending" | "running" | "done" | "warn" | "skipped" | "blocked" | "failed" | "unavailable";

export interface RoadmapStep {
  key: string; title: string; icon: IconName; status: StepStatus; detail: string; parallel?: boolean; seconds?: number;
}

const FROM_AGENT: Record<string, StepStatus> = {
  pending: "pending", running: "running", completed: "done", skipped: "skipped", blocked: "blocked", failed: "failed", inconclusive: "warn",
};

const secondsBetween = (a?: string, b?: string) => (a && b ? Math.max(0, (Date.parse(b) - Date.parse(a)) / 1000) : undefined);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

function agentStep(a: AgentRun | undefined, finished: boolean): Pick<RoadmapStep, "status" | "seconds"> {
  if (!a) return { status: finished ? "skipped" : "pending" };
  let status = FROM_AGENT[a.status] ?? "pending";
  if (finished && status === "pending") status = "skipped";
  return { status, seconds: secondsBetween(a.started_at, a.finished_at) };
}

export function buildRoadmap(job: Job): RoadmapStep[] {
  const r = job.results;
  const finished = !(job.status === "running" || job.status === "pending");
  const codeFlow = job.analysis_type === "full_analysis" || job.analysis_type === "full_repair" || job.analysis_type === "investigate_only";
  const scanWanted = job.analysis_type === "full_analysis" || job.analysis_type === "security_scan" || job.options.run_security_scan;
  const audit = job.audit ?? [];
  const laneStart = audit.find((e) => e.message.includes("security & malware scan started"));
  const laneEnd = [...audit].reverse().find((e) => e.message.startsWith("[parallel lane]") && e !== laneStart);
  const sec = r.security;

  // 1. Repository upload (the job exists only after a successful upload / GitHub download)
  const facts = r.repo?.facts;
  const source = job.source?.startsWith("github:") ? `GitHub ${job.source.slice(7)}` : "ZIP upload";
  const upload: RoadmapStep = {
    key: "upload", title: "Repository Upload", icon: "upload", status: "done",
    detail: facts ? `${source} · ${plural(facts.indexed_files, "file")} indexed` : `${source} · extracted safely`,
  };

  // 2. Security scan (parallel lane of Agent 5)
  let security: RoadmapStep = { key: "security", title: "Security Scan", icon: "shield", status: "pending", detail: "Waiting to start", parallel: true };
  if (!scanWanted) security = { ...security, status: "skipped", detail: "Turned off for this analysis" };
  else if (sec) {
    const ran = sec.scanners.filter((s) => s.status === "completed").length;
    security = { ...security, status: "done", detail: `${plural(sec.findings.length, "finding")} · ${ran}/${sec.scanners.length} scanners ran`,
                 seconds: secondsBetween(laneStart?.at, laneEnd?.at) };
  } else if (laneStart) security = { ...security, status: finished ? "failed" : "running", detail: finished ? "Did not complete" : "Bandit, Semgrep, secrets, malware rules…" };
  else if (finished) security = { ...security, status: "skipped", detail: "Not run" };

  // 3. Dependency analysis (the OSV lookup inside the security scan)
  let deps: RoadmapStep = { key: "dependencies", title: "Dependency Analysis", icon: "list", status: security.status === "running" ? "running" : "pending",
                            detail: security.status === "running" ? "Checking OSV.dev for known vulnerabilities…" : "Waiting to start", parallel: true };
  if (security.status === "skipped" || security.status === "failed") deps = { ...deps, status: security.status, detail: security.detail };
  const osv = sec?.scanners.find((s) => s.name === "osv");
  if (sec && osv) {
    const n = sec.findings.filter((f) => f.category === "dependency").length;
    if (osv.status === "completed") deps = { ...deps, status: n ? "warn" : "done", detail: n ? `${plural(n, "known vulnerability")} in dependencies` : "No known-vulnerable dependencies" };
    else if (osv.message.startsWith("no dependency manifests")) deps = { ...deps, status: "done", detail: "No third-party dependencies declared" };
    else deps = { ...deps, status: osv.status === "skipped" ? "skipped" : "failed", detail: osv.message || osv.status };
  } else if (sec) deps = { ...deps, status: "skipped", detail: "Not part of this scan" };

  // 4. Bug detection (Agent 2)
  const inv = job.agents.bug_investigation;
  let bugs: RoadmapStep = { key: "bugs", title: "Bug Detection", icon: "bug", ...agentStep(inv, finished), detail: inv?.message || "Waiting to start" };
  if (!codeFlow) bugs = { ...bugs, status: "skipped", detail: "Not part of this analysis type" };
  else if (r.diagnosis) {
    const n = r.diagnosis.findings.length;
    bugs.detail = r.diagnosis.mode === "discovery" ? `Code audit found ${plural(n, "possible bug")}` : `${plural(n, "finding")} for the reported bug`;
  } else if (bugs.status === "running") bugs.detail = "Claude is reading the code…";

  // 5. Attack path analysis — feature not built yet; shown honestly instead of pretending to run.
  const attack: RoadmapStep = { key: "attack", title: "Attack Path Analysis", icon: "alert", status: "unavailable", detail: "Coming soon — not part of this version" };

  // 6. AI repair (Agent 4)
  const rep = job.agents.repair;
  let repair: RoadmapStep = { key: "repair", title: "AI Repair", icon: "wrench", ...agentStep(rep, finished), detail: rep?.message || "Waiting for a proven bug" };
  if (!codeFlow || job.analysis_type === "investigate_only") repair = { ...repair, status: "skipped", detail: "Not part of this analysis type" };
  else if (r.patches.length) {
    const p = r.patches[r.patches.length - 1];
    repair.detail = `${plural(r.patches.length, "patch attempt")} · ${plural(p.files_changed.length, "file")}, +${p.lines_added}/−${p.lines_removed}`;
  } else if (repair.status === "running") repair.detail = "Writing a minimal fix on a copy…";

  // 7. Test execution (Agent 3 reproduction + Agent 5 patch verification)
  const repro = job.agents.reproduction;
  const ver = job.agents.verification;
  const v = r.verification;
  let tests: RoadmapStep = { key: "tests", title: "Test Execution", icon: "beaker", status: "pending", detail: "Waiting to start", seconds: secondsBetween(repro?.started_at, repro?.finished_at) };
  if (!codeFlow) tests = { ...tests, status: "skipped", detail: "Not part of this analysis type" };
  else if (job.execution_backend === "blocked") tests = { ...tests, status: "blocked", detail: "Execution blocked — no sandbox consent" };
  else if (v?.patched_run) {
    const pr = v.patched_run;
    const total = pr.passed + pr.failed + pr.errors;
    tests = { ...tests, status: v.status === "verified" ? "done" : v.status === "failed" ? "failed" : "warn",
              detail: `After patch: ${pr.passed}/${total} passing` + (v.original_bug_status === "fixed" ? " · bug fixed" : "") };
  } else if (repro?.status === "running" || (ver?.status === "running" && r.patches.length > 0 && !v)) tests = { ...tests, status: "running", detail: "Running tests in the sandbox…" };
  else if (r.reproduction?.baseline_run) {
    const b = r.reproduction.baseline_run;
    const reproduced = r.reproduction.status === "reproduced";
    tests = { ...tests, status: reproduced || r.reproduction.status === "not_reproduced" ? "done" : FROM_AGENT[repro?.status ?? "pending"] ?? "warn",
              detail: `Baseline ${b.passed} passed, ${b.failed} failed` + (reproduced ? " · bug reproduced" : "") };
    if (finished && tests.status === "pending") tests.status = "skipped";
  } else if (finished) tests = { ...tests, status: repro?.status === "blocked" ? "blocked" : "skipped", detail: repro?.message || "Not run" };

  // 8. Final security report (Agent 6)
  const fin = job.agents.reporting;
  const report: RoadmapStep = { key: "report", title: "Final Security Report", icon: "file", ...agentStep(fin, finished), detail: fin?.message || "Waiting for the other steps" };
  const rs = r.risk_score;
  if (r.report) report.detail = rs ? `Risk score ${rs.before.score}${rs.after ? ` → ${rs.after.score}` : ""}/100 · report ready` : "Report ready";

  return [upload, security, deps, bugs, attack, repair, tests, report];
}

const STATUS_LABEL: Record<StepStatus, string> = {
  pending: "waiting", running: "running", done: "done", warn: "needs attention", skipped: "skipped", blocked: "blocked", failed: "failed", unavailable: "not available",
};

function StepIcon({ step, n }: { step: RoadmapStep; n: number }) {
  if (step.status === "done") return <Icon name="check" size={16} />;
  if (step.status === "failed" || step.status === "blocked") return <Icon name="x" size={15} />;
  if (step.status === "warn") return <Icon name="alert" size={15} />;
  if (step.status === "running") return <Icon name={step.icon} size={15} />;
  if (step.status === "skipped" || step.status === "unavailable") return <span aria-hidden>–</span>;
  return <span>{n}</span>;
}

export function Roadmap({ job }: { job: Job }) {
  const steps = buildRoadmap(job);
  const applicable = steps.filter((s) => s.status !== "skipped" && s.status !== "unavailable");
  const settled = applicable.filter((s) => !["pending", "running"].includes(s.status)).length;
  const live = job.status === "running" || job.status === "pending";
  const pct = applicable.length ? Math.round((settled / applicable.length) * 100) : 100;
  return (
    <div className="card roadmap-card">
      <div className="card-head" style={{ marginBottom: 10 }}>
        <h2>Analysis roadmap</h2>
        {live ? <span className="live-dot">live</span> : <span className="muted small">finished</span>}
        <span className="spacer" />
        <span className="muted small">{settled}/{applicable.length} steps · {pct}%</span>
      </div>
      <ol className="roadmap" aria-label="Analysis steps">
        {steps.map((s, i) => (
          <li key={s.key} className={`rm-step rm-${s.status}`} aria-label={`${s.title}: ${STATUS_LABEL[s.status]}. ${s.detail}`}>
            <div className="rm-dot"><StepIcon step={s} n={i + 1} /></div>
            <div className="rm-text">
              <div className="rm-title">{s.title}{s.parallel && <span className="lane-tag" title="Runs at the same time as bug detection">⇉ parallel</span>}</div>
              <div className="rm-status">{STATUS_LABEL[s.status]}{s.seconds !== undefined && s.status !== "running" ? ` · ${s.seconds < 1 ? "<1" : Math.round(s.seconds)}s` : ""}</div>
              <div className="rm-detail" title={s.detail}>{s.detail}</div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
