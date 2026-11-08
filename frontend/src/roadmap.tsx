import type { AgentRun, Job } from "./types";
import { Icon } from "./ui";
import type { IconName } from "./ui";

/** Live analysis roadmap: the pipeline as one straight line of 8 steps.
 *
 * Everything is derived from the job state the page already polls (agent statuses, results and the
 * activity log). Some steps really run at the same time — the security scan and dependency check
 * run alongside bug detection — so more than one step can show "running" at once. */

// "found" = the step completed and found real problems; "warn" = it could not fully check something.
export type StepStatus = "pending" | "running" | "done" | "found" | "warn" | "skipped" | "blocked" | "failed" | "unavailable";

export interface RoadmapStep {
  key: string; title: string; icon: IconName; status: StepStatus; detail: string; parallel?: boolean; seconds?: number;
}

const FROM_AGENT: Record<string, StepStatus> = {
  pending: "pending", running: "running", completed: "done", skipped: "skipped", blocked: "blocked", failed: "failed", inconclusive: "warn",
};

const secondsBetween = (a?: string, b?: string) => (a && b ? Math.max(0, (Date.parse(b) - Date.parse(a)) / 1000) : undefined);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

function agentStep(a: AgentRun | undefined, finished: boolean): Pick<RoadmapStep, "status" | "seconds"> {
  if (!a) return { status: finished ? "warn" : "pending" };
  let status = FROM_AGENT[a.status] ?? "pending";
  if (finished && status === "pending") status = "warn";  // the job ended before this step started
  return { status, seconds: secondsBetween(a.started_at, a.finished_at) };
}

export function buildRoadmap(job: Job): RoadmapStep[] {
  const r = job.results;
  const finished = !(job.status === "running" || job.status === "pending");
  const codeFlow = job.analysis_type === "full_analysis" || job.analysis_type === "full_repair" || job.analysis_type === "investigate_only";
  const scanWanted = job.analysis_type === "full_analysis" || job.analysis_type === "security_scan" || job.options.run_security_scan;
  const fixesWanted = (job.analysis_type === "full_analysis" || job.analysis_type === "security_scan") && job.options.auto_remediate !== false;
  // Steps that belong to this analysis type; the others are not shown (instead of "skipped").
  const inScope: Record<string, boolean> = {
    upload: true, security: scanWanted, dependencies: scanWanted, bugs: codeFlow, attack: scanWanted,
    repair: (codeFlow && job.analysis_type !== "investigate_only") || fixesWanted, tests: codeFlow || fixesWanted, report: true,
  };
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
    security = { ...security, status: "done", detail: `${plural(sec.findings.length, "possible problem")} · ${ran} of ${sec.scanners.length} checkers ran`,
                 seconds: secondsBetween(laneStart?.at, laneEnd?.at) };
  } else if (laneStart) security = { ...security, status: finished ? "failed" : "running", detail: finished ? "Did not complete" : "Bandit, Semgrep, secrets, malware rules…" };
  else if (finished) security = { ...security, status: "failed", detail: "Did not run" };

  // 3. Dependency analysis (the OSV lookup inside the security scan)
  let deps: RoadmapStep = { key: "dependencies", title: "Dependency Analysis", icon: "list", status: security.status === "running" ? "running" : "pending",
                            detail: security.status === "running" ? "Checking OSV.dev for known vulnerabilities…" : "Waiting to start", parallel: true };
  if (security.status === "skipped" || security.status === "failed") deps = { ...deps, status: security.status, detail: security.detail };
  const osv = sec?.scanners.find((s) => s.name === "osv");
  if (sec && osv) {
    const n = sec.findings.filter((f) => f.category === "dependency").length;
    if (osv.status === "completed") deps = { ...deps, status: n ? "found" : "done", detail: n ? `${n} known ${n === 1 ? "vulnerability" : "vulnerabilities"} in dependencies` : "No known-vulnerable dependencies" };
    else if (osv.message.startsWith("no dependency manifests")) deps = { ...deps, status: "done", detail: "No third-party packages to check" };
    else deps = { ...deps, status: osv.status === "failed" ? "failed" : "warn", detail: `Not checked: ${osv.message || osv.status}` };
    if (osv.status === "completed") deps.detail += ` · ${osv.message.replace(/^checked /, "checked ")}`;
  } else if (sec) deps = { ...deps, status: "warn", detail: "Not checked in this scan" };

  // 4. Bug detection (Agent 2)
  const inv = job.agents.bug_investigation;
  let bugs: RoadmapStep = { key: "bugs", title: "Bug Detection", icon: "bug", ...agentStep(inv, finished), detail: inv?.message || "Waiting to start" };
  if (!codeFlow) bugs = { ...bugs, status: "skipped", detail: "Not part of this analysis type" };
  else if (r.diagnosis) {
    const n = r.diagnosis.findings.length;
    bugs.detail = r.diagnosis.mode === "discovery" ? `Code audit found ${plural(n, "possible bug")}` : `${plural(n, "possible cause")} found for the reported bug`;
  } else if (bugs.status === "running") bugs.detail = "Claude is reading the code…";

  // 5. Attack path analysis (part of Agent 5's security work, after triage)
  const attackStart = audit.find((e) => e.message.startsWith("attack path analysis started"));
  let attack: RoadmapStep = { key: "attack", title: "Attack Path Analysis", icon: "alert", status: "pending", detail: "Runs after the security scan", parallel: true };
  const ap = sec?.attack_paths;
  if (security.status === "skipped" || security.status === "failed") attack = { ...attack, status: security.status, detail: security.detail };
  else if (ap) {
    const sevOrder = ["critical", "high", "medium", "low", "info"];
    const worst = ap.paths.map((p) => p.severity).sort((a, b) => sevOrder.indexOf(a) - sevOrder.indexOf(b))[0];
    if (ap.status === "completed") {
      attack = { ...attack, status: ap.paths.length ? "found" : "done",
                 detail: ap.paths.length ? `${plural(ap.paths.length, "possible attack path")} · worst: ${worst}` : "No realistic chain found" };
    } else if (ap.status === "not_needed") attack = { ...attack, status: "done", detail: "Fewer than 2 problems — nothing to combine" };
    else attack = { ...attack, status: ap.status.startsWith("failed") ? "failed" : "warn", detail: ap.summary || ap.status };
  } else if (sec) attack = { ...attack, status: "warn", detail: "Not run in this scan" };
  else if (attackStart && !finished) {
    attack = { ...attack, status: "running", detail: "Claude is checking how the problems could be combined…" };
    security = { ...security, status: "done", detail: "Scan complete · results being finalised" };
    if (deps.status === "running") deps = { ...deps, status: "done", detail: "Checked · results being finalised" };
  } else if (finished) attack = { ...attack, status: "failed", detail: "Did not run" };

  // 6. AI repair (Agent 4)
  const rep = job.agents.repair;
  let repair: RoadmapStep = { key: "repair", title: "AI Repair", icon: "wrench", ...agentStep(rep, finished), detail: rep?.message || "Waiting for a proven bug" };
  const rem = r.remediation && r.remediation.status !== "not_needed" ? r.remediation : null;
  const remStarted = audit.some((e) => e.message === "security fixes started");
  const remText = rem ? `security fixes: ${rem.targets.filter((t) => t.outcome === "no_longer_reported").length}/${rem.targets.length} cleared` : "";
  if (r.patches.length) {
    const p = r.patches[r.patches.length - 1];
    repair.detail = `${plural(r.patches.length, "fix attempt")} · ${plural(p.files_changed.length, "file")} changed (+${p.lines_added}/−${p.lines_removed} lines)` + (remText ? ` · ${remText}` : "");
  } else if (rem) repair.detail = remText.charAt(0).toUpperCase() + remText.slice(1);
  else if (repair.status === "running") repair.detail = remStarted ? "Writing fixes for the top security findings…" : "Writing a minimal fix on a copy…";
  if (finished && !r.patches.length && !rem && (repair.status === "skipped" || repair.status === "pending")) {
    const why = r.remediation?.status === "not_needed" ? "no proven bug and no security problem that can be fixed safely and automatically"
      : (rep?.message || "no proven bug to fix").replace(/^security fixes: not needed — /, "");
    repair = { ...repair, status: "done", detail: `Nothing to fix: ${why.charAt(0).toLowerCase()}${why.slice(1)}` };
  }

  // 7. Test execution (Agent 3 reproduction + Agent 5 patch verification)
  const repro = job.agents.reproduction;
  const ver = job.agents.verification;
  const v = r.verification;
  let tests: RoadmapStep = { key: "tests", title: "Test Execution", icon: "beaker", status: "pending", detail: "Waiting to start", seconds: secondsBetween(repro?.started_at, repro?.finished_at) };
  const remTests = rem?.tests_after && rem.tests_after.status === "completed" ? rem.tests_after : null;
  const needsPermission = "Waiting for permission: tick “I trust this repository” so the tests can run in the sandbox";
  if (!codeFlow) {
    tests = remTests
      ? { ...tests, status: rem!.new_failures.length ? "failed" : "done", detail: `Security fixes: ${remTests.passed} of ${remTests.passed + remTests.failed + remTests.errors} tests pass · ${rem!.new_failures.length ? plural(rem!.new_failures.length, "test") + " broken" : "nothing broken"}` }
      : rem ? { ...tests, status: job.execution_backend === "blocked" ? "blocked" : "warn", detail: job.execution_backend === "blocked" ? needsPermission : "The project has no working tests to run on the fixes" }
      : r.remediation?.status === "not_needed" ? { ...tests, status: "done", detail: "Nothing to test: no fixes were needed" }
      : { ...tests, status: finished ? "warn" : "running", detail: finished ? "Tests did not run" : "Re-checking the security fixes…" };
  } else if (job.execution_backend === "blocked") tests = { ...tests, status: "blocked", detail: needsPermission };
  else if (v?.patched_run) {
    const pr = v.patched_run;
    const total = pr.passed + pr.failed + pr.errors;
    tests = { ...tests, status: v.status === "verified" ? "done" : v.status === "failed" ? "failed" : "warn",
              detail: `After the fix: ${pr.passed} of ${total} tests pass` + (v.original_bug_status === "fixed" ? " · bug fixed" : "") };
  } else if (repro?.status === "running" || (ver?.status === "running" && r.patches.length > 0 && !v)) tests = { ...tests, status: "running", detail: "Running tests in the sandbox…" };
  else if (r.reproduction?.baseline_run) {
    const b = r.reproduction.baseline_run;
    const reproduced = r.reproduction.status === "reproduced";
    tests = { ...tests, status: reproduced || r.reproduction.status === "not_reproduced" ? "done" : FROM_AGENT[repro?.status ?? "pending"] ?? "warn",
              detail: `Existing tests: ${b.passed} passed, ${b.failed} failed` + (reproduced ? " · bug proven by a test" : "") };
    if (b.status === "no_tests") tests = { ...tests, status: "done", detail: "The project has no automated tests of its own" + (reproduced ? " · bug proven by PatchPilot's test" : "") };
    if (finished && tests.status === "pending") tests.status = "done";
  } else if (finished) tests = { ...tests, status: repro?.status === "blocked" ? "blocked" : "warn", detail: repro?.status === "blocked" ? needsPermission : (repro?.message || "Tests did not run") };
  if (codeFlow && remTests && tests.status !== "running") tests.detail += ` · security fixes: ${rem!.new_failures.length ? plural(rem!.new_failures.length, "test") + " broken" : "nothing broken"}`;

  // 8. Final security report (Agent 6)
  const fin = job.agents.reporting;
  const report: RoadmapStep = { key: "report", title: "Final Security Report", icon: "file", ...agentStep(fin, finished), detail: fin?.message || "Waiting for the other steps" };
  const rs = r.risk_score;
  const afterText = rs?.after && rs?.after_remediation ? ` → ${rs.after.score} after the bug fix, ${rs.after_remediation.score} after the security fixes`
    : (rs?.after_remediation ?? rs?.after) ? ` → ${(rs!.after_remediation ?? rs!.after)!.score}` : "";
  if (r.report) report.detail = rs ? `Risk score ${rs.before.score}${afterText} (out of 100) · report ready` : "Report ready";

  return [upload, security, deps, bugs, attack, repair, tests, report].filter((step) => inScope[step.key]);
}

const STATUS_LABEL: Record<StepStatus, string> = {
  pending: "waiting", running: "running", done: "done", found: "done · issues found", warn: "needs attention", skipped: "skipped", blocked: "blocked", failed: "failed", unavailable: "not available",
};

function StepIcon({ step, n }: { step: RoadmapStep; n: number }) {
  if (step.status === "done") return <Icon name="check" size={16} />;
  if (step.status === "failed" || step.status === "blocked") return <Icon name="x" size={15} />;
  if (step.status === "warn" || step.status === "found") return <Icon name="alert" size={15} />;
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
