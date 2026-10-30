import { useMemo, useState } from "react";
import { apiUrl } from "../api";
import { BarChart } from "../charts";
import type { Job, PatchScopeReport, SecurityFinding, TestRun, VerificationResult } from "../types";
import {
  Badge, ConfidenceBadge, DiffView, Empty, ExcerptView, FileModal, Icon, Markdown, SeverityBadge, Src, StatusBadge, fmtTime, label,
} from "../ui";

type Open = { path: string; hl?: [number, number]; version?: string } | null;

function useFile(jobId: string) {
  const [open, setOpen] = useState<Open>(null);
  const modal = open && <FileModal jobId={jobId} path={open.path} highlight={open.hl} version={open.version} onClose={() => setOpen(null)} />;
  return { setOpen, modal };
}

function Loc({ path, line, end, onOpen }: { path?: string; line?: number | null; end?: number | null; onOpen?: () => void }) {
  if (!path) return null;
  const text = `${path}${line ? `:${line}${end && end !== line ? `-${end}` : ""}` : ""}`;
  return onOpen ? <a className="mono" href="#" onClick={(e) => { e.preventDefault(); onOpen(); }}>{text}</a> : <span className="mono">{text}</span>;
}

function List({ items, empty = "None" }: { items: string[]; empty?: string }) {
  if (!items.length) return <span className="muted">{empty}</span>;
  return <ul style={{ margin: 0, paddingLeft: 18 }}>{items.map((x, i) => <li key={i}>{x}</li>)}</ul>;
}

// --------------------------------------------------------------------------- proof card

function ProofCard({ job }: { job: Job }) {
  const r = job.results;
  const v = r.verification;
  if (!v) return null;
  const patch = r.patches.find((p) => p.id === v.patch_id) ?? r.patches[r.patches.length - 1];
  const before = r.reproduction?.repro_run;
  const after = v.repro_after_patch;
  const b = v.baseline_run;
  const a = v.patched_run;
  const ok = v.status === "verified";
  const bad = v.status === "failed";
  const title = ok ? "Bug fixed — patch verified" : bad ? "Patch did not pass verification" : `Verification ${label(v.status)}`;
  return (
    <div className={`card proof ${ok ? "" : bad ? "failed" : "neutral"}`}>
      <div className="proof-head">
        <div className="proof-icon"><Icon name={ok ? "check" : bad ? "x" : "alert"} size={24} /></div>
        <div style={{ flex: 1 }}>
          <div className="row"><h2 style={{ fontSize: 19 }}>{title}</h2><Src kind="tool" /></div>
          <div className="muted" style={{ marginTop: 2 }}>{v.reasons[0] ?? ""}{ok && " Verified against the configured checks — not a claim that the code is bug-free."}</div>
        </div>
        {patch && <a className="btn" href={apiUrl(`/api/jobs/${job.id}/patch.diff?attempt=${patch.attempt}`)}><Icon name="download" size={14} /> Download patch</a>}
      </div>
      <div className="proof-metrics">
        <div className="proof-metric">
          <div className="k">Reproduction test</div>
          <div className="v">{before ? <span className="pill-fail">{before.failed} failing</span> : "—"}<span className="arrow">→</span>{after ? <span className={after.failed ? "pill-fail" : "pill-pass"}>{after.failed ? `${after.failed} failing` : `${after.passed} passing`}</span> : "—"}</div>
        </div>
        <div className="proof-metric">
          <div className="k">Full test suite</div>
          <div className="v">{b ? `${b.passed}/${b.passed + b.failed + b.errors}` : "—"}<span className="arrow">→</span>{a ? <span className={a.failed + a.errors ? "pill-fail" : "pill-pass"}>{a.passed}/{a.passed + a.failed + a.errors}</span> : "—"}</div>
        </div>
        <div className="proof-metric">
          <div className="k">Regressions</div>
          <div className="v"><span className={v.new_failures.length ? "pill-fail" : "pill-pass"}>{v.new_failures.length}</span></div>
        </div>
        <div className="proof-metric">
          <div className="k">Patch size</div>
          <div className="v">{patch ? <><span className="pill-pass">+{patch.lines_added}</span><span className="pill-fail">−{patch.lines_removed}</span><span className="muted small" style={{ fontWeight: 500 }}>{patch.files_changed.length} file{patch.files_changed.length === 1 ? "" : "s"}{r.patches.length > 1 ? ` · attempt ${patch.attempt}` : ""}</span></> : "—"}</div>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- overview

export function OverviewTab({ job }: { job: Job }) {
  const r = job.results;
  const { setOpen, modal } = useFile(job.id);
  const facts = r.repo?.facts;
  const n = r.repo?.narrative;
  const v = r.verification;
  return (
    <div className="stack">
      {modal}
      <ProofCard job={job} />
      <MalwareCard job={job} compact />
      {r.report && (
        <div className="card">
          <div className="card-head"><h2>{r.report.headline}</h2><StatusBadge status={r.report.overall_status} /></div>
          {r.report.narrative ? (
            <div className="stack" style={{ gap: 8 }}>
              <div className="row"><Src kind="model" /><span className="muted small">Executive summary written from the evidence below</span></div>
              <div>{r.report.narrative.executive_summary}</div>
              {r.report.narrative.recommended_next_actions.length > 0 && <><strong className="small">Recommended next actions</strong><List items={r.report.narrative.recommended_next_actions} /></>}
            </div>
          ) : <div className="muted small">AI summary not available ({r.report.narrative_status}). All findings below are still shown.</div>}
        </div>
      )}
      {v && (
        <div className="card">
          <div className="card-head"><h2>Verification</h2><Src kind="tool" /><StatusBadge status={v.status} /></div>
          <div className="kv">
            <div>Original bug</div><div><StatusBadge status={v.original_bug_status} /></div>
            <div>Reasons</div><div><List items={v.reasons} /></div>
            {v.repro_after_patch && <><div>Reproduction test</div><div>{v.repro_after_patch.passed} passed · {v.repro_after_patch.failed} failed after patch</div></>}
            {v.patched_run && <><div>Full suite after patch</div><div>{v.patched_run.passed} passed · {v.patched_run.failed} failed · {v.patched_run.errors} errors · {v.new_failures.length} regressions</div></>}
          </div>
        </div>
      )}
      {facts && (
        <div className="grid grid-2" style={{ alignItems: "start" }}>
          <div className="card">
            <div className="card-head"><h2>Repository facts</h2><Src kind="tool" /></div>
            <div className="kv">
              <div>Files indexed</div><div>{facts.indexed_files} of {facts.total_files} · {facts.total_lines.toLocaleString()} lines</div>
              <div>Languages</div><div className="chips">{facts.languages.slice(0, 6).map((l) => <Badge key={l.language} tone="outline">{l.language} · {l.files}</Badge>)}</div>
              <div>Frameworks</div><div>{facts.frameworks.join(", ") || <span className="muted">none detected</span>}</div>
              <div>Tests</div><div>{facts.test_framework ?? "none"} · {facts.test_files.length} test files</div>
              <div>Dependencies</div><div>{facts.dependencies.length} declared ({facts.dependencies.filter((d) => d.pinned).length} pinned) in {facts.manifests.join(", ") || "—"}</div>
              <div>Entry points</div><div className="mono small">{facts.candidate_entry_points.join(", ") || "—"}</div>
              <div>Env variables</div><div className="mono small">{facts.env_var_references.slice(0, 12).join(", ") || "—"}</div>
              <div>Secrets redacted</div><div>{facts.secrets_redacted} value(s) masked before AI analysis</div>
              <div>Not installed in sandbox</div><div className="mono small">{facts.missing_imports?.length ? facts.missing_imports.join(", ") : "—"}{facts.missing_imports?.length ? <div className="muted" style={{ fontFamily: "var(--sans)" }}>Dependencies are never installed; these are stubbed during tests.</div> : null}</div>
            </div>
            {facts.special_files.length > 0 && (
              <>
                <div className="divider" />
                <strong className="small">Files needing special handling</strong>
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>{facts.special_files.map((s, i) => <li key={i} className="small"><span className="mono">{s.path}</span> — {s.reason}</li>)}</ul>
              </>
            )}
          </div>
          <div className="card">
            <div className="card-head"><h2>Repository understanding</h2><Src kind="model" /><StatusBadge status={r.repo?.narrative_status} /></div>
            {n ? (
              <div className="stack" style={{ gap: 10 }}>
                <div>{n.overview}</div>
                <div className="muted">{n.architecture}</div>
                <div><strong className="small">Important files</strong>
                  <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>{n.important_files.map((f) => <li key={f.path} className="small"><Loc path={f.path} onOpen={() => setOpen({ path: f.path })} /> — {f.role}</li>)}</ul>
                </div>
                {n.initial_security_observations.length > 0 && <div><strong className="small">Initial security observations</strong><List items={n.initial_security_observations} /></div>}
                {n.missing_information.length > 0 && <div><strong className="small">Missing information</strong><List items={n.missing_information} /></div>}
              </div>
            ) : <div className="muted">Not available.</div>}
            {r.repo && r.repo.limitations.length > 0 && <><div className="divider" /><strong className="small">Limitations</strong><List items={r.repo.limitations} /></>}
          </div>
        </div>
      )}
      {job.bug_description && (
        <div className="card"><div className="card-head"><h3>Reported problem</h3><Badge tone="outline">user input · treated as untrusted</Badge></div><pre className="block">{job.bug_description}</pre></div>
      )}
      {!job.bug_description && r.diagnosis?.mode === "discovery" && r.diagnosis.discovered_issue && (
        <div className="card"><div className="card-head"><h3>Bug selected for reproduction & repair</h3><Src kind="model" /><Badge tone="violet">found by code audit</Badge></div><pre className="block">{r.diagnosis.discovered_issue}</pre></div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- bugs

export function BugsTab({ job }: { job: Job }) {
  const d = job.results.diagnosis;
  const { setOpen, modal } = useFile(job.id);
  if (!d) return <Empty title="No diagnosis">{job.agents.bug_investigation?.message}</Empty>;
  return (
    <div className="stack">
      {modal}
      <div className="card">
        <div className="card-head"><h2>{d.mode === "discovery" ? "Bugs found by the code audit" : "Diagnosis"}</h2><Src kind="model" />
          {d.mode === "discovery" && <Badge tone="violet">autonomous discovery · no bug report</Badge>}
          {d.findings.length === 0 ? <Badge tone="ok">no defect found</Badge> : d.conclusive ? <Badge tone="ok">{d.mode === "discovery" ? "primary defect verified" : "root cause established"}</Badge> : <Badge tone="warn">inconclusive</Badge>}</div>
        {d.mode === "discovery" && <div className="alert info" style={{ marginBottom: 10 }}>No bug report was given, so Claude audited the code itself. Each finding below is a hypothesis; the primary one is only patched if a generated test first fails on the original code.</div>}
        <div>{d.summary}</div>
        <div className="muted small" style={{ marginTop: 8 }}>Claude made {d.tool_calls} read-only tool calls and read {d.files_read.length} file(s): <span className="mono">{d.files_read.join(", ")}</span>. Every cited location below was checked against the real files by PatchPilot.</div>
        {d.alternative_hypotheses.length > 0 && <><div className="divider" /><strong className="small">Alternative hypotheses considered</strong><List items={d.alternative_hypotheses} /></>}
      </div>
      {d.findings.map((f) => (
        <div key={f.id} className={`finding sev-${f.severity}`}>
          <div className="row">
            <span className="title">{f.title}</span>
            {f.id === d.primary_finding_id && <Badge tone="accent">primary</Badge>}
            <span className="spacer" />
            <StatusBadge status={f.status === "confirmed" ? "completed" : f.status === "suspected" ? "inconclusive" : "failed"} />
            <Badge tone={f.status === "confirmed" ? "ok" : f.status === "suspected" ? "warn" : "bad"}>{label(f.status)}</Badge>
            <SeverityBadge severity={f.severity} /><ConfidenceBadge confidence={f.confidence} />
          </div>
          <dl>
            <dt>Location</dt>
            <dd><Loc path={f.file_path} line={f.line_start} end={f.line_end} onOpen={f.location_verified ? () => setOpen({ path: f.file_path, hl: [f.line_start, f.line_end] }) : undefined} />
              {f.function_name && <span className="muted"> in <span className="mono">{f.function_name}</span></span>}{" "}
              {f.location_verified ? <Badge tone="ok">location verified</Badge> : <Badge tone="bad">location not found</Badge>}</dd>
            <dt>Description</dt><dd>{f.description}</dd>
            <dt>Root cause</dt><dd>{f.root_cause_hypothesis}</dd>
            <dt>Evidence</dt><dd><List items={f.evidence} /></dd>
            <dt>Reproduction</dt><dd>{f.reproduction_strategy}</dd>
            <dt>Next step</dt><dd>{f.recommended_next_step}</dd>
            {f.validation_notes.length > 0 && <><dt>Validation <Src kind="tool" /></dt><dd><List items={f.validation_notes} /></dd></>}
          </dl>
          {f.code_excerpt && <ExcerptView text={f.code_excerpt} highlight={[f.line_start, f.line_end]} />}
        </div>
      ))}
    </div>
  );
}

// --------------------------------------------------------------------------- tests

type RunKind = "baseline" | "repro-before" | "repro-after";

/** Plain-language "what does this result mean?" line for each kind of test run. */
function RunMeaning({ run, kind }: { run: TestRun; kind?: RunKind }) {
  if (!kind || run.status === "blocked") return null;
  const broken = run.errors > 0;
  if (kind === "repro-before") {
    if (run.failed > 0) {
      return <div className="alert ok" style={{ marginBottom: 10 }}><span><strong>Bug proven.</strong> These are PatchPilot's new tests, run on your <em>unchanged</em> code. They describe how the code <em>should</em> behave, so {run.failed === 1 ? "this failure is" : `these ${run.failed} failures are`} expected — {run.failed === 1 ? "it shows" : "they show"} the bug really exists.{run.passed > 0 && ` The ${run.passed} passing test${run.passed === 1 ? "" : "s"} check${run.passed === 1 ? "s" : ""} nearby cases that already work.`}</span></div>;
    }
    return <div className="alert warn" style={{ marginBottom: 10 }}><span><strong>Bug not proven.</strong> {broken ? "The new test could not run (see the error below), so it could not show the bug." : "Every new test passed on the unchanged code, so they did not show the bug. PatchPilot will not patch a bug it cannot prove."}</span></div>;
  }
  if (kind === "repro-after") {
    return run.failed || run.errors
      ? <div className="alert bad" style={{ marginBottom: 10 }}><span><strong>The fix did not work yet.</strong> Some of the bug's tests still fail after the patch.</span></div>
      : <div className="alert ok" style={{ marginBottom: 10 }}><span><strong>Fix confirmed.</strong> The same tests that failed before the patch now all pass.</span></div>;
  }
  return (
    <div className="alert info" style={{ marginBottom: 10 }}>
      <span>This is <strong>your repository's own test suite</strong>, run on the unchanged code before PatchPilot changes anything. It is the "before" picture used to spot regressions.
        {broken && ` ${run.errors === 1 ? "1 test file" : `${run.errors} test files`} could not even load (reason below) — that was already broken, not caused by PatchPilot.`}
        {!broken && run.passed + run.failed === 0 && " No tests were found."}</span>
    </div>
  );
}

export function TestRunCard({ run, title, kind }: { run: TestRun; title: string; kind?: RunKind }) {
  const [showOut, setShowOut] = useState(false);
  return (
    <div className="card">
      <div className="card-head">
        <h3>{title}</h3><Src kind="tool" /><StatusBadge status={run.status} />
      </div>
      {run.status === "blocked" ? <div className="alert warn">{run.blocked_reason}</div> : (
        <>
          <RunMeaning run={run} kind={kind} />
          <div className="row small" style={{ marginBottom: 8 }}>
            <Badge tone="ok">{run.passed} passed</Badge><Badge tone={run.failed ? "bad" : "neutral"}>{run.failed} failed</Badge>
            <Badge tone={run.errors ? "bad" : "neutral"}>{run.errors} errors</Badge><Badge>{run.skipped} skipped</Badge>
            <span className="muted">exit {run.exit_code ?? "—"} · {run.duration_seconds}s · {run.backend}</span>
          </div>
          <div className="mono small muted" style={{ marginBottom: 8 }}>$ {run.command}</div>
          {!!run.stubbed_modules?.length && (
            <div className="alert info" style={{ marginBottom: 8 }}>
              <span>Not installed in the sandbox, replaced by inert stand-ins: <span className="mono">{run.stubbed_modules.join(", ")}</span>. These results cover the repository's own logic, not those libraries.</span>
            </div>
          )}
          {run.tests.length > 0 && (
            <div className="table-wrap"><table><tbody>
              {run.tests.map((t) => (
                <tr key={t.nodeid}><td style={{ width: 90 }}><Badge tone={t.outcome === "passed" ? "ok" : t.outcome === "skipped" ? "neutral" : "bad"}>{t.outcome}</Badge></td>
                  <td className="mono small">{t.nodeid}{t.message && <div className="muted" style={{ whiteSpace: "pre-wrap", marginTop: 4 }}>{t.message.split("\n")[0].slice(0, 240)}</div>}</td></tr>
              ))}
            </tbody></table></div>
          )}
          {run.output_tail && <><button className="btn small" style={{ marginTop: 8 }} onClick={() => setShowOut(!showOut)}>{showOut ? "Hide" : "Show"} raw output</button>
            {showOut && <pre className="block" style={{ marginTop: 8 }}>{run.output_tail}</pre>}</>}
        </>
      )}
    </div>
  );
}

export function TestsTab({ job }: { job: Job }) {
  const rp = job.results.reproduction;
  if (!rp) return <Empty title="No test results">{job.agents.reproduction?.message}</Empty>;
  return (
    <div className="stack">
      <div className="card">
        <div className="card-head"><h2>Bug reproduction</h2><StatusBadge status={rp.status} /></div>
        <div className="muted">To prove a bug is real, PatchPilot writes new tests describing the <em>correct</em> behaviour and runs them on your unchanged code. If they fail, the bug is proven; only then is it fixed. ({rp.attempts} attempt{rp.attempts === 1 ? "" : "s"})</div>
        {rp.notes.length > 0 && <div style={{ marginTop: 8 }}><List items={rp.notes} /></div>}
      </div>
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        {rp.baseline_run && <TestRunCard run={rp.baseline_run} title="Your existing tests (before any change)" kind="baseline" />}
        {rp.repro_run && <TestRunCard run={rp.repro_run} title="New bug tests on the original code" kind="repro-before" />}
      </div>
      {rp.test_code && (
        <div className="card">
          <div className="card-head"><h3>Generated test <span className="mono muted small">{rp.test_path}</span></h3><Src kind="model" /></div>
          <div className="small muted" style={{ marginBottom: 8 }}>{rp.rationale} The code below was written by Claude and vetted by policy (no network, subprocess, env access); its results above come from actual execution.</div>
          {rp.edge_cases.length > 0 && <div className="chips" style={{ marginBottom: 8 }}>{rp.edge_cases.map((e) => <Badge key={e} tone="outline">{e}</Badge>)}</div>}
          <pre className="block">{rp.test_code}</pre>
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- patch

function VerificationCard({ v }: { v: VerificationResult }) {
  return (
    <div className="card">
      <div className="card-head"><h3>Verification of this patch</h3><Src kind="tool" /><StatusBadge status={v.status} /></div>
      <div className="kv">
        <div>Original bug</div><div><StatusBadge status={v.original_bug_status} /></div>
        <div>Reasons</div><div><List items={v.reasons} /></div>
        <div>Before → after</div>
        <div>{v.baseline_run ? `${v.baseline_run.passed} passed / ${v.baseline_run.failed} failed` : "—"} → {v.patched_run ? `${v.patched_run.passed} passed / ${v.patched_run.failed} failed / ${v.patched_run.errors} errors` : "—"} <span className="muted small">(after includes the reproduction test)</span></div>
        <div>Regressions</div><div>{v.new_failures.length ? <List items={v.new_failures} /> : <Badge tone="ok">none</Badge>}</div>
        {v.fixed_tests.length > 0 && <><div>Newly passing</div><div><List items={v.fixed_tests} /></div></>}
        <div>Syntax errors</div><div>{v.syntax_errors.length ? <List items={v.syntax_errors} /> : <Badge tone="ok">none</Badge>}</div>
        <div>New lint issues</div><div>{v.new_lint_issues.length ? <List items={v.new_lint_issues} /> : <Badge tone="ok">none</Badge>}</div>
        <div>Dependency changes</div><div>{v.dependency_changes.length ? <List items={v.dependency_changes} /> : <Badge tone="ok">none</Badge>}</div>
        <div>Patch security</div><div>{v.patch_security_findings.length ? <List items={v.patch_security_findings.map((f) => `${f.severity}: ${f.title} (${f.file_path}:${f.line})`)} /> : <Badge tone="ok">no new findings in changed files</Badge>}</div>
        <div>Checks performed</div><div><List items={v.checks_performed} /></div>
        <div>Not performed</div><div className="muted"><List items={v.checks_not_performed} /></div>
      </div>
      {v.interpretation && (
        <><div className="divider" /><div className="row" style={{ marginBottom: 6 }}><Src kind="model" /><strong className="small">Interpretation</strong></div>
          <div>{v.interpretation.assessment}</div>
          {v.interpretation.reviewer_notes.length > 0 && <div style={{ marginTop: 6 }}><List items={v.interpretation.reviewer_notes} /></div>}</>
      )}
      {v.repro_after_patch && <div style={{ marginTop: 12 }}><TestRunCard run={v.repro_after_patch} title="Same bug tests after the patch" kind="repro-after" /></div>}
    </div>
  );
}

export function PatchTab({ job }: { job: Job }) {
  const patches = [...job.results.patches].reverse();
  if (!patches.length) return <Empty title="No patch proposed">{job.agents.repair?.message}</Empty>;
  return (
    <div className="stack">
      <div className="alert info">Patches are applied only to disposable copies. Your original repository is never modified — download the diff and apply it yourself (<span className="mono">git apply patchpilot.diff</span>) after review.</div>
      {patches.map((p, idx) => {
        const v = job.results.verification_history.find((x) => x.patch_id === p.id);
        return (
          <div key={p.id} className="stack" style={{ opacity: idx === 0 ? 1 : 0.85 }}>
            <div className="card">
              <div className="card-head">
                <h2>Attempt {p.attempt}{idx === 0 && patches.length > 1 ? " (latest)" : ""}</h2><Src kind="model" />
                {v && <StatusBadge status={v.status} />}
                <a className="btn small" href={apiUrl(`/api/jobs/${job.id}/patch.diff?attempt=${p.attempt}`)}><Icon name="download" size={14} /> .diff</a>
              </div>
              <div>{p.summary}</div>
              <div className="row small" style={{ margin: "10px 0" }}>
                <Badge tone="outline">{p.files_changed.length} file(s)</Badge><Badge tone="ok">+{p.lines_added}</Badge><Badge tone="bad">−{p.lines_removed}</Badge>
                <span className="mono muted">{p.files_changed.join(", ")}</span>
              </div>
              {p.apply_errors.length > 0 && <div className="alert bad" style={{ marginBottom: 10 }}><div><strong>Could not apply:</strong><List items={p.apply_errors} /></div></div>}
              <div className="kv" style={{ marginBottom: 12 }}>
                <div>Intended behaviour</div><div>{p.intended_behaviour}</div>
                <div>Why minimal</div><div>{p.why_minimal}</div>
                <div>Edits</div><div><List items={p.edits.map((e) => `${e.file_path}: ${e.explanation}`)} /></div>
                {p.risk_notes.length > 0 && <><div>Risk notes</div><div><List items={p.risk_notes} /></div></>}
              </div>
              <div className="row" style={{ marginBottom: 6 }}><Src kind="tool" /><span className="small muted">Diff computed from the files on disk (not from model output)</span></div>
              <DiffView diff={p.diff} />
            </div>
            {v && <VerificationCard v={v} />}
          </div>
        );
      })}
    </div>
  );
}

// --------------------------------------------------------------------------- malware check

const MALWARE_VERDICT = {
  no_malicious_indicators: { cls: "", icon: "shield" as const, title: "No malicious indicators found", note: "None of the malware checks raised a concern. This is not a guarantee the code is safe." },
  suspicious_needs_review: { cls: "neutral", icon: "alert" as const, title: "Suspicious — needs human review", note: "Some code behaves in ways malware often does. Read the items below before running this code." },
  likely_malicious: { cls: "failed", icon: "x" as const, title: "Likely malicious", note: "Do not run this code. Review the evidence below and remove or report it." },
};
const ITEM_TONE = { benign: "ok", suspicious: "warn", likely_malicious: "bad" } as const;

export function MalwareCard({ job, compact }: { job: Job; compact?: boolean }) {
  const m = job.results.security?.malware;
  const [showAll, setShowAll] = useState(false);
  const { setOpen, modal } = useFile(job.id);
  if (!m) return null;
  const v = MALWARE_VERDICT[m.overall];
  const byId = Object.fromEntries((job.results.security?.findings ?? []).map((f) => [f.id, f]));
  const matched = new Set(m.indicators_matched);
  const version = job.analysis_type === "patch_review" ? "modified" : "original";
  return (
    <div className={`card proof ${v.cls}`}>
      {modal}
      <div className="proof-head">
        <div className="proof-icon"><Icon name={v.icon} size={22} /></div>
        <div style={{ flex: 1 }}>
          <div className="row"><h2 style={{ fontSize: 18 }}>Malware check: {v.title}</h2><Src kind={m.ai_status === "completed" ? "mixed" : "tool"} /></div>
          <div className="muted" style={{ marginTop: 2 }}>{v.note}</div>
        </div>
      </div>
      <div style={{ marginTop: 12 }}>{m.summary}</div>
      {!compact && (
        <>
          {m.items.length > 0 && (
            <div className="stack" style={{ gap: 8, marginTop: 14 }}>
              <strong className="small">What was found <Src kind="model" /></strong>
              {m.items.map((it) => {
                const f = byId[it.finding_id];
                return (
                  <div key={it.finding_id} className="subtle" style={{ background: "#fff" }}>
                    <div className="row" style={{ marginBottom: 4 }}>
                      <Badge tone={ITEM_TONE[it.verdict]}>{label(it.verdict)}</Badge>
                      <strong className="small">{f?.title ?? it.finding_id}</strong>
                      {f?.file_path && <Loc path={f.file_path} line={f.line} onOpen={() => setOpen({ path: f.file_path!, hl: f.line ? [f.line, f.line] : undefined, version })} />}
                    </div>
                    <div className="small">{it.explanation}</div>
                  </div>
                );
              })}
            </div>
          )}
          {m.recommended_actions.length > 0 && <div style={{ marginTop: 12 }}><strong className="small">Next steps</strong><List items={m.recommended_actions} /></div>}
          <div className="divider" />
          <div className="row small" style={{ marginBottom: 6 }}>
            <strong>Checked for {m.indicators_checked.length} kinds of malicious behaviour</strong>
            <span className="muted">· antivirus signatures: {m.signature_scan}</span>
            <span className="spacer" />
            <button className="btn small" onClick={() => setShowAll(!showAll)}>{showAll ? "Hide list" : "Show list"}</button>
          </div>
          {showAll && (
            <div className="chips">
              {m.indicators_checked.map((c) => <Badge key={c} tone={matched.has(c) ? "warn" : "ok"}>{matched.has(c) ? "⚠ " : "✓ "}{c}</Badge>)}
            </div>
          )}
          {m.limitations.length > 0 && <div className="small muted" style={{ marginTop: 10 }}>{m.limitations.join(" ")}</div>}
        </>
      )}
      {compact && m.indicators_matched.length > 0 && <div className="chips" style={{ marginTop: 10 }}>{m.indicators_matched.map((c) => <Badge key={c} tone="warn">⚠ {c}</Badge>)}</div>}
    </div>
  );
}

// --------------------------------------------------------------------------- security

const CAT_LABEL: Record<string, string> = {
  static_analysis: "Static analysis", dependency: "Dependencies", secret: "Secrets", suspicious_code: "Suspicious code", patch_security: "Patch security", lint: "Lint",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR: Record<string, string> = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)" };

function FindingCard({ f, onOpen }: { f: SecurityFinding; onOpen: () => void }) {
  return (
    <div className={`finding sev-${f.severity}`}>
      <div className="row">
        <span className="title">{f.title}</span>
        {f.introduced_by_patch && <Badge tone="bad">introduced by patch</Badge>}
        <span className="spacer" />
        <SeverityBadge severity={f.severity} /><ConfidenceBadge confidence={f.confidence} />
        <Badge tone="outline">{f.scanner} · {f.rule_id}</Badge>
      </div>
      <div className="row small"><Src kind="tool" /><Loc path={f.file_path} line={f.line} onOpen={f.file_path && f.category !== "dependency" ? onOpen : undefined} /></div>
      <div>{f.description}</div>
      {f.snippet && <pre className="block mono">{f.snippet}</pre>}
      {f.category === "suspicious_code" && <div className="small muted">Pattern match only — this is not a confirmed malware detection. Review the context to judge intent.</div>}
      {f.references.length > 0 && <div className="small muted">{f.references.map((r, i) => r.startsWith("http") ? <a key={i} href={r} target="_blank" rel="noreferrer noopener" style={{ marginRight: 10 }}>{r.replace(/^https?:\/\//, "").slice(0, 60)}</a> : <span key={i} style={{ marginRight: 10 }}>{r}</span>)}</div>}
      {f.ai_assessment && (
        <div className="subtle">
          <div className="row" style={{ marginBottom: 4 }}><Src kind="model" /><Badge tone={f.ai_assessment.verdict === "likely_true_positive" ? "bad" : f.ai_assessment.verdict === "likely_false_positive" ? "ok" : "warn"}>{label(f.ai_assessment.verdict)}</Badge><Badge tone="outline">priority: {f.ai_assessment.priority}</Badge></div>
          <div className="small">{f.ai_assessment.rationale}</div>
        </div>
      )}
    </div>
  );
}

export function SecurityTab({ job }: { job: Job }) {
  const s = job.results.security;
  const { setOpen, modal } = useFile(job.id);
  const [cat, setCat] = useState("all");
  const [sev, setSev] = useState("all");
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    s?.findings.forEach((f) => { c[f.severity] = (c[f.severity] ?? 0) + 1; });
    return c;
  }, [s]);
  if (!s) return <Empty title="No security scan">{job.options.run_security_scan ? job.agents.verification?.message : "Security scanning was disabled for this analysis."}</Empty>;
  const cats = Array.from(new Set(s.findings.map((f) => f.category)));
  const shown = s.findings.filter((f) => (cat === "all" || f.category === cat) && (sev === "all" || f.severity === sev));
  const version = job.analysis_type === "patch_review" ? "modified" : "original";
  return (
    <div className="stack">
      {modal}
      <MalwareCard job={job} />
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card">
          <div className="card-head"><h2>Scanners</h2><Src kind="tool" /></div>
          <div className="table-wrap"><table>
            <thead><tr><th>Scanner</th><th>Version</th><th>Status</th><th>Findings</th><th>Note</th></tr></thead>
            <tbody>{s.scanners.map((x) => (
              <tr key={x.name}><td><strong>{x.name}</strong></td><td className="mono small muted">{x.version ?? "—"}</td><td><StatusBadge status={x.status} /></td><td>{x.findings}</td><td className="small muted">{x.message}</td></tr>
            ))}</tbody>
          </table></div>
        </div>
        <div className="card">
          <div className="card-head"><h2>{s.findings.length} findings</h2></div>
          <BarChart data={SEV_ORDER.map((k) => ({ key: k, label: k[0].toUpperCase() + k.slice(1), value: counts[k] ?? 0, color: SEV_COLOR[k] }))} caption="Findings by severity" />
          <div className="divider" />
          <div className="row" style={{ marginBottom: 6 }}><Src kind="model" /><strong className="small">AI triage</strong><StatusBadge status={s.triage_status} /></div>
          <div className="small muted">{s.triage_summary || "—"}</div>
          <div className="divider" />
          <div className="small muted">No findings does not mean the code is secure — only that the configured scanners found nothing.</div>
        </div>
      </div>
      <div className="row">
        <select value={cat} onChange={(e) => setCat(e.target.value)} style={{ width: "auto" }}>
          <option value="all">All categories</option>{cats.map((c) => <option key={c} value={c}>{CAT_LABEL[c] ?? c}</option>)}
        </select>
        <select value={sev} onChange={(e) => setSev(e.target.value)} style={{ width: "auto" }}>
          <option value="all">All severities</option>{SEV_ORDER.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <span className="muted small">{shown.length} shown</span>
      </div>
      {shown.map((f) => <FindingCard key={f.id} f={f} onOpen={() => f.file_path && setOpen({ path: f.file_path, hl: f.line ? [f.line, f.line] : undefined, version })} />)}
      {shown.length === 0 && <Empty title="No findings match these filters" />}
    </div>
  );
}

// --------------------------------------------------------------------------- patch scope

export function ScopeTab({ job }: { job: Job }) {
  const reports = [job.results.patch_scope, job.results.supplied_patch_scope].filter((x): x is PatchScopeReport => !!x);
  if (!reports.length) {
    return <Empty title="No patch-scope analysis">{job.analysis_type === "patch_review" ? job.agents.verification?.message
      : "Runs after PatchPilot verifies a patch, or when you supply a modified version of the repository."}</Empty>;
  }
  return <div className="stack">{reports.map((ps) => <ScopeReportView key={ps.subject} job={job} ps={ps} />)}</div>;
}

function ScopeReportView({ job, ps }: { job: Job; ps: PatchScopeReport }) {
  const { setOpen, modal } = useFile(job.id);
  const m = ps.metrics;
  const tone = ps.overall_assessment === "appears_minimal" ? "ok" : ps.overall_assessment === "likely_excessive" ? "bad" : "warn";
  return (
    <div className="stack">
      {modal}
      <div className="alert info"><strong>Detection & reporting only.</strong>&nbsp;PatchPilot never rewrites or simplifies the patch — you decide whether a smaller correction is appropriate.</div>
      <div className="card">
        <div className="card-head"><h2>{ps.subject === "patchpilot_patch" ? "PatchPilot's own patch" : "Your supplied patch"}</h2><Src kind="mixed" /><Badge tone={tone}>{label(ps.overall_assessment)}</Badge></div>
        <div>{ps.summary}</div>
        <div className="grid grid-4" style={{ marginTop: 14 }}>
          {[["Files changed", m.files_changed], ["Lines", `+${m.lines_added} / −${m.lines_removed}`], ["Functions changed", m.functions_changed], ["Formatting-only hunks", m.formatting_only_hunks]].map(([k, val]) => (
            <div key={String(k)} className="subtle stat"><span className="label">{k}</span><span className="value" style={{ fontSize: 20 }}>{val}</span></div>
          ))}
        </div>
      </div>
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card">
          <div className="card-head"><h3>Changed functions</h3><Src kind="tool" /></div>
          <div className="small muted" style={{ marginBottom: 8 }}>Implicated by the bug (diagnosis, failing traceback or bug text): <span className="mono">{m.implicated_functions.join(", ") || "none identified"}</span></div>
          <div className="table-wrap"><table>
            <thead><tr><th>Function</th><th>Change</th><th>Lines</th><th>Related to bug?</th></tr></thead>
            <tbody>{m.changed_functions.map((c) => (
              <tr key={c.file_path + c.name}><td className="mono small">{c.name}<div className="muted">{c.file_path}</div></td><td>{c.kind}</td><td>{c.lines_changed} <span className="muted small">({Math.round(c.change_ratio * 100)}%)</span></td>
                <td>{c.implicated ? <Badge tone="ok">implicated</Badge> : m.implicated_functions.length ? <Badge tone="warn">no signal</Badge> : <Badge>unknown</Badge>}</td></tr>
            ))}</tbody>
          </table></div>
        </div>
        <div className="card">
          <div className="card-head"><h3>Additions</h3><Src kind="tool" /></div>
          <div className="kv">
            <div>New dependencies</div><div><List items={m.new_dependencies} /></div>
            <div>New imports</div><div className="mono small"><List items={m.new_imports} /></div>
            <div>New definitions</div><div className="mono small"><List items={m.new_definitions} /></div>
            <div>Duplicated logic</div><div className="small"><List items={m.duplicated_blocks} /></div>
          </div>
        </div>
      </div>
      {ps.findings.map((f) => (
        <div key={f.id} className={`finding sev-${f.confidence === "high" ? "high" : f.confidence === "medium" ? "medium" : "low"}`}>
          <div className="row"><span className="title">{label(f.category)}</span><Loc path={f.file_path} line={f.line_start} end={f.line_end} onOpen={() => setOpen({ path: f.file_path, hl: f.line_start ? [f.line_start, f.line_end ?? f.line_start] : undefined, version: ps.subject === "user_supplied_patch" ? "modified" : "original" })} />
            <span className="spacer" /><ConfidenceBadge confidence={f.confidence} /></div>
          <dl>
            <dt>Observation</dt><dd>{f.observation}</dd>
            <dt>Reasoning <Src kind={ps.ai_status === "completed" ? "model" : "tool"} /></dt><dd>{f.reasoning}</dd>
            <dt>Could be justified</dt><dd>{f.could_be_justified_because}</dd>
            <dt>Recommendation</dt><dd>{f.recommendation}</dd>
            {f.evidence.length > 0 && <><dt>Evidence <Src kind="tool" /></dt><dd className="small"><List items={f.evidence} /></dd></>}
            <dt>Status</dt><dd className="muted">{f.verification_status}</dd>
          </dl>
        </div>
      ))}
      {ps.findings.length === 0 && <div className="card muted">No potentially unnecessary changes reported.</div>}
      {ps.introduced_security?.length > 0 && (
        <div className="card">
          <div className="card-head"><h3>Security findings introduced by this change</h3><Src kind="tool" /><Badge tone="bad">{ps.introduced_security.length}</Badge></div>
          <div className="stack" style={{ gap: 10 }}>
            {ps.introduced_security.map((f) => <FindingCard key={f.id} f={f} onOpen={() => f.file_path && setOpen({ path: f.file_path, hl: f.line ? [f.line, f.line] : undefined, version: "modified" })} />)}
          </div>
        </div>
      )}
      {ps.limitations.length > 0 && <div className="card"><strong className="small">Limitations</strong><List items={ps.limitations} /></div>}
      <div className="card"><div className="card-head"><h3>Diff under review</h3></div><DiffView diff={ps.diff} maxHeight={600} /></div>
    </div>
  );
}

// --------------------------------------------------------------------------- report & activity

export function ReportTab({ job }: { job: Job }) {
  const r = job.results.report;
  if (!r) return <Empty title="Report not generated yet">The report is produced after the other stages finish or record their limitations.</Empty>;
  return (
    <div className="stack">
      <div className="row">
        <a className="btn" href={apiUrl(`/api/jobs/${job.id}/report.md`)}><Icon name="download" size={14} /> Markdown</a>
        <a className="btn" href={apiUrl(`/api/jobs/${job.id}/report.json`)}><Icon name="download" size={14} /> Full JSON evidence</a>
        <span className="muted small">Generated {fmtTime(r.generated_at)}</span>
      </div>
      <div className="card"><Markdown text={r.markdown} /></div>
    </div>
  );
}

export function ActivityTab({ job }: { job: Job }) {
  return (
    <div className="card">
      <div className="card-head"><h2>Audit trail</h2><span className="muted small">secret values are never logged</span></div>
      <div className="table-wrap"><table>
        <thead><tr><th>Time</th><th>Agent</th><th>Kind</th><th>Event</th></tr></thead>
        <tbody>{job.audit.map((e, i) => (
          <tr key={i}><td className="mono small muted" style={{ whiteSpace: "nowrap" }}>{new Date(e.at).toLocaleTimeString()}</td><td className="small">{e.agent ? label(e.agent) : "orchestrator"}</td>
            <td><Badge tone={e.kind === "warning" ? "warn" : e.kind === "stage" ? "accent" : "neutral"}>{e.kind}</Badge></td><td className="small">{e.message}</td></tr>
        ))}</tbody>
      </table></div>
    </div>
  );
}
