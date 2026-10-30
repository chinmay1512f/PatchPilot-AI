"""Central orchestrator: owns job state, decides which agents run, passes typed context between
them, enforces retry limits, and records an audit trail.

Agents cannot trigger each other or grant themselves capabilities: only this module decides
what runs next, which execution backend is used, and when the workflow stops.
"""

from __future__ import annotations

import logging
import threading
import time
import traceback
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from .agents import bug_investigation, patch_scope, repair, repo_understanding, reporting, reproduction, verification
from .agents.base import AgentContext
from .config import Settings
from .core.models import (
    AGENT_ORDER, AGENT_TITLES, AgentRun, AnalysisType, Job, JobOptions, Reproduction, SecurityReport, StageStatus, VerificationStatus, new_id, utcnow,
)
from .core.store import JobStore
from .ingest.indexer import build_index
from .ingest.workspace import Workspace
from .llm.client import LLMBudgetExceeded, LLMClient, LLMError, LLMNotConfigured, LLMRefusal, estimate_cost
from .tools.sandbox import select_backend
from .tools.scanners import fingerprint, run_security_scan

log = logging.getLogger("patchpilot.orchestrator")

LLMFactory = Callable[[Settings, Callable, str], LLMClient]


class StageBlocked(Exception):
    pass


class StageSkipped(Exception):
    pass


class StageInconclusive(Exception):
    pass


class Orchestrator:
    def __init__(self, store: JobStore, settings: Settings, llm_factory: LLMFactory | None = None, max_workers: int = 2):
        self.store = store
        self.s = settings
        self.llm_factory = llm_factory or (lambda s, cb, name: LLMClient(s, on_usage=cb, replay_name=name))
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="patchpilot-job")
        # Parallel lanes inside a job (security lane, early baseline test run).
        self.lanes = ThreadPoolExecutor(max_workers=max_workers * 3, thread_name_prefix="patchpilot-lane")
        self._cancel: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ job lifecycle
    def new_job(self, project_name: str, analysis_type: AnalysisType, bug: str, options: JobOptions) -> tuple[Job, Workspace]:
        job = Job(id=new_id("job"), project_name=project_name[:80] or "repository", analysis_type=analysis_type,
                  bug_description=bug[:8000], options=options, model=self.s.model, llm_mode=self.s.llm_mode)
        for name in AGENT_ORDER:
            job.agents[name] = AgentRun(agent=name, title=AGENT_TITLES[name])
        ws = Workspace(self.s.workspaces_dir, job.id)
        ws.create()
        return job, ws

    def submit(self, job_id: str) -> None:
        self.pool.submit(self.run, job_id)

    def recover_interrupted(self) -> int:
        """Jobs left 'running' by a crash/restart are marked failed rather than shown as live."""
        n = 0
        for job in self.store.list(limit=500):
            if job.status in (StageStatus.running, StageStatus.pending):
                def mark(j: Job) -> None:
                    j.status = StageStatus.failed
                    j.error = "Interrupted by a server restart. Use 'Re-run' to start it again."
                    for a in j.agents.values():
                        if a.status == StageStatus.running:
                            a.status, a.message = StageStatus.failed, "interrupted"
                self.store.update(job.id, mark)
                n += 1
        return n

    # ------------------------------------------------------------------ helpers
    def _audit(self, job_id: str, agent: str | None, message: str, kind: str = "info") -> None:
        log.info("job=%s agent=%s %s", job_id, agent, message)
        self.store.add_audit(job_id, kind, message, agent)

    def _usage_cb(self, job_id: str):
        def cb(agent: str, inp: int, out: int, cache: int, fast: bool = False) -> None:
            def mut(j: Job) -> None:
                a = j.agents.get(agent)
                if a:
                    a.input_tokens += inp
                    a.output_tokens += out
                    a.llm_calls += 1
                j.usage.input_tokens += inp
                j.usage.output_tokens += out
                j.usage.cache_read_tokens += cache
                j.usage.llm_calls += 1
                j.usage.fast_calls += int(fast)
                # per-call so fast-mode calls are priced at their own (2x) rate
                j.usage.estimated_cost_usd = round(j.usage.estimated_cost_usd + estimate_cost(j.model, inp, out, cache, fast), 4)
            self.store.update(job_id, mut)
        return cb

    @contextmanager
    def _stage(self, job_id: str, agent: str):
        def start(j: Job) -> None:
            j.current_stage = agent
            a = j.agents[agent]
            a.status, a.started_at, a.message = StageStatus.running, utcnow(), ""
        self.store.update(job_id, start)
        self._audit(job_id, agent, "stage started", "stage")
        status, message = StageStatus.completed, ""
        t0 = time.monotonic()
        try:
            yield
        except StageSkipped as e:
            status, message = StageStatus.skipped, str(e)
        except StageBlocked as e:
            status, message = StageStatus.blocked, str(e)
        except StageInconclusive as e:
            status, message = StageStatus.inconclusive, str(e)
        except (LLMNotConfigured, LLMRefusal, LLMBudgetExceeded) as e:
            status, message = StageStatus.blocked, str(e)
        except LLMError as e:
            status, message = StageStatus.failed, str(e)
        except Exception as e:  # noqa: BLE001 — a stage failure must be recorded, never crash the worker
            status, message = StageStatus.failed, f"Internal error: {type(e).__name__}: {e}"
            log.error("job=%s agent=%s crashed\n%s", job_id, agent, traceback.format_exc())
        finally:
            def finish(j: Job) -> None:
                a = j.agents[agent]
                if a.status == StageStatus.running:
                    a.status = status
                a.finished_at = utcnow()
                a.message = message or a.message
            self.store.update(job_id, finish)
            self._audit(job_id, agent, f"stage {status} in {time.monotonic() - t0:.1f}s {('— ' + message) if message else ''}", "stage")

    def _set(self, job_id: str, fn: Callable[[Job], None]) -> Job:
        return self.store.update(job_id, fn)

    def _note(self, job_id: str, agent: str, message: str) -> None:
        self._set(job_id, lambda j: setattr(j.agents[agent], "message", message))

    def _skip(self, job_id: str, agents: list[str], reason: str) -> None:
        def mut(j: Job) -> None:
            for a in agents:
                if j.agents[a].status == StageStatus.pending:
                    j.agents[a].status, j.agents[a].message = StageStatus.skipped, reason
        self._set(job_id, mut)

    # ------------------------------------------------------------------ main workflow
    def run(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None:
            return
        ws = Workspace(self.s.workspaces_dir, job_id)
        try:
            llm = self.llm_factory(self.s, self._usage_cb(job_id), job_id)
            backend = select_backend(self.s, job.options.allow_local_execution)
        except Exception as e:  # noqa: BLE001 — never leave a job stuck in "pending"
            err = f"Could not start analysis: {e}"
            self._set(job_id, lambda j: (setattr(j, "status", StageStatus.failed), setattr(j, "error", err)))
            return
        self._set(job_id, lambda j: (setattr(j, "status", StageStatus.running), setattr(j, "execution_backend", backend.name),
                                     setattr(j, "execution_backend_detail", backend.detail)))
        self._audit(job_id, None, f"execution backend: {backend.name} — {backend.detail}")
        ok, why = llm.available()
        if not ok:
            self._audit(job_id, None, why, "warning")
        try:
            index = build_index(ws.original, max_file_kb=self.s.max_index_file_kb)
            ctx = AgentContext(job_id, self.s, llm, ws, index, backend, lambda agent, msg: self._audit(job_id, agent, msg))
            {
                AnalysisType.full_analysis: self._flow_full,
                AnalysisType.full_repair: self._flow_repair,
                AnalysisType.investigate_only: self._flow_repair,
                AnalysisType.security_scan: self._flow_security,
                AnalysisType.patch_review: self._flow_patch_review,
            }[job.analysis_type](ctx, job)
            with self._stage(job_id, "reporting"):
                current = self.store.get(job_id)
                report = reporting.run(ctx, current)
                self._set(job_id, lambda j: setattr(j.results, "report", report))
            final = self.store.get(job_id)
            statuses = {a.status for a in final.agents.values()}
            overall = StageStatus.completed
            if final.results.verification and final.results.verification.status in (VerificationStatus.failed,):
                overall = StageStatus.failed
            elif StageStatus.failed in statuses:
                overall = StageStatus.failed
            elif StageStatus.blocked in statuses or StageStatus.inconclusive in statuses:
                overall = StageStatus.inconclusive
            self._set(job_id, lambda j: (setattr(j, "status", overall), setattr(j, "current_stage", None)))
        except Exception as e:  # noqa: BLE001
            log.error("job=%s failed\n%s", job_id, traceback.format_exc())
            err = f"{type(e).__name__}: {e}"
            self._set(job_id, lambda j: (setattr(j, "status", StageStatus.failed), setattr(j, "error", err)))
        finally:
            if getattr(llm, "fast_note", ""):
                self._audit(job_id, None, llm.fast_note, "warning")
            path = llm.save_recording(job_id) if hasattr(llm, "save_recording") else None
            if path:
                self._audit(job_id, None, f"LLM outputs recorded to {Path(path).name} for replay")
            try:
                ws.cleanup_runs()
            except OSError as e:
                self._audit(job_id, None, f"workspace cleanup incomplete: {e}", "warning")

    # ------------------------------------------------------------------ parallel lanes
    def _start_security_lane(self, ctx: AgentContext, job: Job) -> Future:
        """Security scanning, AI triage and the malware check do not depend on Agents 1-4, so they
        run in their own lane alongside them. Only patch verification waits for this result."""
        jid = job.id

        def start(j: Job) -> None:
            a = j.agents["verification"]
            a.status, a.started_at, a.lane = StageStatus.running, utcnow(), "parallel"
            a.message = "Security & malware scan running in parallel with the other agents…"
        self._set(jid, start)
        self._audit(jid, "verification", "[parallel lane] security & malware scan started", "stage")

        def lane() -> SecurityReport | None:
            t0 = time.monotonic()
            try:
                sec = verification.security_review(ctx)
            except Exception as e:  # noqa: BLE001 — recorded; the repair lane carries on
                log.error("job=%s security lane failed\n%s", jid, traceback.format_exc())
                msg = f"Security lane failed: {type(e).__name__}: {e}"
                self._set(jid, lambda j: setattr(j.agents["verification"], "message", msg))
                self._audit(jid, "verification", "[parallel lane] " + msg, "warning")
                return None
            done = sum(1 for s in sec.scanners if s.status == "completed")
            malware = f"; malware check: {sec.malware.overall.replace('_', ' ')}" if sec.malware else ""
            note = f"Security scan done in {time.monotonic() - t0:.0f}s (parallel): {done}/{len(sec.scanners)} scanners, {len(sec.findings)} findings{malware}"

            def finish(j: Job) -> None:
                j.results.security = sec
                a = j.agents["verification"]
                if a.lane == "parallel" and a.status == StageStatus.running:  # patch verification has not started yet
                    a.status, a.finished_at = StageStatus.completed, utcnow()
                    a.message = note
            self._set(jid, finish)
            self._audit(jid, "verification", "[parallel lane] " + note, "stage")
            return sec

        return self.lanes.submit(lane)

    @staticmethod
    def _join(fut: Future | None) -> SecurityReport | None:
        return fut.result() if fut else None

    def _finish_security_only(self, jid: str, security: SecurityReport | None, reason: str) -> None:
        """Agent 5 did security work only (no patch): record the outcome of its parallel lane."""
        def mut(j: Job) -> None:
            a = j.agents["verification"]
            a.finished_at = utcnow()
            if security is None:
                a.status = StageStatus.failed
                a.message = (a.message or "Security lane failed.") + f" {reason}"
            else:
                a.status = StageStatus.completed
                a.message = " · ".join(x for x in (a.message, reason) if x)
        self._set(jid, mut)

    # ------------------------------------------------------------------ flows
    def _flow_repair(self, ctx: AgentContext, job: Job) -> None:
        jid = job.id
        # Independent work starts immediately, in parallel with the agent chain 1 → 2 → 3 → 4.
        security_future = self._start_security_lane(ctx, job) if job.options.run_security_scan else None
        baseline_future = self.lanes.submit(reproduction.baseline, ctx)
        with self._stage(jid, "repo_understanding"):
            repo = repo_understanding.run(ctx)
            self._set(jid, lambda j: setattr(j.results, "repo", repo))
            if repo.narrative_status == "blocked":
                raise StageBlocked("Index built (tool facts available); AI summary blocked: " + repo.limitations[-1])
            self._note(jid, "repo_understanding", f"{repo.facts.indexed_files} files indexed; {len(repo.facts.languages)} languages")

        # Full analysis without a bug report = autonomous mode: Agent 2 audits the code for defects.
        discovery = job.analysis_type == AnalysisType.full_analysis and not job.bug_description.strip()
        diagnosis = None
        with self._stage(jid, "bug_investigation"):
            if not job.bug_description.strip() and not discovery:
                raise StageSkipped("No bug description provided.")
            diagnosis = bug_investigation.run(ctx, job.bug_description, repo)
            self._set(jid, lambda j: setattr(j.results, "diagnosis", diagnosis))
            if discovery and not diagnosis.findings:
                self._note(jid, "bug_investigation", f"code audit ({diagnosis.tool_calls} tool calls) found no defect with enough evidence to report")
            else:
                kind = "audit" if discovery else "investigation"
                msg = f"{kind}: {len(diagnosis.findings)} finding(s); {diagnosis.tool_calls} tool calls; {'conclusive' if diagnosis.conclusive else 'inconclusive'}"
                if not diagnosis.conclusive:
                    raise StageInconclusive(msg + " — no verified primary defect.")
                self._note(jid, "bug_investigation", msg)

        # What reproduction and repair work from: the user's report, or the defect the audit found.
        bug_text = job.bug_description.strip() or (diagnosis.discovered_issue if diagnosis else "")
        repro = None
        with self._stage(jid, "reproduction"):
            baseline = baseline_future.result()  # started at the beginning of the job
            if not bug_text:
                note = "No defect to reproduce" if discovery else "No bug description"
                repro = Reproduction(status="skipped", baseline_run=baseline, notes=[f"{note}; only the existing test suite was run."])
            else:
                repro = reproduction.run(ctx, bug_text, diagnosis, baseline)
            self._set(jid, lambda j: setattr(j.results, "reproduction", repro))
            msg = f"reproduction {repro.status}; baseline {baseline.status} ({baseline.passed} passed, {baseline.failed} failed)"
            if repro.status == "blocked":
                raise StageBlocked(msg + ". " + (baseline.blocked_reason or ""))
            if repro.status in ("inconclusive", "not_reproduced"):
                raise StageInconclusive(msg)
            self._note(jid, "reproduction", msg)

        security = None
        if job.analysis_type == AnalysisType.investigate_only:
            self._skip(jid, ["repair"], "Investigation-only analysis.")
            if security_future:
                security = self._join(security_future)
                self._finish_security_only(jid, security, "No patch in an investigation-only analysis.")
            else:
                self._skip(jid, ["verification"], "Investigation-only analysis.")
            return

        can_repair = bool(diagnosis and (diagnosis.conclusive or (repro and repro.status == "reproduced")))
        skip_reason = "Root cause not established with enough confidence; repair skipped rather than guessed."
        if discovery:
            # A defect the AI found on its own is only patched once a failing test proves it is real
            # (or, if execution is blocked, proposed but left unverified).
            can_repair = bool(diagnosis and diagnosis.conclusive and repro and repro.status in ("reproduced", "blocked"))
            if diagnosis and not diagnosis.findings:
                skip_reason = "The code audit found no defect with enough evidence; nothing to repair."
            elif repro and repro.status == "not_reproduced":
                skip_reason = "The suspected defect was not confirmed by a failing test, so it was not patched."
            elif repro and repro.status in ("inconclusive", "skipped"):
                skip_reason = "The suspected defect could not be demonstrated with a working test, so it was not patched."
        if not can_repair:
            self._skip(jid, ["repair"], skip_reason)
            if security_future:
                security = self._join(security_future)
                self._finish_security_only(jid, security, "No patch to verify.")
            else:
                self._skip(jid, ["verification"], "No patch to verify; security scan disabled.")
            return

        # Join point: patch verification compares security findings before/after the patch.
        security = self._join(security_future)

        max_attempts = max(1, min(job.options.max_repair_attempts or self.s.max_repair_attempts, 4))
        history: list = []
        final_ver = None
        for attempt in range(1, max_attempts + 1):
            patch = patched_dir = None
            with self._stage(jid, "repair"):
                patch, patched_dir = repair.run(ctx, bug_text, diagnosis, repro, attempt, history)
                self._set(jid, lambda j: j.results.patches.append(patch))
                note = f"attempt {attempt}/{max_attempts}: {len(patch.files_changed)} file(s), +{patch.lines_added}/-{patch.lines_removed}"
                if patch.apply_errors:
                    raise StageInconclusive(note + "; could not apply: " + "; ".join(patch.apply_errors)[:300])
                self._note(jid, "repair", note)
            if patch is None:
                break  # repair stage itself failed (LLM error etc.)
            # The unnecessary-change review only needs the diff, so it starts now, alongside the tests.
            scope_future = self.lanes.submit(patch_scope.analyze, ctx, ctx.workspace.original, patched_dir, "patchpilot_patch", bug_text,
                                             diagnosis, repro.repro_run.output_tail if repro and repro.repro_run else "",
                                             exclude={repro.test_path} if repro and repro.test_path else None)
            with self._stage(jid, "verification"):
                ver = verification.verify_patch(ctx, patch, patched_dir, repro, repro.baseline_run if repro else None, security)
                self._set(jid, lambda j: (j.results.verification_history.append(ver), setattr(j.results, "verification", ver)))
                if ver.status == VerificationStatus.verified or attempt == max_attempts or ver.status == VerificationStatus.blocked:
                    verification.interpret(ctx, ver, patch, diagnosis)
                    scope = scope_future.result()
                    self._set(jid, lambda j: (setattr(j.results, "verification", ver), setattr(j.results, "patch_scope", scope)))
                note = f"attempt {attempt}: {ver.status}"
                if ver.status == VerificationStatus.blocked:
                    raise StageBlocked(note + " — " + "; ".join(ver.reasons))
                if ver.status in (VerificationStatus.failed,) and attempt < max_attempts:
                    self._note(jid, "verification", note + " — retrying repair with failure evidence")
                elif ver.status in (VerificationStatus.inconclusive, VerificationStatus.incomplete):
                    raise StageInconclusive(note + " — " + "; ".join(ver.reasons))
                else:
                    self._note(jid, "verification", note)
            history.append((patch, ver))
            final_ver = ver
            if ver.status != VerificationStatus.failed:
                break
            self._audit(jid, "repair", f"retry {attempt + 1} scheduled using verification failure evidence")
            self._set(jid, lambda j: setattr(j.agents["repair"], "status", StageStatus.pending))
        if final_ver and final_ver.status == VerificationStatus.failed:
            self._set(jid, lambda j: (setattr(j.agents["verification"], "status", StageStatus.failed),
                                      setattr(j.agents["verification"], "message", f"failed after {len(history)} attempt(s): " + "; ".join(final_ver.reasons))))

    def _flow_security(self, ctx: AgentContext, job: Job, skip_reason: str = "Not required for a security scan.") -> None:
        jid = job.id
        # Repository understanding and the security/malware lane are independent: run them together.
        security_future = self._start_security_lane(ctx, job)
        self._skip(jid, ["bug_investigation", "reproduction", "repair"], skip_reason)
        with self._stage(jid, "repo_understanding"):
            repo = repo_understanding.run(ctx)
            self._set(jid, lambda j: setattr(j.results, "repo", repo))
            if repo.narrative_status == "blocked":
                raise StageBlocked("Index built (tool facts available); AI summary blocked: " + repo.limitations[-1])
        self._finish_security_only(jid, self._join(security_future), "")

    def _flow_full(self, ctx: AgentContext, job: Job) -> None:
        """Run everything: bug investigation (from a report, or an autonomous code audit when none is
        given) → reproduction → repair → verification, the full security scan, and review of a
        supplied modified version (if one was uploaded)."""
        jid = job.id
        self._flow_repair(ctx, job)
        if not ctx.workspace.modified.exists():
            return
        self._audit(jid, "verification", "full analysis: reviewing the supplied modified version")
        try:
            current = self.store.get(jid)
            before = current.results.security.findings if current and current.results.security else None
            scope, after, (mod_ctx, mod_index) = self._review_supplied(ctx, job, before)
            introduced = SecurityReport(scanners=[], findings=[f for f in after.findings if f.introduced_by_patch])
            verification.triage(mod_ctx, introduced, mod_index)
            scope.introduced_security = introduced.findings
            note = (f"supplied patch: {scope.overall_assessment.replace('_', ' ')}, {len(scope.findings)} scope finding(s), "
                    f"{len(scope.introduced_security)} new security finding(s)")
            def mut(j: Job) -> None:
                j.results.supplied_patch_scope = scope
                v = j.agents["verification"]
                v.message = f"{v.message} · {note}" if v.message else note
            self._set(jid, mut)
        except Exception as e:  # noqa: BLE001 — the rest of the analysis is still valid
            self._audit(jid, "verification", f"supplied patch review failed: {type(e).__name__}: {e}", "warning")

    def _review_supplied(self, ctx: AgentContext, job: Job, before_findings=None):
        """Unnecessary-change analysis + security diff of the uploaded modified version."""
        scope = patch_scope.analyze(ctx, ctx.workspace.original, ctx.workspace.modified, "user_supplied_patch", job.bug_description)
        mod_index = build_index(ctx.workspace.modified, max_file_kb=self.s.max_index_file_kb)
        mod_ctx = AgentContext(ctx.job_id, ctx.settings, ctx.llm, ctx.workspace, mod_index, ctx.backend, ctx.log)
        if before_findings is None:
            before_findings = run_security_scan(ctx.workspace.original, ctx.index, self.s, include_osv=job.options.run_security_scan).findings
        after = run_security_scan(ctx.workspace.modified, mod_index, self.s, include_osv=job.options.run_security_scan)
        seen = {fingerprint(f) for f in before_findings}
        for f in after.findings:
            if fingerprint(f) not in seen:
                f.introduced_by_patch = True
        return scope, after, (mod_ctx, mod_index)

    def _flow_patch_review(self, ctx: AgentContext, job: Job) -> None:
        jid = job.id
        with self._stage(jid, "repo_understanding"):
            repo = repo_understanding.run(ctx)
            self._set(jid, lambda j: setattr(j.results, "repo", repo))
            if repo.narrative_status == "blocked":
                raise StageBlocked("Index built; AI summary blocked: " + repo.limitations[-1])
        self._skip(jid, ["bug_investigation", "reproduction", "repair"], "Reviewing a supplied patch; no new repair generated.")
        with self._stage(jid, "verification"):
            if not ctx.workspace.modified.exists():
                raise StageBlocked("No modified version was uploaded.")
            scope, after, (mod_ctx, mod_index) = self._review_supplied(ctx, job)
            verification.triage(mod_ctx, after, mod_index)
            verification.malware_review(mod_ctx, after, mod_index)
            scope.introduced_security = [f for f in after.findings if f.introduced_by_patch]
            self._set(jid, lambda j: setattr(j.results, "patch_scope", scope))
            self._set(jid, lambda j: setattr(j.results, "security", after))
            self._note(jid, "verification", f"scope: {scope.overall_assessment}; {len(scope.findings)} scope finding(s); "
                                             f"{sum(f.introduced_by_patch for f in after.findings)} security finding(s) introduced by the patch")
