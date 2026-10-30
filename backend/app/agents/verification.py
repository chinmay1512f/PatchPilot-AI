"""Agent 5 — Verification & Security.

Does not trust the Repair agent: it re-runs the reproduction test and the full suite on the
patched copy, compares against the baseline, lints and scans the changed files, and checks
dependency changes. The verification status is computed by code from that evidence; Claude
only adds an interpretation and triages scanner findings.
"""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from ..core.models import (
    AIAssessment,
    MalwareAssessment,
    MalwareDraft,
    Diagnosis,
    PatchProposal,
    Reproduction,
    ScannerRun,
    SecurityFinding,
    SecurityReport,
    Severity,
    TestRun,
    VerificationInterpretation,
    VerificationResult,
    VerificationStatus,
)
from ..ingest.indexer import RepoIndex, build_index
from ..llm.client import LLMError, untrusted
from ..tools.diffing import dependency_changes, diff_trees
from ..tools.scanners import (
    fingerprint,
    run_bandit,
    run_builtin_secrets,
    run_ruff,
    run_security_scan,
    run_semgrep,
    run_suspicious,
)
from ..tools.testing import run_pytest
from ..tools.malware import INDICATOR_CATALOG
from .base import PLAIN_LANGUAGE, AgentContext

TRIAGE_SYSTEM = """You are the security triage part of the Verification & Security agent, doing
defensive review of scanner output for the repository owner. For each finding, look at the code
context and decide whether it is likely a true positive, likely a false positive, or needs human
review, and how urgently it should be handled. Pattern matches for "suspicious code" are not proof
of malware: legitimate software uses subprocesses, networking and file deletion. Explain the
evidence briefly. Do not provide exploit code."""
TRIAGE_SYSTEM += "\n\n" + PLAIN_LANGUAGE

INTERPRET_SYSTEM = """You are the Verification & Security agent. Interpret the tool evidence about a
proposed patch for the developer. The verification status has already been computed from actual
test and scanner results — explain it, list unresolved issues, and note what a human reviewer
should check. Do not claim any check passed unless the evidence says so."""
INTERPRET_SYSTEM += "\n\n" + PLAIN_LANGUAGE


class TriageItem(BaseModel):
    finding_id: str
    verdict: Literal["likely_true_positive", "likely_false_positive", "needs_review"]
    priority: Literal["urgent", "high", "normal", "low"]
    rationale: str


class TriageDraft(BaseModel):
    items: list[TriageItem]
    summary: str


# --------------------------------------------------------------------------- security review


def security_review(ctx: AgentContext, include_osv: bool = True) -> SecurityReport:
    report = run_security_scan(ctx.workspace.original, ctx.index, ctx.settings, include_osv=include_osv)
    ctx.log("verification", "scanners: " + ", ".join(f"{s.name}={s.status}({s.findings})" for s in report.scanners))
    # The two Claude reviews are independent (triage annotates findings, malware writes report.malware),
    # so they run at the same time.
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="review") as pool:
        jobs = [pool.submit(triage, ctx, report, ctx.index), pool.submit(malware_review, ctx, report, ctx.index)]
        for j in jobs:
            j.result()
    return report


MALWARE_SYSTEM = """You are the malware-review part of the Verification & Security agent. This is
defensive analysis for the owner of the repository: decide whether the code shows signs of being
malicious (stealing data, giving remote access, persisting, hiding itself, damaging systems,
mining crypto, or trojanised dependencies).

You get the static indicators that matched, each with surrounding code, plus what the project is.
For each indicator decide: benign (normal for what this project does), suspicious (unclear, a human
should look), or likely_malicious (the code's behaviour only makes sense as an attack). Consider
intent and context: subprocesses, networking, encryption and file deletion are normal in many apps;
combinations such as "collect credentials + send to a webhook" or "decode a blob + exec it" are not.
An antivirus signature match is strong evidence. Then give an overall verdict and concrete next
steps. Never claim the repository is malware-free — only that no malicious indicators were found by
these checks. Do not write exploit or malware code."""
MALWARE_SYSTEM += "\n\n" + PLAIN_LANGUAGE


def malware_review(ctx: AgentContext, report: SecurityReport, index: RepoIndex) -> MalwareAssessment:
    """Malware check: deterministic indicators (+ ClamAV if installed), reviewed by Claude for intent."""
    indicators = [f for f in report.findings if f.category == "suspicious_code"]
    labels = dict(INDICATOR_CATALOG)
    matched = sorted({t for f in indicators for t in f.references if t in labels} | ({"signature-match"} if any(f.scanner == "clamav" for f in indicators) else set()))
    clam = next((s for s in report.scanners if s.name == "clamav"), None)
    signature = f"{clam.status}{' — ' + clam.message if clam and clam.message else ''}" if clam else "not run"
    order = list(Severity)
    serious = [f for f in indicators if f.severity in (Severity.critical, Severity.high)]
    sig_hits = [f for f in indicators if f.scanner == "clamav"]
    # Deterministic baseline verdict (used when AI review is unavailable, and as a floor for signature hits).
    if sig_hits:
        base = "likely_malicious"
    elif serious:
        base = "suspicious_needs_review"
    else:
        base = "no_malicious_indicators"
    assessment = MalwareAssessment(
        overall=base, signature_scan=signature, finding_ids=[f.id for f in indicators],
        indicators_checked=[label for _, label in INDICATOR_CATALOG], indicators_matched=[labels.get(m, "Antivirus signature match") for m in matched],
        summary=(f"None of the {len(INDICATOR_CATALOG)} malware indicator groups matched." if not indicators else
                 f"{len(indicators)} indicator(s) matched ({len(serious)} high-risk); see the review below."),
    )
    if clam and clam.status != "completed":
        assessment.limitations.append("No antivirus signature scan was run (ClamAV is not installed); only behaviour-based static checks were used.")
    assessment.limitations.append("Static checks only: the code was not executed to observe its behaviour, and obfuscated or novel malware can evade pattern-based checks.")
    if not indicators:
        assessment.ai_status = "not_needed"
        report.malware = assessment
        return assessment
    ok, why = ctx.llm.available()
    if not ok:
        assessment.ai_status = "unavailable"
        report.malware = assessment
        return assessment
    readme = next((p for p in index.files if Path(p).name.lower().startswith("readme")), None)
    about = f"Project facts: {', '.join(x.language for x in index.facts.languages[:4])}; frameworks: {', '.join(index.facts.frameworks) or 'none'}."
    blocks = [about]
    if readme:
        blocks.append("README excerpt:\n" + untrusted(readme, index.read_numbered(readme, 1, 40)))
    for f in sorted(indicators, key=lambda x: order.index(x.severity))[:25]:
        code = index.excerpt(f.file_path, f.line, f.line, context=6) if f.file_path and f.line and index.resolve(f.file_path) else f.snippet
        blocks.append(f"finding_id={f.id} rule={f.rule_id} severity={f.severity} tags={','.join(f.references)}\n"
                      f"location={f.file_path}:{f.line}\nindicator={f.title}: {f.description}\n"
                      + untrusted(f.file_path or "file", code or "(no source excerpt)"))
    try:
        draft = ctx.llm.structured(agent="verification", system=MALWARE_SYSTEM, messages="Malware indicators to review:\n\n" + "\n\n".join(blocks),
                                   output_model=MalwareDraft, effort="high")
    except LLMError as e:
        assessment.ai_status = f"failed: {e}"
        report.malware = assessment
        return assessment
    valid = {f.id for f in indicators}
    assessment.items = [i for i in draft.items if i.finding_id in valid]
    assessment.overall = draft.overall
    if sig_hits and assessment.overall == "no_malicious_indicators":
        assessment.overall = "suspicious_needs_review"  # an antivirus hit is never waved through
        assessment.limitations.append("Overall verdict raised to 'suspicious' because an antivirus signature matched.")
    assessment.summary = draft.summary
    assessment.recommended_actions = draft.recommended_actions
    assessment.ai_status = "completed"
    report.malware = assessment
    ctx.log("verification", f"malware check: {assessment.overall} ({len(indicators)} indicator(s) reviewed)")
    return assessment


def triage(ctx: AgentContext, report: SecurityReport, index: RepoIndex) -> None:
    if not report.findings:
        report.triage_status = "not_needed"
        return
    ok, why = ctx.llm.available()
    if not ok:
        report.triage_status = "unavailable"
        report.triage_summary = why
        return
    order = list(Severity)
    selected = sorted(report.findings, key=lambda f: (order.index(f.severity), f.category != "suspicious_code"))[:30]
    blocks = []
    for f in selected:
        ctx_text = index.excerpt(f.file_path, f.line, f.line, context=4) if f.file_path and f.line else f.snippet
        blocks.append(f"finding_id={f.id} scanner={f.scanner} rule={f.rule_id} severity={f.severity} category={f.category}\n"
                      f"location={f.file_path}:{f.line}\ndescription={f.description}\n" + untrusted(f"{f.file_path}", ctx_text))
    try:
        draft = ctx.llm.structured(agent="verification", system=TRIAGE_SYSTEM, messages="Scanner findings to triage:\n\n" + "\n\n".join(blocks),
                                   output_model=TriageDraft, effort="medium")
    except LLMError as e:
        report.triage_status = f"failed: {e}"
        return
    by_id = {f.id: f for f in report.findings}
    applied = 0
    for item in draft.items:
        f = by_id.get(item.finding_id)
        if f:
            f.ai_assessment = AIAssessment(verdict=item.verdict, rationale=item.rationale, priority=item.priority)
            applied += 1
    report.triage_status = "completed"
    report.triage_summary = draft.summary + ("" if len(selected) == len(report.findings) else f" (AI triage covered the top {len(selected)} of {len(report.findings)} findings.)")
    ctx.log("verification", f"AI triage annotated {applied} findings")


# --------------------------------------------------------------------------- patch verification


def _patch_scan(ctx: AgentContext, patched: Path, changed: set[str], original_findings: list[SecurityFinding]) -> tuple[list[SecurityFinding], list[str]]:
    idx = build_index(patched, max_file_kb=ctx.settings.max_index_file_kb)
    runs, found = [], []
    def semgrep_step():
        if not ctx.settings.patch_recheck_semgrep:
            # Semgrep needs ~20s just to start on Windows; for the few changed lines Bandit + secret + malware
            # rules cover the same risks. It still scans the whole repository in the parallel security lane.
            return ScannerRun(name="semgrep", status="skipped",
                              message="not used for the patch re-check (speed setting); it scanned the full repository earlier"), []
        return run_semgrep(patched, idx, ctx.settings, files=sorted(changed))

    steps = (lambda: run_bandit(patched, idx, ctx.settings.scanner_timeout_seconds), semgrep_step,
             lambda: run_builtin_secrets(idx), lambda: run_suspicious(idx))
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="patch-scan") as pool:  # independent scanners, run together
        for r, f in pool.map(lambda fn: fn(), steps):
            runs.append(r)
            found += f
    before = {fingerprint(f) for f in original_findings}
    introduced = []
    for f in found:
        if f.file_path in changed and fingerprint(f) not in before:
            f.introduced_by_patch = True
            f.category = "patch_security" if f.category != "secret" else "secret"
            introduced.append(f)
    return introduced, [f"{r.name}: {r.status}" for r in runs]


def verify_patch(ctx: AgentContext, patch: PatchProposal, patched: Path, repro: Reproduction | None,
                 baseline_run: TestRun | None, original_security: SecurityReport | None) -> VerificationResult:
    res = VerificationResult(status=VerificationStatus.inconclusive, patch_id=patch.id, original_bug_status="unknown", baseline_run=baseline_run)
    if not patch.applied:
        res.status = VerificationStatus.failed
        res.original_bug_status = "not_fixed"
        res.reasons = ["Patch could not be applied: " + "; ".join(patch.apply_errors)]
        return res

    changed = set(patch.files_changed)
    # 1. syntax
    for p in sorted(changed):
        if p.endswith(".py") and (patched / p).is_file():
            try:
                ast.parse((patched / p).read_text(encoding="utf-8"))
            except SyntaxError as e:
                res.syntax_errors.append(f"{p}:{e.lineno}: {e.msg}")
    res.checks_performed.append("Python syntax check of changed files")

    # 2. dependency changes (before the repro test is added to the copy)
    res.dependency_changes = dependency_changes(diff_trees(ctx.workspace.original, patched))
    res.checks_performed.append("dependency manifest comparison")

    # The patch security scan does not depend on the test results, so it runs while the tests run.
    orig_findings = original_security.findings if original_security else []
    scan_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="patch-scan-lane")
    scan_future = scan_pool.submit(_patch_scan, ctx, patched, changed, orig_findings)
    scan_pool.shutdown(wait=False)

    # 3. tests
    if repro and repro.test_code and repro.test_path:
        target = patched / repro.test_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(repro.test_code, encoding="utf-8")
        res.repro_after_patch = run_pytest(ctx.backend, patched, f"repro-after-{patch.attempt}", [repro.test_path], timeout=ctx.settings.sandbox_timeout_seconds, stubs=ctx.index.facts.third_party_imports)
    res.patched_run = run_pytest(ctx.backend, patched, f"suite-after-{patch.attempt}", timeout=ctx.settings.sandbox_timeout_seconds, stubs=ctx.index.facts.third_party_imports)
    blocked = res.patched_run.status == "blocked"
    if not blocked:
        res.checks_performed.append("full test suite on patched copy (incl. reproduction test)")
    if baseline_run and res.patched_run.status in ("completed", "no_tests"):
        res.new_failures = sorted(baseline_run.passing_ids & res.patched_run.failing_ids)
        res.fixed_tests = sorted(baseline_run.failing_ids & res.patched_run.passing_ids)
        missing = baseline_run.passing_ids - {t.nodeid for t in res.patched_run.tests}
        if missing:
            res.new_failures += [f"{m} (no longer executed)" for m in sorted(missing)]
        res.checks_performed.append("regression comparison against baseline run")
    ra = res.repro_after_patch
    if repro and repro.status == "reproduced" and ra and ra.status == "completed":
        res.original_bug_status = "fixed" if ra.failed == 0 and ra.errors == 0 and ra.passed > 0 else "not_fixed"

    # 4. lint on changed files (new issues only)
    py_changed = [p for p in changed if p.endswith(".py")]
    if py_changed:
        existed = [p for p in py_changed if (ctx.workspace.original / p).is_file()]
        before = run_ruff(ctx.workspace.original, existed)[1] if existed else []
        r_after, after = run_ruff(patched, py_changed)
        if r_after.status == "completed":
            key = lambda i: (i["file"], i["code"], i["message"])  # noqa: E731
            extra = Counter(map(key, after)) - Counter(map(key, before))
            res.new_lint_issues = [f"{f}: {c} {m}" for (f, c, m) in extra.elements()]
            res.checks_performed.append("ruff lint on changed files")
        else:
            res.checks_not_performed.append(f"lint ({r_after.message or r_after.status})")

    # 5. patch security (started in parallel with the tests above)
    res.patch_security_findings, scan_status = scan_future.result()
    res.checks_performed.append("security scan of patched files (" + ", ".join(scan_status) + ")")

    # 6. what we did not do
    res.checks_not_performed += [
        "type checking (mypy) — not configured for analysed repositories",
        "integration / end-to-end tests beyond the repository's own pytest suite",
    ]
    if ctx.index.facts.dependencies:
        res.checks_not_performed.append("third-party dependencies were not installed in the sandbox; tests needing them may error")

    # 7. status from evidence only
    serious = [f for f in res.patch_security_findings if f.severity in (Severity.critical, Severity.high)]
    if res.syntax_errors:
        res.status, res.reasons = VerificationStatus.failed, ["Patched files contain syntax errors."]
    elif blocked:
        res.status, res.reasons = VerificationStatus.blocked, [res.patched_run.blocked_reason or "Test execution was blocked."]
    elif res.original_bug_status == "not_fixed":
        res.status, res.reasons = VerificationStatus.failed, ["The reproduction test still fails on the patched code."]
    elif res.new_failures:
        res.status, res.reasons = VerificationStatus.failed, [f"{len(res.new_failures)} previously passing test(s) now fail."]
    elif serious:
        res.status, res.reasons = VerificationStatus.failed, [f"Patch introduces {len(serious)} high/critical security finding(s)."]
    elif res.patched_run.status not in ("completed",):
        res.status, res.reasons = VerificationStatus.incomplete, [f"Test suite status after patch: {res.patched_run.status}."]
    elif res.original_bug_status != "fixed":
        res.status, res.reasons = VerificationStatus.inconclusive, ["The original bug was not reproduced by a failing test, so the fix cannot be confirmed by execution."]
    else:
        res.status = VerificationStatus.verified
        res.reasons = [
            "Reproduction test failed before the patch and passes after it.",
            f"Full suite after patch: {res.patched_run.passed} passed, {res.patched_run.failed} failed, {res.patched_run.errors} errors; no regressions versus baseline"
            + (f" (the {len(res.patched_run.failing_ids & baseline_run.failing_ids)} failing/erroring test(s) already failed before the patch)."
               if baseline_run and res.patched_run.failing_ids & baseline_run.failing_ids else "."),
            "No new high/critical security findings in changed files.",
        ]
    return res


def interpret(ctx: AgentContext, res: VerificationResult, patch: PatchProposal, diagnosis: Diagnosis | None) -> None:
    ok, _ = ctx.llm.available()
    if not ok:
        return
    evidence = res.model_dump(exclude={"baseline_run", "patched_run", "repro_after_patch", "interpretation"})
    evidence["patched_suite"] = {k: getattr(res.patched_run, k) for k in ("status", "passed", "failed", "errors", "skipped")} if res.patched_run else None
    evidence["repro_after_patch"] = {k: getattr(res.repro_after_patch, k) for k in ("status", "passed", "failed", "errors")} if res.repro_after_patch else None
    prompt = (f"Patch summary (model-generated): {patch.summary}\nDiff:\n" + untrusted("diff", patch.diff[:20000])
              + "\n\nTool evidence:\n" + json.dumps(evidence, indent=1, default=str)[:20000])
    try:
        res.interpretation = ctx.llm.structured(agent="verification", system=INTERPRET_SYSTEM, messages=prompt, output_model=VerificationInterpretation, effort="medium")
    except LLMError as e:
        ctx.log("verification", f"interpretation skipped: {e}")
