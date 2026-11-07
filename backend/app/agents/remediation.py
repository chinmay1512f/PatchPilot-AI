"""Intelligent auto-remediation of security findings.

Agent 4 (Repair) asks Claude for minimal fixes for the most severe code vulnerabilities and exposed
secrets; they are applied to a disposable copy only. Agent 5 (Verification) then re-runs EVERY
scanner on the fixed copy and the test suite, and compares before/after. Nothing is pushed anywhere:
the user gets a reviewable, downloadable patch.

Honesty rules:
- A finding counts as cleared only if the same scanner re-ran and reports fewer findings of that rule
  in that file. That means "the scanner no longer reports it", not "proven secure".
- Regressions, or new high/critical findings introduced by the fixes, make the result "failed".
- Without a test run the result is "untested", never "verified".
- Claude only sees secret-redacted code; the shown/downloadable diff is redacted too.
- Not attempted automatically: dependency upgrades (cannot be tested without installing packages) and
  suspicious/malware-like code (removing it could delete real functionality — a human decides).
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import BaseModel, Field

from ..core.models import (
    FileEditDraft,
    Remediation,
    RemediationTarget,
    RepairDraft,
    SecurityFinding,
    SecurityReport,
    Severity,
    TestRun,
)
from ..ingest.indexer import build_index
from ..ingest.secrets import REDACTED, redact
from ..llm.client import LLMError, untrusted
from ..tools.diffing import combined_diff, diff_trees, enclosing_function
from ..tools.scanners import run_ruff, run_security_scan
from ..tools.testing import run_pytest
from .base import PLAIN_LANGUAGE, AgentContext
from .repair import _is_test_path, apply_edits

FIXABLE = {"static_analysis", "secret"}
SERIOUS = (Severity.critical, Severity.high)

SYSTEM = """You are the Repair agent fixing security findings that real scanners reported in this
repository. Produce the smallest safe change for each listed finding.

Rules:
- Fix only the listed findings. Do not refactor, rename, reformat or touch unrelated code. Do not add
  dependencies. Never edit test files.
- Each edit replaces `original_snippet` (copied EXACTLY from the file, including indentation, unique in
  the file — include surrounding lines if needed) with `replacement_snippet`.
- The code you see is secret-redacted: [REDACTED_SECRET] stands for a hidden value. Copy that marker
  unchanged inside original_snippet when the line contains it, but NEVER put it in a replacement.
- Hard-coded secrets: replace the value with a read from an environment variable that keeps the same
  name (e.g. os.environ.get("AWS_SECRET_ACCESS_KEY")), importing os if needed. Do not invent values.
- Keep behaviour for legitimate callers (e.g. use parameterised SQL queries, shell=False with an
  argument list, yaml.safe_load, a safe serialisation format, or path checks).
- If a finding cannot be fixed safely in code, leave it out of the edits and say why in skipped.
- In follow_ups list actions a human must take outside the code (for a leaked secret: rotate it).
Explain every fix."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE


class FixNote(BaseModel):
    finding_id: str
    note: str


class SkipNote(BaseModel):
    finding_id: str
    reason: str


class RemediationDraft(BaseModel):
    summary: str
    edits: list[FileEditDraft]
    fixes: list[FixNote] = Field(default_factory=list)
    skipped: list[SkipNote] = Field(default_factory=list)
    follow_ups: list[str] = Field(default_factory=list)
    risk_notes: list[str] = Field(default_factory=list)


def select_targets(report: SecurityReport, limit: int) -> list[SecurityFinding]:
    """The most severe findings that a code edit can fix: code vulnerabilities and exposed secrets,
    outside test files, not judged likely false positives by triage."""
    order = list(Severity)
    keep = [f for f in report.findings
            if f.category in FIXABLE and f.file_path and not _is_test_path(f.file_path) and not f.introduced_by_patch
            and not (f.ai_assessment and f.ai_assessment.verdict == "likely_false_positive")
            and f.severity in (Severity.critical, Severity.high, Severity.medium)]
    keep.sort(key=lambda f: (order.index(f.severity), f.explanation is None, f.file_path or ""))
    # Spread the fixes: the most severe finding of each file first, then the rest by severity.
    first: list[SecurityFinding] = []
    seen: set[str | None] = set()
    for f in keep:
        if f.file_path not in seen:
            first.append(f)
            seen.add(f.file_path)
    picked = first + [f for f in keep if f not in first]
    return picked[: max(0, limit)]


def _key(f: SecurityFinding) -> tuple:
    return (f.scanner, f.rule_id, f.file_path)


def _target(f: SecurityFinding) -> RemediationTarget:
    return RemediationTarget(finding_id=f.id, title=f.title, scanner=f.scanner, rule_id=f.rule_id, category=f.category,
                             file_path=f.file_path, line=f.line, severity=f.severity)


def _prompt(ctx: AgentContext, targets: list[SecurityFinding]) -> str:
    parts, files = [], []
    for f in targets:
        src = ctx.index.resolve(f.file_path) if f.file_path else None
        fn = enclosing_function(src.text, f.line) if src and src.text and f.line and f.file_path.endswith(".py") else None
        how = f.explanation.how_to_fix if f.explanation else ""
        parts.append(f"finding_id={f.id} severity={f.severity} scanner={f.scanner} rule={f.rule_id} category={f.category}\n"
                     f"location={f.file_path}:{f.line}{' in ' + fn + '()' if fn else ''}\ntitle={f.title}\n"
                     f"description={f.description[:500]}" + (f"\nsuggested fix (earlier analysis): {how}" if how else "") + "\n"
                     + untrusted(f.file_path, ctx.index.excerpt(f.file_path, f.line or 1, f.line or 1, context=4)))
        if f.file_path not in files:
            files.append(f.file_path)
    for path in files[:4]:
        src = ctx.index.resolve(path)
        if src and src.text is not None:
            parts.append(f"Full current content of {path} (secret-redacted; copy snippets exactly):\n" + untrusted(path, redact(src.text[:40000])[0]))
    return "Security findings to fix:\n\n" + "\n\n".join(parts)


def _tests(ctx: AgentContext, work: Path, baseline: TestRun | None) -> tuple[TestRun | None, TestRun | None]:
    """(baseline, after). Reuses the job's baseline run when it has one."""
    if ctx.backend.name == "blocked":
        return baseline, None
    stubs = ctx.index.facts.third_party_imports
    timeout = ctx.settings.sandbox_timeout_seconds
    if baseline is None or baseline.status != "completed":
        baseline = run_pytest(ctx.backend, ctx.workspace.fresh_copy("security-baseline"), "baseline (before security fixes)", timeout=timeout, stubs=stubs)
    if baseline.status != "completed":
        return baseline, None
    return baseline, run_pytest(ctx.backend, work, "after security fixes", timeout=timeout, stubs=stubs)


def _new_lint(ctx: AgentContext, work: Path, changed: list[str]) -> list[str]:
    py = [p for p in changed if p.endswith(".py")]
    if not py:
        return []
    existed = [p for p in py if (ctx.workspace.original / p).is_file()]
    before = run_ruff(ctx.workspace.original, existed)[1] if existed else []
    run, after = run_ruff(work, py)
    if run.status != "completed":
        return []
    key = lambda i: (i["file"], i["code"], i["message"])  # noqa: E731
    extra = Counter(map(key, after)) - Counter(map(key, before))
    return [f"{f}: {c} {m}" for (f, c, m) in extra.elements()]


def run(ctx: AgentContext, security: SecurityReport, baseline: TestRun | None) -> Remediation:
    picked = select_targets(security, ctx.settings.remediation_max_findings)
    if not picked:
        return Remediation(status="not_needed", summary="No code vulnerabilities or exposed secrets that PatchPilot can safely fix "
                           "automatically (dependency upgrades and suspicious-code findings are left for a human).")
    ok, why = ctx.llm.available()
    if not ok:
        return Remediation(status="unavailable", summary=why, targets=[_target(f) for f in picked])
    ctx.log("repair", f"security fixes: generating fixes for {len(picked)} finding(s)")
    try:
        draft = ctx.llm.structured(agent="repair", system=SYSTEM, messages=_prompt(ctx, picked), output_model=RemediationDraft, effort="high")
    except LLMError as e:
        return Remediation(status="unavailable", summary=f"Claude could not generate fixes: {e}", targets=[_target(f) for f in picked])

    work = ctx.workspace.fresh_copy("security-fixes")
    errors = apply_edits(ctx, RepairDraft(summary=draft.summary, intended_behaviour="", edits=draft.edits, why_minimal="",
                                          risk_notes=draft.risk_notes), work)
    changes = diff_trees(ctx.workspace.original, work)
    diff = combined_diff(changes)
    red = redact(diff)[0]
    rem = Remediation(
        status="failed", summary=draft.summary, edits=draft.edits, diff=red, apply_errors=errors,
        redacted_lines=sum(1 for ln in red.splitlines() if REDACTED in ln and not ln.startswith(("+++", "---"))),
        files_changed=[c.path for c in changes], lines_added=sum(c.added for c in changes), lines_removed=sum(c.removed for c in changes),
        targets=[_target(f) for f in picked],
    )
    notes = {n.finding_id: n.note for n in draft.fixes}
    skips = {s.finding_id: s.reason for s in draft.skipped}
    for t in rem.targets:
        t.fix_note = notes.get(t.finding_id) or (f"Not attempted: {skips[t.finding_id]}" if t.finding_id in skips else "")
    ctx.log("repair", f"security fixes: {len(draft.edits)} edit(s), +{rem.lines_added}/-{rem.lines_removed} in {rem.files_changed}; errors={errors}")
    if not changes:
        rem.reasons.append("The proposed fixes could not be applied, so nothing changed." if errors else "Claude proposed no change.")
        return rem

    # Agent 5: every scanner and the tests on the fixed copy, at the same time.
    ctx.log("verification", "security fixes: re-running all scanners and the test suite on the fixed copy")
    rescan = lambda: run_security_scan(work, build_index(work, max_file_kb=ctx.settings.max_index_file_kb), ctx.settings,  # noqa: E731
                                       include_osv=ctx.settings.osv_enabled)
    if ctx.settings.semgrep_max_memory_mb:  # small host (memory-capped Semgrep): one heavy step at a time
        after = rescan()
        rem.tests_before, rem.tests_after = _tests(ctx, work, baseline)
    else:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="remediation") as pool:
            scan_f, tests_f = pool.submit(rescan), pool.submit(_tests, ctx, work, baseline)
            after = scan_f.result()
            rem.tests_before, rem.tests_after = tests_f.result()
    rem.new_lint_issues = _new_lint(ctx, work, rem.files_changed)
    _compare(rem, security, after)
    _decide(rem, draft)
    ctx.log("verification", f"security fixes: {rem.status} — {rem.summary}")
    return rem


def _compare(rem: Remediation, before: SecurityReport, after: SecurityReport) -> None:
    rescanned = {s.name for s in after.scanners if s.status == "completed"}
    run_name = {"secrets": "patchpilot-secrets", "suspicious": "patchpilot-suspicious"}
    b_count, a_count = Counter(map(_key, before.findings)), Counter(map(_key, after.findings))
    slots = {k: max(0, b_count[k] - a_count[k]) for k in b_count}
    for t in rem.targets:
        k = (t.scanner, t.rule_id, t.file_path)
        if run_name.get(t.scanner, t.scanner) in rescanned and slots.get(k, 0) > 0:
            t.outcome, slots[k] = "no_longer_reported", slots[k] - 1
        elif t.fix_note.startswith("Not attempted"):
            t.outcome = "not_attempted"
        else:
            t.outcome = "still_reported"
    rem.also_cleared = sum(v for v in slots.values())
    seen = {(f.scanner, f.rule_id, f.file_path, f.line) for f in before.findings}
    extra = {k: a_count[k] - b_count.get(k, 0) for k in a_count if a_count[k] > b_count.get(k, 0)}
    for f in after.findings:
        k = _key(f)
        if extra.get(k, 0) > 0 and (f.scanner, f.rule_id, f.file_path, f.line) not in seen:
            f.introduced_by_patch = True
            rem.introduced.append(f)
            extra[k] -= 1
    no_lint = lambda fs: [f for f in fs if f.category != "lint"]  # noqa: E731
    rem.findings_before, rem.findings_after_count = len(before.findings), len(after.findings)
    rem.severity_before = dict(Counter(f.severity.value for f in no_lint(before.findings)))
    rem.severity_after = dict(Counter(f.severity.value for f in no_lint(after.findings)))
    rem.findings_after, rem.scanners_after = after.findings, after.scanners


def _decide(rem: Remediation, draft: RemediationDraft) -> None:
    cleared = [t for t in rem.targets if t.outcome == "no_longer_reported"]
    ta, tb = rem.tests_after, rem.tests_before
    if ta and tb and ta.status == "completed":
        rem.new_failures = sorted(tb.passing_ids & ta.failing_ids)
    serious_new = [f for f in rem.introduced if f.severity in SERIOUS]
    rem.follow_ups = list(draft.follow_ups)
    secrets = [t for t in cleared if t.category == "secret"]
    if secrets and not any(w in " ".join(rem.follow_ups).lower() for w in ("rotat", "revoke")):
        where = ", ".join(f"{t.file_path}:{t.line}" for t in secrets)
        rem.follow_ups.append(f"Rotate or revoke the exposed secret value(s) ({where}): removing them from the code does not revoke them, "
                              "and they stay in the git history.")
    if rem.new_failures:
        rem.status = "failed"
        rem.reasons.append(f"The fixes broke {len(rem.new_failures)} test(s) that passed before.")
    elif serious_new:
        rem.status = "failed"
        rem.reasons.append(f"The fixes introduced {len(serious_new)} new high/critical finding(s).")
    elif not cleared:
        rem.status = "failed"
        rem.reasons.append("The scanners still report every targeted finding after the fixes.")
    elif not ta or ta.status != "completed":
        rem.status = "untested"
        rem.reasons.append("Tests were not run on the fixed copy " + (f"({ta.blocked_reason or ta.status})" if ta else
                           "(execution not allowed or no working test suite)") + ", so only the scanners checked these fixes.")
    elif len(cleared) < len(rem.targets) or rem.apply_errors:
        rem.status = "partial"
        rem.reasons.append(f"{len(cleared)} of {len(rem.targets)} targeted finding(s) are no longer reported; the rest still need attention.")
    else:
        rem.status = "verified"
        rem.reasons.append("Every targeted finding is no longer reported by its scanner, and the test suite shows no regressions. "
                           "Verified against these checks only — review the change before merging.")
    minor_new = [f for f in rem.introduced if f.severity not in SERIOUS]
    if minor_new and rem.status != "failed":
        rem.reasons.append(f"The re-scan also reports {len(minor_new)} new lower-severity finding(s) in the changed code "
                           f"({', '.join(sorted({f.rule_id for f in minor_new}))}); review them below.")
    tests = f"tests {ta.passed}/{ta.passed + ta.failed + ta.errors} passing" if ta and ta.status == "completed" else "tests not run"
    rem.summary = (f"{len(cleared)} of {len(rem.targets)} targeted finding(s) no longer reported · {tests}"
                   + (f" · {len(rem.introduced)} new finding(s)" if rem.introduced else "")
                   + (f". {draft.summary}" if draft.summary else ""))
