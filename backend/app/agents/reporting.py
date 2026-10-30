"""Agent 6 — Evidence & Reporting.

The report body is assembled deterministically from stored results, with every section labelled
as tool evidence or model interpretation. Claude writes only the executive summary and next
actions, from a compact JSON of those same results.
"""

from __future__ import annotations

import json

from ..core.models import Job, Report, ReportNarrative, Severity, utcnow
from ..llm.client import LLMError
from .base import PLAIN_LANGUAGE, AgentContext

SYSTEM = """You are the Evidence & Reporting agent. Write a short executive summary, the key risks,
and concrete next actions for the developer, using ONLY the facts in the provided JSON. Distinguish
tool-verified results from model hypotheses. Never say the repository is bug-free or fully secure;
say what was checked and what was not."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE

STATUS_HEADLINES = {
    "verified": "Patch verified against the configured checks",
    "failed": "Proposed patch failed verification",
    "incomplete": "Verification incomplete",
    "blocked": "Verification blocked",
    "inconclusive": "Verification inconclusive",
}


def _facts(job: Job) -> dict:
    r = job.results
    d: dict = {"analysis_type": job.analysis_type, "bug_description": job.bug_description[:1500]}
    if r.repo:
        d["repo"] = {"languages": [x.language for x in r.repo.facts.languages[:5]], "frameworks": r.repo.facts.frameworks,
                     "overview": r.repo.narrative.overview if r.repo.narrative else None}
    if r.diagnosis:
        d["bugs"] = [{"title": f.title, "file": f.file_path, "lines": [f.line_start, f.line_end], "status": f.status,
                      "severity": f.severity, "confidence": f.confidence} for f in r.diagnosis.findings]
        d["diagnosis_conclusive"] = r.diagnosis.conclusive
        d["bug_source"] = ("discovered by PatchPilot's autonomous code audit (no user bug report); a finding only counts as "
                           "confirmed if the reproduction test failed on the original code") if r.diagnosis.mode == "discovery" else "user bug report"
    if r.reproduction:
        d["reproduction"] = {"status": r.reproduction.status, "attempts": r.reproduction.attempts}
    if r.patches:
        p = r.patches[-1]
        d["final_patch"] = {"attempt": p.attempt, "files": p.files_changed, "added": p.lines_added, "removed": p.lines_removed, "summary": p.summary}
        d["patch_attempts"] = len(r.patches)
    if r.verification:
        v = r.verification
        d["verification"] = {"status": v.status, "bug": v.original_bug_status, "reasons": v.reasons, "new_failures": v.new_failures[:10],
                             "patch_security_findings": len(v.patch_security_findings), "not_performed": v.checks_not_performed}
    if r.security:
        sev = {s.value: sum(1 for f in r.security.findings if f.severity == s) for s in Severity}
        d["security"] = {"by_severity": sev, "scanners": {s.name: s.status for s in r.security.scanners},
                         "top": [f"{f.severity}: {f.title} ({f.file_path}:{f.line})" for f in r.security.findings[:8]],
                         "introduced_by_patch": [f"{f.severity}: {f.title}" for f in r.security.findings if f.introduced_by_patch][:10]}
        triaged = [f for f in r.security.findings if f.ai_assessment]
        if r.security.malware:
            m = r.security.malware
            d["security"]["malware_check"] = {"verdict": m.overall, "summary": m.summary, "indicators_matched": m.indicators_matched,
                                              "antivirus_signature_scan": m.signature_scan, "ai_review": m.ai_status}
        d["security"]["ai_triage"] = {
            "status": r.security.triage_status, "findings_triaged": len(triaged), "of_total": len(r.security.findings),
            "verdicts": {v: sum(1 for f in triaged if f.ai_assessment.verdict == v) for v in ("likely_true_positive", "likely_false_positive", "needs_review")},
            "summary": r.security.triage_summary[:1500],
        }
    if r.patch_scope:
        d["patch_scope"] = {"assessment": r.patch_scope.overall_assessment, "findings": [f"{f.category}: {f.observation}" for f in r.patch_scope.findings[:8]]}
    if r.supplied_patch_scope:
        sp = r.supplied_patch_scope
        d["supplied_patch_review"] = {"assessment": sp.overall_assessment, "findings": [f"{f.category}: {f.observation}" for f in sp.findings[:8]],
                                      "introduced_security_findings": [f"{f.severity}: {f.title}" for f in sp.introduced_security[:8]]}
    stages = {k: v.status for k, v in job.agents.items()}
    d["stages"] = stages
    return d


def build_markdown(job: Job, report: Report) -> str:
    r = job.results
    L: list[str] = [f"# PatchPilot AI Report — {job.project_name}", "",
                    f"*Generated {report.generated_at} · job `{job.id}` · source `{job.source}` · analysis `{job.analysis_type}` · model `{job.model}` · Claude mode `{job.llm_mode}` · execution backend `{job.execution_backend}`*", "",
                    f"## {report.headline}", "", f"**Overall status:** {report.overall_status}", ""]
    if job.llm_mode == "replay":
        L += ["> **Note:** AI reasoning in this run was replayed from a recording of an earlier real run. Test execution and scanners ran live.", ""]
    if report.narrative:
        L += ["## Executive summary *(AI-written from the evidence below)*", "", report.narrative.executive_summary, ""]
    L += ["## Pipeline stages", "", "| Agent | Status | Notes |", "|---|---|---|"]
    for a in job.agents.values():
        L.append(f"| {a.title} | {a.status} | {a.message.replace('|', '/')[:160]} |")
    L.append("")
    if job.bug_description:
        L += ["## Reported problem", "", "```text", job.bug_description[:3000], "```", ""]
    if r.repo:
        f = r.repo.facts
        L += ["## Repository *(tool facts)*", "",
              f"- Files indexed: {f.indexed_files}/{f.total_files} · lines: {f.total_lines}",
              f"- Languages: {', '.join(f'{x.language} ({x.files})' for x in f.languages[:6])}",
              f"- Frameworks: {', '.join(f.frameworks) or 'none detected'} · tests: {f.test_framework or 'none'} ({len(f.test_files)} files)",
              f"- Manifests: {', '.join(f.manifests) or 'none'}"]
        for sf in f.special_files[:10]:
            L.append(f"- Special handling: `{sf.path}` — {sf.reason}")
        if r.repo.narrative:
            L += ["", f"**Overview (AI):** {r.repo.narrative.overview}"]
        L.append("")
    if r.diagnosis:
        if r.diagnosis.mode == "discovery":
            L += ["## Bugs discovered by autonomous code audit *(no bug report given — AI findings, locations verified by PatchPilot)*", "",
                  "Only the primary finding is reproduced and repaired; it is patched only if a generated test first fails on the original code.", ""]
        else:
            L += ["## Bug findings *(AI investigation, locations verified by PatchPilot)*", ""]
        for b in r.diagnosis.findings:
            L += [f"### {b.title}", f"- Location: `{b.file_path}` lines {b.line_start}-{b.line_end}" + (f" (`{b.function_name}`)" if b.function_name else ""),
                  f"- Status: **{b.status}** · severity {b.severity} · confidence {b.confidence} · location verified: {b.location_verified}",
                  f"- Root cause: {b.root_cause_hypothesis}"]
            L += [f"- Evidence: {e}" for e in b.evidence[:5]]
            L += [f"- Validation note: {n}" for n in b.validation_notes]
            if b.code_excerpt:
                L += ["", "```python", b.code_excerpt, "```"]
            L.append("")
    if r.reproduction:
        rp = r.reproduction
        L += ["## Reproduction *(test executed by PatchPilot)*", "", f"- Status: **{rp.status}** after {rp.attempts} attempt(s)"]
        if rp.baseline_run:
            b = rp.baseline_run
            L.append(f"- Baseline suite: {b.status} — {b.passed} passed, {b.failed} failed, {b.errors} errors, {b.skipped} skipped")
        if rp.repro_run:
            L.append(f"- Reproduction test on original code: {rp.repro_run.passed} passed, {rp.repro_run.failed} failed, {rp.repro_run.errors} errors")
        L += [f"- {n}" for n in rp.notes]
        if rp.test_code:
            L += ["", f"`{rp.test_path}` (AI-generated test):", "```python", rp.test_code[:4000], "```"]
        L.append("")
    for p in r.patches:
        L += [f"## Patch attempt {p.attempt} *(AI-proposed, applied only to a disposable copy)*", "", p.summary,
              f"- Files: {', '.join(p.files_changed) or 'none'} · +{p.lines_added} / -{p.lines_removed}",
              f"- Why minimal: {p.why_minimal}"]
        L += [f"- Apply error: {e}" for e in p.apply_errors]
        if p.diff:
            L += ["", "```diff", p.diff[:8000], "```"]
        L.append("")
    if r.verification:
        v = r.verification
        L += ["## Verification *(tool evidence)*", "", f"- **Status: {v.status}** · original bug: {v.original_bug_status}"]
        L += [f"- {x}" for x in v.reasons]
        if v.patched_run:
            L.append(f"- Suite after patch: {v.patched_run.passed} passed, {v.patched_run.failed} failed, {v.patched_run.errors} errors")
        L += [f"- New failure: `{x}`" for x in v.new_failures[:15]]
        L += [f"- Fixed test: `{x}`" for x in v.fixed_tests[:15]]
        L += [f"- New lint issue: {x}" for x in v.new_lint_issues[:10]]
        L += [f"- Dependency change: {x}" for x in v.dependency_changes]
        L += [f"- Patch security: {f.severity} {f.title} at {f.file_path}:{f.line}" for f in v.patch_security_findings]
        L += ["", "Checks performed:"] + [f"- {c}" for c in v.checks_performed]
        if v.interpretation:
            L += ["", f"**Interpretation (AI):** {v.interpretation.assessment}"]
        L.append("")
    if r.security:
        s = r.security
        L += ["## Security *(scanner results; AI triage where noted)*", "", "| Scanner | Version | Status | Findings | Note |", "|---|---|---|---|---|"]
        L += [f"| {x.name} | {x.version or '-'} | {x.status} | {x.findings} | {x.message[:80]} |" for x in s.scanners]
        L.append("")
        for f in s.findings[:60]:
            loc = f"`{f.file_path}:{f.line}`" if f.line else f"`{f.file_path}`"
            ai = f" — AI: {f.ai_assessment.verdict} ({f.ai_assessment.priority}): {f.ai_assessment.rationale}" if f.ai_assessment else ""
            L.append(f"- **{f.severity.upper()}** [{f.scanner}/{f.rule_id}] {f.title} at {loc}: {f.description[:240]}{ai}")
        if len(s.findings) > 60:
            L.append(f"- … {len(s.findings) - 60} more findings in the JSON report")
        if s.triage_summary:
            L += ["", f"**Triage summary (AI):** {s.triage_summary}"]
        if s.malware:
            m = s.malware
            verdict = {"no_malicious_indicators": "No malicious indicators found", "suspicious_needs_review": "Suspicious — needs human review",
                       "likely_malicious": "Likely malicious"}[m.overall]
            L += ["", f"### Malware check: **{verdict}** *(static indicators + AI review: {m.ai_status}; antivirus signatures: {m.signature_scan})*", "", m.summary]
            L += [f"- Matched indicator: {x}" for x in m.indicators_matched]
            by_id = {f.id: f for f in s.findings}
            for it in m.items:
                f = by_id.get(it.finding_id)
                if f:
                    L.append(f"- `{f.file_path}:{f.line}` {f.title} — **{it.verdict.replace('_', ' ')}**: {it.explanation}")
            L += [f"- Next step: {x}" for x in m.recommended_actions]
            L += [f"- Limitation: {x}" for x in m.limitations]
            L.append(f"- Checked for: {'; '.join(m.indicators_checked)}")
        L += ["", "_Suspicious-code findings are pattern matches, not confirmed malware. Absence of findings does not mean the code is secure._", ""]
    for ps in [x for x in (r.patch_scope, r.supplied_patch_scope) if x]:
        m = ps.metrics
        title = "your supplied patch" if ps.subject == "user_supplied_patch" else "PatchPilot's patch"
        L += [f"## Unnecessary patch detection — {title} *(detection only — no code was changed)*", "",
              f"- Subject: {ps.subject} · assessment: **{ps.overall_assessment}** · AI review: {ps.ai_status}",
              f"- {m.files_changed} files, +{m.lines_added}/-{m.lines_removed}, {m.functions_changed} functions changed; implicated: {', '.join(m.implicated_functions) or 'none identified'}"]
        if ps.summary:
            L.append(f"- Summary: {ps.summary}")
        for f in ps.findings:
            L += [f"### {f.category.replace('_', ' ').title()} — `{f.file_path}`" + (f" lines {f.line_start}-{f.line_end}" if f.line_start else ""),
                  f"- Observation: {f.observation}", f"- Reasoning: {f.reasoning}", f"- Could be justified because: {f.could_be_justified_because}",
                  f"- Recommendation: {f.recommendation}", f"- Confidence: {f.confidence} · {f.verification_status}"]
            L += [f"- Evidence: {e}" for e in f.evidence[:5]]
            L.append("")
        L += [f"- Introduced security finding: {f.severity} {f.title} ({f.file_path})" for f in ps.introduced_security]
        L += [f"- Limitation: {x}" for x in ps.limitations]
        L.append("")
    L += ["## Unresolved risks", ""] + ([f"- {x}" for x in report.unresolved_risks] or ["- None recorded"]) + [""]
    L += ["## Checks not performed", ""] + ([f"- {x}" for x in report.checks_not_performed] or ["- None recorded"]) + [""]
    if report.narrative:
        L += ["## Recommended next actions *(AI)*", ""] + [f"- {x}" for x in report.narrative.recommended_next_actions] + [""]
    L += ["---", "PatchPilot never modifies your original repository. Review and apply patches yourself. "
          "A verified status means the configured checks passed, not that the code is free of bugs or vulnerabilities."]
    return "\n".join(L)


def run(ctx: AgentContext, job: Job) -> Report:
    r = job.results
    v = r.verification
    if v:
        overall, headline = v.status.value, STATUS_HEADLINES[v.status.value]
    elif job.analysis_type in ("security_scan", "full_analysis"):
        n = len(r.security.findings) if r.security else 0
        label = "Full analysis" if job.analysis_type == "full_analysis" else "Security scan"
        overall, headline = "security_scan_completed", f"{label} completed — {n} security finding(s) to review"
    elif job.analysis_type == "patch_review":
        overall = r.patch_scope.overall_assessment if r.patch_scope else "incomplete"
        headline = f"Patch review: {overall.replace('_', ' ')}"
    else:
        overall = "diagnosis_" + ("conclusive" if r.diagnosis and r.diagnosis.conclusive else "inconclusive")
        headline = "Investigation completed" if r.diagnosis else "Investigation incomplete"

    unresolved: list[str] = []
    not_performed: list[str] = []
    if v:
        unresolved += [f"Regression: {x}" for x in v.new_failures[:10]]
        unresolved += [f"Patch security: {f.title} ({f.file_path}:{f.line})" for f in v.patch_security_findings]
        not_performed += v.checks_not_performed
        if v.interpretation:
            unresolved += v.interpretation.unresolved_issues
    if r.security:
        unresolved += [f"{f.severity}: {f.title} at {f.file_path}:{f.line}" for f in r.security.findings if f.severity in (Severity.critical, Severity.high)][:15]
        not_performed += [f"{s.name}: {s.status}{' — ' + s.message if s.message else ''}" for s in r.security.scanners if s.status not in ("completed",)]
    if r.diagnosis:
        unresolved += [f"Unconfirmed bug hypothesis: {f.title}" for f in r.diagnosis.findings if f.status != "confirmed"][:5]
    for a in job.agents.values():
        if a.status in ("blocked", "failed", "skipped"):
            not_performed.append(f"{a.title}: {a.status}{' — ' + a.message if a.message else ''}")
    report = Report(generated_at=utcnow(), headline=headline, overall_status=overall,
                    unresolved_risks=list(dict.fromkeys(unresolved)), checks_not_performed=list(dict.fromkeys(not_performed)))

    ok, why = ctx.llm.available()
    if ok:
        try:
            report.narrative = ctx.llm.structured(agent="reporting", system=SYSTEM, messages="Analysis results (JSON):\n" + json.dumps(_facts(job), indent=1, default=str)[:30000],
                                                  output_model=ReportNarrative, effort="low")
            report.narrative_status = "completed"
        except LLMError as e:
            report.narrative_status = f"failed: {e}"
    else:
        report.narrative_status = f"unavailable: {why}"
    report.markdown = build_markdown(job, report)
    return report
