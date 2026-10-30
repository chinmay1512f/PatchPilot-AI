"""Unnecessary Patch Detection — DETECTION AND REPORTING ONLY.

Deterministic evidence (which functions changed, which ones the bug actually implicates, new
imports/dependencies/definitions, duplicated blocks, formatting-only hunks) is computed from the
real files. Claude then judges whether each change looks necessary, explicitly considering
legitimate reasons (security, correctness, compatibility). Nothing here rewrites code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.models import (
    ChangedFunction,
    Confidence,
    Diagnosis,
    PatchScopeFinding,
    PatchScopeMetrics,
    PatchScopeReport,
    ScopeAssessmentDraft,
    new_id,
)
from ..ingest.indexer import normalize_rel
from ..llm.client import LLMError, untrusted
from ..tools.diffing import (
    FileChange,
    changed_function_names,
    combined_diff,
    dependency_changes,
    diff_trees,
    duplicated_blocks,
    enclosing_function,
    new_imports,
    read_tree_text,
)
from .base import PLAIN_LANGUAGE, AgentContext

SYSTEM = """You are PatchPilot's Unnecessary Patch Detection analyst. You REVIEW a code change and
report parts that may be broader than needed to fix the stated problem. You never write or
propose replacement code — the developer decides.

Rules:
- A large change is NOT automatically unnecessary. Before flagging, consider whether it is needed for
  correctness, security, compatibility, maintainability or the stated requirement, and record that in
  could_be_justified_because.
- Never recommend removing code that is part of a security fix.
- Base findings on the diff and the deterministic evidence provided; cite real file paths and line
  numbers from the new version of the file.
- If the bug description or original version is missing, say confidence is limited.
- Recommendations should say what to review (e.g. "review whether the fix can be limited to
  calculate_total"), not provide code."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE

_TB_PY = re.compile(r'File "([^"]+)", line (\d+), in (\w+)')
_TB_PYTEST = re.compile(r"([\w./\\-]+\.py):(\d+): in (\w+)")
_IDENT = re.compile(r"\b([a-z_][a-z0-9_]{2,}|[A-Z][A-Za-z0-9]{2,})\b")
_MANIFESTS = re.compile(r"(requirements.*\.txt|pyproject\.toml|package\.json|setup\.py|setup\.cfg|Pipfile)$")


def implicated_functions(changes: list[FileChange], original_texts: dict[str, str], bug: str,
                         diagnosis: Diagnosis | None, failure_text: str) -> tuple[set[str], set[str], list[str]]:
    names: set[str] = set()
    files: set[str] = set()
    signals: list[str] = []
    if diagnosis:
        for f in diagnosis.findings:
            if not f.location_verified:
                continue
            files.add(f.file_path)
            fn = f.function_name or enclosing_function(original_texts.get(f.file_path, ""), f.line_start)
            if fn:
                names.add(fn.split(".")[-1])
                signals.append(f"diagnosis cites {f.file_path}:{f.line_start} in {fn}")
    for rx in (_TB_PY, _TB_PYTEST):
        for m in rx.finditer(failure_text or ""):
            fn = m.group(3)
            if not fn.startswith("test") and fn != "<module>":
                names.add(fn)
                signals.append(f"failing test traceback passes through {fn}")
    changed_names = {n.split(".")[-1] for c in changes for n in changed_function_names(c)}
    for tok in set(_IDENT.findall(bug or "")):
        if tok in changed_names:
            names.add(tok)
            signals.append(f"bug description mentions {tok}")
    return names, files, sorted(set(signals))


def compute_metrics(ctx_root_original: Path, changes: list[FileChange], bug: str, diagnosis: Diagnosis | None, failure_text: str) -> tuple[PatchScopeMetrics, list[str]]:
    original_texts = {c.path: c.old_text for c in changes}
    implicated, implicated_files, signals = implicated_functions(changes, original_texts, bug, diagnosis, failure_text)
    corpus = {p: t for p, t in read_tree_text(ctx_root_original).items() if p.endswith(".py")}
    changed: list[ChangedFunction] = []
    imports, defs, dups = [], [], []
    formatting = 0
    for c in changes:
        formatting += c.formatting_only_hunks
        imports += new_imports(c)
        if c.path.endswith(".py"):
            dups += duplicated_blocks(c, corpus | {c.path: c.new_text})
        for name, info in changed_function_names(c).items():
            short = name.split(".")[-1]
            changed.append(ChangedFunction(file_path=c.path, name=name, kind=info["kind"], lines_changed=info["lines"],
                                           implicated=short in implicated, change_ratio=info["ratio"]))
            if info["kind"] == "added":
                defs.append(f"{c.path}: new {'class/method' if '.' in name else 'function'} {name}")
        for line in (c.new_text.splitlines() if c.status != "removed" else []):
            m = re.match(r"^class\s+(\w+)", line)
            if m and f"class {m.group(1)}" not in c.old_text:
                defs.append(f"{c.path}: new class {m.group(1)}")
    unrelated = [f"{cf.file_path}::{cf.name}" for cf in changed if not cf.implicated] if implicated else []
    metrics = PatchScopeMetrics(
        files_changed=len(changes), lines_added=sum(c.added for c in changes), lines_removed=sum(c.removed for c in changes),
        functions_changed=len(changed), implicated_functions=sorted(implicated), unrelated_function_candidates=unrelated,
        new_imports=imports, new_dependencies=dependency_changes(changes), new_definitions=sorted(set(defs)),
        duplicated_blocks=sorted(set(dups)), formatting_only_hunks=formatting, changed_functions=changed,
    )
    return metrics, signals


def _heuristic_findings(metrics: PatchScopeMetrics, changes: list[FileChange]) -> list[PatchScopeFinding]:
    out: list[PatchScopeFinding] = []

    def add(path, cat, obs, reason, rec, conf=Confidence.low, ev=()):
        out.append(PatchScopeFinding(id=new_id("scope"), file_path=path, category=cat, observation=obs, reasoning=reason,
                                     recommendation=rec, confidence=conf, could_be_justified_because="not assessed (heuristic only)",
                                     evidence=list(ev)))

    for cand in metrics.unrelated_function_candidates:
        path, fn = cand.split("::", 1)
        add(path, "unrelated_function", f"{fn} was changed but is not implicated by the diagnosis or failing test.",
            "No signal links this function to the reported bug.", f"Review whether the change to {fn} is required.")
    for dep in metrics.new_dependencies:
        add(dep.split(" in ")[-1].split(" from ")[-1], "new_dependency", dep, "New dependencies increase attack surface and maintenance.",
            "Confirm the dependency is required for the fix.", Confidence.medium)
    for d in metrics.duplicated_blocks:
        add(d.split(":")[0], "duplicated_logic", d, "Added lines duplicate existing logic.", "Review whether existing code could be reused.")
    if metrics.formatting_only_hunks:
        path = next((c.path for c in changes if c.formatting_only_hunks), changes[0].path if changes else "")
        add(path, "formatting_noise", f"{metrics.formatting_only_hunks} hunk(s) only change formatting/whitespace/quotes.",
            "Formatting-only changes make the functional change harder to review.", "Consider separating formatting changes from the fix.")
    return out


def analyze(ctx: AgentContext, original_dir: Path, modified_dir: Path, subject: str, bug: str,
            diagnosis: Diagnosis | None = None, failure_text: str = "", exclude: set[str] | None = None) -> PatchScopeReport:
    """``exclude`` removes files PatchPilot itself added for verification (the reproduction test)."""
    changes = [c for c in diff_trees(original_dir, modified_dir) if c.path not in (exclude or set())]
    metrics, signals = compute_metrics(original_dir, changes, bug, diagnosis, failure_text)
    report = PatchScopeReport(subject=subject, metrics=metrics, diff=combined_diff(changes)[:200_000])
    if not changes:
        report.overall_assessment = "insufficient_information"
        report.summary = "No differences found between the original and modified versions."
        return report
    if not bug.strip():
        report.limitations.append("No bug description was provided, so relatedness can only be inferred from the code itself; confidence is limited.")
    if not metrics.implicated_functions:
        report.limitations.append("No independent signal (diagnosis, failing traceback, or bug text) identified which functions the bug involves.")
    changed_paths = {c.path for c in changes}

    ok, why = ctx.llm.available()
    if not ok:
        report.findings = _heuristic_findings(metrics, changes)
        report.ai_status = "unavailable"
        report.limitations.append(f"AI review unavailable ({why}); findings are deterministic heuristics with low confidence.")
        report.overall_assessment = "possibly_broader_than_needed" if report.findings else "insufficient_information"
        report.summary = f"{len(report.findings)} heuristic observation(s)."
        return report

    evidence = metrics.model_dump()
    evidence["relatedness_signals"] = signals
    diag = f"Diagnosis summary (model-generated): {diagnosis.summary}" if diagnosis else "No diagnosis available."
    prompt = (
        f"Subject: {'a patch generated by PatchPilot' if subject == 'patchpilot_patch' else 'a patch supplied by the user (e.g. from an AI coding tool)'}\n\n"
        "Stated problem:\n" + untrusted("bug_report", bug or "(none provided)") + f"\n\n{diag}\n\n"
        "Deterministic change evidence (tool output):\n" + json.dumps(evidence, indent=1)[:15000]
        + "\n\nUnified diff:\n" + untrusted("diff", report.diff[:60000])
    )
    try:
        draft = ctx.llm.structured(agent="verification", system=SYSTEM, messages=prompt, output_model=ScopeAssessmentDraft, effort="high")
    except LLMError as e:
        report.findings = _heuristic_findings(metrics, changes)
        report.ai_status = f"failed: {e}"
        report.overall_assessment = "possibly_broader_than_needed" if report.findings else "insufficient_information"
        return report

    for d in draft.findings:
        path = normalize_rel(d.file_path)
        if path not in changed_paths:
            report.limitations.append(f"Dropped an AI finding referencing an unchanged file: {d.file_path}")
            continue
        ev = [x for x in metrics.new_imports + metrics.new_dependencies + metrics.new_definitions + metrics.duplicated_blocks if path in x]
        ev += [f"{cf.name}: {cf.kind}, {cf.lines_changed} lines changed ({int(cf.change_ratio * 100)}% of function), implicated={cf.implicated}"
               for cf in metrics.changed_functions if cf.file_path == path]
        report.findings.append(PatchScopeFinding(id=new_id("scope"), **{**d.model_dump(), "file_path": path}, evidence=ev[:8]))
    report.overall_assessment = draft.overall_assessment
    report.summary = draft.summary
    report.limitations += draft.limitations
    report.ai_status = "completed"
    return report
