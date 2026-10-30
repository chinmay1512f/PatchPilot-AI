"""Agent 4 — Repair.

Claude proposes search/replace edits. They are applied only to a disposable copy, never to the
uploaded original. Edits to test files, edits outside the repository and ambiguous or missing
snippets are rejected. The diff shown to the user is computed from the files on disk, not
taken from the model.
"""

from __future__ import annotations

from pathlib import Path

from ..core.models import (
    Diagnosis,
    PatchProposal,
    RepairDraft,
    Reproduction,
    VerificationResult,
    new_id,
)
from ..ingest.indexer import normalize_rel
from ..llm.client import untrusted
from ..tools.diffing import combined_diff, diff_trees
from .base import PLAIN_LANGUAGE, AgentContext

SYSTEM = """You are the Repair agent. Propose the smallest correct change that fixes the diagnosed
defect while preserving existing behaviour.

Rules:
- Each edit replaces `original_snippet` (copied EXACTLY from the file, including indentation, and
  unique within the file — include surrounding lines if needed) with `replacement_snippet`.
- Do not refactor, rename, reformat or touch unrelated code. Do not add dependencies.
- Never edit test files to make tests pass, and never weaken assertions.
- A larger change is acceptable only when correctness or security genuinely requires it — explain why in why_minimal.
- Explain the purpose of every edit."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE


def _is_test_path(path: str) -> bool:
    p = Path(path)
    return p.name.startswith("test_") or p.name.endswith("_test.py") or p.name == "conftest.py" or "tests" in p.parts or "test" in p.parts


def _prompt(ctx: AgentContext, bug: str, diagnosis: Diagnosis, repro: Reproduction | None, history: list[tuple[PatchProposal, VerificationResult | None]]) -> str:
    primary = next((f for f in diagnosis.findings if f.id == diagnosis.primary_finding_id), None)
    parts = ["Bug report:\n" + untrusted("bug_report", bug), f"Diagnosis summary: {diagnosis.summary}"]
    files: list[str] = []
    for f in diagnosis.findings:
        if f.location_verified:
            parts.append(f"- [{f.status}] {f.title} ({f.file_path}:{f.line_start}-{f.line_end}): {f.root_cause_hypothesis}")
            if f.file_path not in files:
                files.append(f.file_path)
    if primary:
        parts.append(f"PRIMARY defect to fix: {primary.title} at {primary.file_path}:{primary.line_start}-{primary.line_end}")
    if repro and repro.test_code:
        parts.append("Reproduction test (it must pass after your fix; do not edit it):\n" + untrusted(repro.test_path or "repro", repro.test_code))
        if repro.repro_run:
            parts.append("Its actual failure output on the current code (tool output):\n" + untrusted("pytest", repro.repro_run.output_tail[-2500:]))
    for path in files[:4]:
        f = ctx.index.resolve(path)
        if f and f.text is not None:
            parts.append(f"Full current content of {path} (no line numbers; copy snippets exactly):\n" + untrusted(path, f.text[:40000]))
    for prev, ver in history:
        fb = [f"Previous attempt #{prev.attempt} summary: {prev.summary}"]
        if prev.apply_errors:
            fb.append("It could not be applied: " + "; ".join(prev.apply_errors))
        if ver:
            fb.append(f"Verification status: {ver.status}. Reasons: {'; '.join(ver.reasons)}")
            if ver.repro_after_patch:
                fb.append("Reproduction test output after that patch:\n" + ver.repro_after_patch.output_tail[-1500:])
            if ver.new_failures:
                fb.append("Newly failing tests: " + ", ".join(ver.new_failures[:10]))
        parts.append(untrusted(f"attempt-{prev.attempt}-feedback", "\n".join(fb)))
    return "\n\n".join(parts)


def apply_edits(ctx: AgentContext, draft: RepairDraft, workdir: Path) -> list[str]:
    errors: list[str] = []
    root = workdir.resolve()
    for i, e in enumerate(draft.edits, 1):
        rel = normalize_rel(e.file_path)
        target = (root / rel).resolve()
        if not target.is_relative_to(root) or ".patchpilot" in target.parts:
            errors.append(f"edit {i}: path {e.file_path!r} is outside the repository")
            continue
        if _is_test_path(rel):
            errors.append(f"edit {i}: modifying test file {rel!r} is not allowed")
            continue
        if not target.is_file():
            errors.append(f"edit {i}: file {rel!r} does not exist (creating files is not allowed)")
            continue
        with open(target, encoding="utf-8", newline="") as fh:  # keep CRLF intact
            text = fh.read()
        newline = "\r\n" if "\r\n" in text else "\n"
        text_n = text.replace("\r\n", "\n")
        old = e.original_snippet.replace("\r\n", "\n")
        count = text_n.count(old) if old else 0
        if count == 0 and old.strip():
            # Tolerate trailing-whitespace differences, replacing only the matched lines.
            lines = text_n.split("\n")
            want = [x.rstrip() for x in old.strip("\n").split("\n")]
            hits = [i for i in range(len(lines) - len(want) + 1) if [x.rstrip() for x in lines[i : i + len(want)]] == want]
            if len(hits) == 1:
                old = "\n".join(lines[hits[0] : hits[0] + len(want)])
                count = text_n.count(old)
        if count == 0:
            errors.append(f"edit {i}: original_snippet not found in {rel}")
            continue
        if count > 1:
            errors.append(f"edit {i}: original_snippet occurs {count} times in {rel}; it must be unique")
            continue
        new_text = text_n.replace(old, e.replacement_snippet.replace("\r\n", "\n"), 1)
        target.write_text(new_text.replace("\n", newline), encoding="utf-8", newline="")
    return errors


def run(ctx: AgentContext, bug: str, diagnosis: Diagnosis, repro: Reproduction | None, attempt: int,
        history: list[tuple[PatchProposal, VerificationResult | None]]) -> tuple[PatchProposal, Path]:
    draft = ctx.llm.structured(agent="repair", system=SYSTEM, messages=_prompt(ctx, bug, diagnosis, repro, history), output_model=RepairDraft, effort="high")
    work = ctx.workspace.fresh_copy(f"patch-{attempt}")
    errors = apply_edits(ctx, draft, work)
    changes = diff_trees(ctx.workspace.original, work)
    proposal = PatchProposal(
        id=new_id("patch"), attempt=attempt, summary=draft.summary, intended_behaviour=draft.intended_behaviour,
        why_minimal=draft.why_minimal, risk_notes=draft.risk_notes, edits=draft.edits, diff=combined_diff(changes),
        files_changed=[c.path for c in changes], lines_added=sum(c.added for c in changes), lines_removed=sum(c.removed for c in changes),
        apply_errors=errors, applied=not errors and bool(changes),
    )
    if not changes and not errors:
        proposal.apply_errors.append("the proposed edits produced no change")
    ctx.log("repair", f"attempt {attempt}: {len(draft.edits)} edits, {proposal.lines_added}+/{proposal.lines_removed}- in {proposal.files_changed}; errors={errors}")
    return proposal, work
