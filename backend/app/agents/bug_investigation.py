"""Agent 2 — Bug Investigation.

Claude investigates with read-only tools (list/read/search), then returns a structured
diagnosis. Every cited location is verified against the real file: unknown files or line
ranges outside the file are flagged ``unverified_location`` and can never drive a repair.
"""

from __future__ import annotations

from ..core.models import (
    BugFinding,
    Confidence,
    Diagnosis,
    DiagnosisDraft,
    RepoSummary,
    new_id,
)
from ..llm.client import untrusted, with_user_turn
from ..tools.diffing import enclosing_function
from .base import PLAIN_LANGUAGE, AgentContext, facts_brief, repo_tools

SYSTEM = """You are the Bug Investigation agent. Find the root cause of the reported problem.

Method:
1. Use the tools to read the code paths related to the report. Read before you conclude.
2. Trace data flow and conditions; consider several explanations before settling on one.
3. Cite exact file paths and line ranges you have actually read (line numbers come from read_file output).
4. Separate defects you can see in the code (is_confirmed_by_reading=true) from plausible ones.
5. You must not modify code. Suggest how the defect could be reproduced with a test.
Severity is impact if the defect is real; confidence is how sure you are. Keep them independent."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE


SYSTEM_DISCOVERY = """You are the Bug Investigation agent running a proactive code audit. No bug report
was given: your job is to find real functional defects in this codebase on your own.

Look for: wrong conditions and boundaries (off-by-one, < vs <=), wrong calculations or units,
inverted logic, unhandled edge cases (empty input, None, zero, negative numbers), incorrect
exception handling, state or mutation bugs, resource leaks, and behaviour that contradicts the
code's own docstrings, comments, README or existing tests.
Ignore: style, naming, missing type hints, micro-performance, and security-scanner topics (a
separate security scan covers those).

Method:
1. Use the tools to read the core modules. Compare what the code does with its documented intent.
2. Report only defects you can point to in code you actually read, with exact file paths and line
   ranges from read_file output. At most 5 findings; quality over quantity.
3. As primary, choose the defect that is most clearly wrong AND can be demonstrated with a small,
   deterministic unit test that needs no network or extra dependencies.
4. If you find no convincing defect, return an empty findings list and say so. Never invent problems.
Severity is impact if the defect is real; confidence is how sure you are. Keep them independent."""
SYSTEM_DISCOVERY += "\n\n" + PLAIN_LANGUAGE


def _core_files(ctx: AgentContext, limit: int = 10) -> list[str]:
    code = [f for f in ctx.index.files.values() if f.language == "Python" and not f.is_test and f.text]
    return [f.path for f in sorted(code, key=lambda f: -f.lines)[:limit]]


def run(ctx: AgentContext, bug_description: str, repo: RepoSummary | None) -> Diagnosis:
    """With a bug report: root-cause it. Without one: audit the code and discover defects."""
    discovery = not bug_description.strip()
    files_read: list[str] = []
    tools = repo_tools(ctx.index, files_read)
    overview = repo.narrative.overview if repo and repo.narrative else "(no AI overview available)"
    if discovery:
        system = SYSTEM_DISCOVERY
        important = [f.path for f in repo.narrative.important_files] if repo and repo.narrative else []
        user = (
            "No bug report was provided. Audit this repository for real functional defects.\n\n"
            + f"Repository overview: {overview}\n{facts_brief(ctx.index)}\n"
            + f"Files the repository-understanding agent marked as important: {', '.join(important) or 'none'}\n"
            + f"Largest non-test source files: {', '.join(_core_files(ctx)) or 'none'}\n\n"
            + "Read the code with the tools, then summarise the defects you found."
        )
        turns = ctx.settings.max_investigation_tool_turns + 4
    else:
        system = SYSTEM
        candidates = ctx.index.rank_files(bug_description, limit=8)
        user = (
            "Bug report from the user:\n" + untrusted("bug_report", bug_description)
            + f"\n\nRepository overview: {overview}\n{facts_brief(ctx.index)}\n"
            + f"Files ranked as most relevant by keyword search: {', '.join(candidates) or 'none'}\n\n"
            + "Investigate using the tools, then summarise what you found."
        )
        turns = ctx.settings.max_investigation_tool_turns
    loop = ctx.llm.tool_loop(agent="bug_investigation", system=system, user=user, tools=tools, max_turns=turns, effort="high")
    ctx.log("bug_investigation", f"{'audit' if discovery else 'investigation'}: {len(loop.tool_calls)} read-only tool calls; files read: {sorted(set(files_read))[:10]}")
    final_msgs = with_user_turn(loop.messages, "Now return the final structured diagnosis. Use only locations you read.")
    draft = ctx.llm.structured(agent="bug_investigation", system=system, messages=final_msgs, output_model=DiagnosisDraft, effort="high", tools=tools)
    diagnosis = validate(ctx, draft, files_read, len(loop.tool_calls))
    if discovery:
        diagnosis.mode = "discovery"
        diagnosis.discovered_issue = discovered_bug_text(diagnosis)
    return diagnosis


def discovered_bug_text(diagnosis: Diagnosis) -> str:
    """Turn the primary discovered finding into the 'bug report' that reproduction and repair work from."""
    primary = next((f for f in diagnosis.findings if f.id == diagnosis.primary_finding_id), None)
    if primary is None or not primary.location_verified:
        return ""
    return (
        "Defect discovered by PatchPilot's code audit (no user bug report was given; this is a model hypothesis "
        "until a test proves it).\n"
        f"Title: {primary.title}\nLocation: {primary.file_path} lines {primary.line_start}-{primary.line_end}"
        + (f" ({primary.function_name})" if primary.function_name else "")
        + f"\nDescription: {primary.description}\nExpected behaviour / root cause: {primary.root_cause_hypothesis}\n"
        f"How to reproduce: {primary.reproduction_strategy}"
    )


def validate(ctx: AgentContext, draft: DiagnosisDraft, files_read: list[str], tool_calls: int) -> Diagnosis:
    findings: list[BugFinding] = []
    for d in draft.findings:
        notes: list[str] = []
        f = ctx.index.resolve(d.file_path)
        verified = f is not None
        start, end = d.line_start, max(d.line_end, d.line_start)
        if f is None:
            notes.append(f"File '{d.file_path}' does not exist in the repository.")
        elif not (1 <= start <= f.lines and end <= f.lines + 1):
            verified = False
            notes.append(f"Line range {start}-{end} is outside the file ({f.lines} lines).")
        if verified and f is not None and f.path not in files_read:
            notes.append("Claude cited this file without reading it through the tools during this investigation.")
        if verified and f is not None and d.function_name and f.path.endswith(".py"):
            actual = enclosing_function(f.text or "", start)
            if actual and actual.split(".")[-1] != d.function_name.split(".")[-1]:
                notes.append(f"Cited function '{d.function_name}' but line {start} is inside '{actual}'.")
                d.function_name = actual
        if not verified:
            status = "unverified_location"
        elif d.is_confirmed_by_reading and d.confidence != Confidence.low:
            status = "confirmed"
        else:
            status = "suspected"
        findings.append(BugFinding(
            id=new_id("bug"), title=d.title, file_path=f.path if f else d.file_path, line_start=start, line_end=end,
            function_name=d.function_name, description=d.description, severity=d.severity,
            root_cause_hypothesis=d.root_cause_hypothesis, evidence=d.evidence, reproduction_strategy=d.reproduction_strategy,
            confidence=d.confidence if verified else Confidence.low, status=status, recommended_next_step=d.recommended_next_step,
            location_verified=verified, code_excerpt=ctx.index.excerpt(f.path, start, end) if f and verified else "",
            validation_notes=notes,
        ))
    primary = None
    if draft.primary_finding_index is not None and 0 <= draft.primary_finding_index < len(findings):
        primary = findings[draft.primary_finding_index]
    conclusive = bool(primary and primary.location_verified and primary.confidence in (Confidence.high, Confidence.medium))
    return Diagnosis(
        findings=findings, primary_finding_id=primary.id if primary else None,
        alternative_hypotheses=draft.alternative_hypotheses, summary=draft.summary, conclusive=conclusive,
        files_read=sorted(set(files_read)), tool_calls=tool_calls,
    )
