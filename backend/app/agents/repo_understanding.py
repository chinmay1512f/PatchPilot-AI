"""Agent 1 — Repository Understanding.

Deterministic indexing produces the facts (languages, manifests, tests, hooks); Claude reads a
bounded, redacted selection of files and explains the architecture. Claude's entry points and
important files are checked against the index; invented paths are dropped and noted.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.models import RepoNarrative, RepoSummary
from ..llm.client import untrusted
from .base import AgentContext

SYSTEM = """You are the Repository Understanding agent. Using the deterministic facts and file
excerpts provided, explain what the project does, how its modules relate, where execution starts,
which files matter most, and any initial security observations (e.g. install hooks, dynamic code
execution, hard-coded credentials markers, network access). List information that is missing and
would limit later bug investigation. Only reference file paths that appear in the provided index."""


def _select_context(ctx: AgentContext, budget: int) -> str:
    idx = ctx.index
    chunks: list[str] = []
    used = 0

    def add(path: str, max_lines: int) -> None:
        nonlocal used
        if used >= budget or idx.resolve(path) is None:
            return
        text = idx.read_numbered(path, 1, max_lines)
        if used + len(text) > budget:
            text = text[: budget - used]
        chunks.append(untrusted(path, text))
        used += len(text)

    readme = next((p for p in idx.files if Path(p).name.lower().startswith("readme")), None)
    if readme:
        add(readme, 80)
    for m in idx.facts.manifests[:4]:
        add(m, 60)
    for e in idx.facts.candidate_entry_points[:4]:
        add(e, 80)
    code = sorted((f for f in idx.files.values() if f.language == "Python" and not f.is_test), key=lambda f: -f.lines)
    for f in code[:8]:
        add(f.path, 120)
    if idx.facts.test_files:
        add(idx.facts.test_files[0], 60)
    return "\n\n".join(chunks)


def run(ctx: AgentContext) -> RepoSummary:
    facts = ctx.index.facts
    summary = RepoSummary(facts=facts)
    if facts.skipped_files:
        summary.limitations.append(f"{facts.skipped_files} files were not indexed (binary, too large, or non-UTF-8).")
    if facts.secrets_redacted:
        summary.limitations.append(f"{facts.secrets_redacted} possible secret values were redacted before any AI analysis.")
    ok, why = ctx.llm.available()
    if not ok:
        summary.narrative_status = "blocked"
        summary.limitations.append(why)
        return summary

    facts_json = facts.model_dump(exclude={"tree"})
    facts_json["tree"] = facts.tree[:200]
    prompt = (
        "Deterministic repository facts (tool output):\n" + json.dumps(facts_json, indent=1)[:20000]
        + "\n\nSelected file excerpts:\n" + _select_context(ctx, ctx.settings.max_context_chars // 3)
    )
    narrative = ctx.llm.structured(agent="repo_understanding", system=SYSTEM, messages=prompt, output_model=RepoNarrative, effort="medium")

    valid_entries = [p for p in narrative.entry_points if ctx.index.resolve(p)]
    dropped = [p for p in narrative.entry_points if not ctx.index.resolve(p)]
    narrative.entry_points = valid_entries
    kept_files = [f for f in narrative.important_files if ctx.index.resolve(f.path)]
    dropped += [f.path for f in narrative.important_files if not ctx.index.resolve(f.path)]
    narrative.important_files = kept_files
    if dropped:
        summary.limitations.append(f"Discarded {len(dropped)} AI-referenced paths not present in the repository: {', '.join(dropped[:5])}")
        ctx.log("repo_understanding", f"validation dropped non-existent paths: {dropped[:5]}")
    summary.narrative = narrative
    summary.narrative_status = "completed"
    return summary
