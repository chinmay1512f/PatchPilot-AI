"""Shared agent context and read-only repository tools."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..config import Settings
from ..ingest.indexer import RepoIndex, normalize_rel
from ..ingest.workspace import Workspace
from ..llm.client import LLMClient, ToolSpec, untrusted
from ..tools.sandbox import Backend

# Shared writing style for agent output that people read (every agent except Repository Understanding).
PLAIN_LANGUAGE = """How to write every prose field you return (titles, descriptions, explanations,
summaries, rationales, reasons — NOT code and NOT code snippets).

Your reader is intelligent but may not work in software: a hackathon judge, a manager, a customer, a
student from another field. A developer reading the same text must still find the exact detail
they need.

Order every explanation like this:
1. What happens, in everyday terms: who is affected and what they would notice, lose or risk.
   ("A customer whose order is exactly $50.00 is still charged $4.99 for shipping.")
2. Why it happens, in one plain sentence.
   ("The code checks for 'more than $50' instead of '$50 or more'.")
3. The technical detail for developers, with exact names in `backticks`.
   ("In `shipping_cost`, the comparison uses `>` instead of `>=`.")
Only titles and one-line reasons may stop after step 1 or 2. Every explanation, description,
rationale and summary keeps step 3.

Simpler wording must never mean fewer facts. Keep every specific a developer needs: versions,
advisory or CVE identifiers, exact files, functions and lines, related unsafe code nearby, and
concrete checks or test ideas. Put them after the plain-language part, not instead of it.

Rules:
- Every sentence must still make sense to someone who skips the words in `backticks`.
- Explain each technical term the first time it appears, in a few everyday words after a dash or
  in brackets: "SQL injection (tricking the database into running an attacker's own commands)",
  "dependency (a ready-made package of code the project borrows)", "regression (something that
  worked before and is now broken)", "environment variable (a setting kept outside the code)".
  Spell out an acronym the first time.
- Use one short real-world comparison only when it makes the idea clearly easier ("like leaving the
  house key under the doormat"). Never use it instead of the facts, and at most one per field.
- Short sentences (about 20 words or fewer), active voice, concrete numbers and examples.
- Do not talk down to the reader: no "simply", "just" or "basically", no childish analogies. Keep
  the real level of risk; do not soften or exaggerate it.
- Titles: one plain sentence a non-programmer understands, about 12 words at most. Name the effect,
  not the tool rule: "Passwords are written directly into the code", not "B105 hardcoded password".
- No filler, hype or hedging beyond what the evidence requires. Keep each field brief."""


@dataclass
class AgentContext:
    job_id: str
    settings: Settings
    llm: LLMClient
    workspace: Workspace
    index: RepoIndex
    backend: Backend
    log: Callable[[str, str], None]  # (agent, message) -> audit trail


def repo_tools(index: RepoIndex, files_read: list[str]) -> list[ToolSpec]:
    """Read-only tools. They can only see files in the index (inside the workspace copy);
    all returned text is secret-redacted. There is deliberately no write/exec/network tool."""

    def list_files(args: dict) -> str:
        prefix = normalize_rel(str(args.get("prefix", "")))
        paths = [p for p in sorted(index.files) if p.startswith(prefix)]
        more = f"\n... {len(paths) - 300} more" if len(paths) > 300 else ""
        return "\n".join(f"{p} ({index.files[p].lines} lines)" for p in paths[:300]) + more or "(no files)"

    def read_file(args: dict) -> str:
        path = str(args["path"])
        if index.resolve(path) is None:
            raise FileNotFoundError(f"{path} is not in the repository index")
        start = int(args.get("start_line", 1) or 1)
        end = args.get("end_line")
        files_read.append(index.resolve(path).path)
        return untrusted(index.resolve(path).path, index.read_numbered(path, start, int(end) if end else None))

    def search_code(args: dict) -> str:
        hits = index.search(str(args["query"]), regex=bool(args.get("regex", False)))
        return untrusted("search_results", "\n".join(hits)) if hits else "(no matches)"

    return [
        ToolSpec("list_files", "List indexed repository files, optionally under a path prefix.",
                 {"type": "object", "properties": {"prefix": {"type": "string"}}, "additionalProperties": False}, list_files),
        ToolSpec("read_file", "Read a repository file with line numbers. Use start_line/end_line for large files.",
                 {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
                  "required": ["path"], "additionalProperties": False}, read_file),
        ToolSpec("search_code", "Search all indexed files for a literal string (or regex if regex=true). Returns path:line: text.",
                 {"type": "object", "properties": {"query": {"type": "string"}, "regex": {"type": "boolean"}},
                  "required": ["query"], "additionalProperties": False}, search_code),
    ]


def facts_brief(index: RepoIndex) -> str:
    f = index.facts
    langs = ", ".join(f"{lang.language} ({lang.files} files)" for lang in f.languages[:6])
    return (
        f"Languages: {langs}\nFrameworks: {', '.join(f.frameworks) or 'none detected'}\n"
        f"Test framework: {f.test_framework or 'none detected'}; test files: {', '.join(f.test_files[:15]) or 'none'}\n"
        f"Entry point candidates: {', '.join(f.candidate_entry_points[:10]) or 'none'}\n"
        f"Indexed files: {f.indexed_files} of {f.total_files}"
    )
