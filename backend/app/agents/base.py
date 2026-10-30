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
PLAIN_LANGUAGE = """Writing style for every prose field you return (titles, descriptions, explanations,
summaries, rationales — NOT code). Readers range from students to senior engineers:
- Plain English and short sentences. Start with what goes wrong for the user or the app, then the
  technical cause. Example: "A $50.00 order is still charged $4.99 shipping. The check in
  `shipping_cost` uses `>` instead of `>=`, so exactly $50.00 doesn't count."
- Keep the precise technical names developers need — file, function, variable, operator, error —
  in `backticks`, but explain any jargon in a few everyday words the first time you use it
  (e.g. "off-by-one error — the check stops one step too early").
- Prefer a concrete example over an abstract description. Avoid long chains of clauses.
- Titles: one short plain sentence, about 12 words at most.
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
