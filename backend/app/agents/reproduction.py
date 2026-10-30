"""Agent 3 — Reproduction & Test.

1. Runs the existing test suite on a disposable copy (baseline evidence).
2. Asks Claude for a targeted pytest reproduction test.
3. Statically vets the generated test (syntax, file name, banned capabilities).
4. Runs it against the *unmodified* code. "Reproduced" means the runner reported a failing
   test — Claude's expectation is never used as the result.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..core.models import Diagnosis, Reproduction, ReproTestDraft, TestRun
from ..llm.client import untrusted
from ..tools.testing import run_pytest
from .base import PLAIN_LANGUAGE, AgentContext

SYSTEM = """You are the Reproduction & Test agent. Write ONE pytest module that reproduces the
reported defect: it must FAIL on the current (buggy) code and PASS once the defect is fixed.

Rules:
- Import the project's code the same way existing tests do. Test only behaviour, no internals that a fix may rename.
- Assert the intended, correct behaviour described in the bug report (not the current buggy output).
- Include the key edge cases (boundaries, empty input, zero, negative values) relevant to the defect.
- No network, subprocesses, file deletion, sleeping, or environment access. Deterministic only.
- Do not modify or monkeypatch the code under test to force a result.
- Name the file test_patchpilot_repro.py unless a clearer test_*.py name is needed."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE

BANNED_MODULES = {"socket", "subprocess", "requests", "urllib", "httpx", "http", "ctypes", "shutil", "multiprocessing", "asyncio.subprocess", "ftplib", "smtplib"}
BANNED_CALLS = {"os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir", "os.kill", "exec", "eval", "__import__", "os.environ"}
NAME_RE = re.compile(r"^test_[a-z0-9_]{1,60}\.py$")


def vet_test_code(name: str, code: str) -> list[str]:
    problems: list[str] = []
    if not NAME_RE.match(name):
        problems.append(f"file name {name!r} must match test_<name>.py (lowercase)")
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return problems + [f"syntax error: {e}"]
    if not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test") for n in ast.walk(tree)):
        problems.append("no test functions found")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in BANNED_MODULES:
                    problems.append(f"imports banned module {a.name}")
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in BANNED_MODULES:
            problems.append(f"imports banned module {node.module}")
        elif isinstance(node, (ast.Call, ast.Attribute, ast.Name)):
            target = ast.unparse(node.func if isinstance(node, ast.Call) else node)
            if target in BANNED_CALLS:
                problems.append(f"uses banned capability {target}")
    return sorted(set(problems))


def _first_error(output: str) -> str:
    """The most informative error line from pytest output, e.g. "ModuleNotFoundError: No module named 'x'"."""
    for line in output.splitlines():
        m = re.match(r"^E\s+(\w*(?:Error|Exception)\b.*)$", line.strip())
        if m:
            return m.group(1)[:200]
    return "collection/import error"


def _tests_dir(ctx: AgentContext) -> str:
    dirs = {Path(p).parts[0] for p in ctx.index.facts.test_files if len(Path(p).parts) > 1}
    for d in ("tests", "test"):
        if d in dirs:
            return d
    return ""


def baseline(ctx: AgentContext) -> TestRun:
    work = ctx.workspace.fresh_copy("baseline")
    run = run_pytest(ctx.backend, work, "baseline", timeout=ctx.settings.sandbox_timeout_seconds, stubs=ctx.index.facts.third_party_imports)
    ctx.log("reproduction", f"baseline suite: {run.status} passed={run.passed} failed={run.failed} errors={run.errors}")
    return run


def run(ctx: AgentContext, bug_description: str, diagnosis: Diagnosis | None, baseline_run: TestRun) -> Reproduction:
    rep = Reproduction(status="inconclusive", baseline_run=baseline_run)
    if baseline_run.status == "blocked":
        rep.status = "blocked"
        rep.notes.append(baseline_run.blocked_reason or "execution blocked")
    test_dir = _tests_dir(ctx)
    primary = next((f for f in (diagnosis.findings if diagnosis else []) if f.id == diagnosis.primary_finding_id), None) if diagnosis else None

    context_parts = ["Bug report:\n" + untrusted("bug_report", bug_description)]
    if primary:
        context_parts.append(
            f"Diagnosis (from the investigation agent, model-generated): {primary.title} in {primary.file_path} "
            f"lines {primary.line_start}-{primary.line_end}. Root cause hypothesis: {primary.root_cause_hypothesis}\n"
            f"Suggested reproduction: {primary.reproduction_strategy}"
        )
        context_parts.append(untrusted(primary.file_path, ctx.index.read_numbered(primary.file_path, 1, 300)))
    for f in ctx.index.rank_files(bug_description, limit=3):
        if not primary or f != primary.file_path:
            context_parts.append(untrusted(f, ctx.index.read_numbered(f, 1, 150)))
    if ctx.index.facts.test_files:
        example = ctx.index.facts.test_files[0]
        context_parts.append("Example existing test (for import style):\n" + untrusted(example, ctx.index.read_numbered(example, 1, 60)))
    context_parts.append(f"The test file will be placed in: {test_dir or '(repository root)'}/ and run from the repository root with pytest.")
    missing = ctx.index.facts.missing_imports
    if missing:
        context_parts.append(
            "Sandbox environment (tool facts): third-party dependencies are NOT installed. These packages imported by the "
            f"repository are missing and will be replaced by inert stand-in objects at import time: {', '.join(missing)}. "
            "Importing the project's modules will therefore work, but anything that really calls those libraries returns "
            "meaningless stand-ins. Write tests that exercise the repository's own pure logic (calculations, conditions, "
            "parsing, data handling) and do not depend on the behaviour of the missing packages. Do not skip or xfail "
            "tests because of missing packages, and do not modify sys.path or sys.modules yourself.")
    base_prompt = "\n\n".join(context_parts)

    feedback = ""
    for attempt in range(1, ctx.settings.max_repro_attempts + 1):
        rep.attempts = attempt
        prompt = base_prompt + (f"\n\nYour previous attempt was not usable:\n{feedback}\nWrite a corrected test." if feedback else "")
        draft = ctx.llm.structured(agent="reproduction", system=SYSTEM, messages=prompt, output_model=ReproTestDraft, effort="medium")
        problems = vet_test_code(draft.test_file_name, draft.test_code)
        rel = f"{test_dir}/{draft.test_file_name}" if test_dir else draft.test_file_name
        rep.test_path, rep.test_code = rel, draft.test_code
        rep.rationale, rep.edge_cases, rep.related_existing_tests = draft.rationale, draft.edge_cases_covered, draft.related_existing_tests
        if ctx.index.resolve(rel) is not None:
            problems.append(f"{rel} already exists in the repository; choose a new file name")
        if problems:
            feedback = "Policy check rejected the test: " + "; ".join(problems)
            rep.notes.append(f"attempt {attempt}: {feedback}")
            ctx.log("reproduction", feedback)
            continue
        if rep.status == "blocked":
            rep.notes.append("Reproduction test generated but not executed: sandbox unavailable.")
            return rep
        work = ctx.workspace.fresh_copy(f"repro-{attempt}")
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(draft.test_code, encoding="utf-8")
        result = run_pytest(ctx.backend, work, f"repro-{attempt}", [rel], timeout=ctx.settings.sandbox_timeout_seconds, stubs=ctx.index.facts.third_party_imports)
        rep.repro_run = result
        ctx.log("reproduction", f"repro attempt {attempt}: {result.status} passed={result.passed} failed={result.failed} errors={result.errors}")
        if result.status in ("blocked", "timeout"):
            rep.status = "blocked" if result.status == "blocked" else "inconclusive"
            rep.notes.append(result.blocked_reason or result.status)
            return rep
        if result.failed > 0:
            rep.status = "reproduced"
            return rep
        if result.errors > 0 or result.status in ("error", "no_tests"):
            feedback = f"The test could not run correctly ({_first_error(result.output_tail)}):\n" + result.output_tail[-2500:]
        else:
            feedback = "Every test PASSED on the unmodified code, so it does not demonstrate the defect. Output:\n" + result.output_tail[-1500:]
            rep.status = "not_reproduced"
        rep.notes.append(f"attempt {attempt}: {feedback.splitlines()[0]}")
    if rep.status != "not_reproduced":
        rep.status = "inconclusive"
    return rep
