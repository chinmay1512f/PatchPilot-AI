"""Pytest execution through the sandbox + JUnit XML parsing.

A test is only ever reported as passed when the runner actually executed it and the JUnit
report says so. Claude's predictions never enter these results.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.models import TestCaseResult, TestRun
from .sandbox import Backend

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9_./\-:\[\]]+$")


def run_pytest(backend: Backend, workdir: Path, label: str, targets: list[str] | None = None, timeout: int = 120,
               stubs: list[str] | None = None) -> TestRun:
    """``stubs``: third-party top-level modules that may be replaced by inert stand-ins if they are
    not installed (dependencies are never installed in the sandbox)."""
    targets = targets or []
    backend.prepare(workdir)
    pp = workdir / ".patchpilot"
    (pp / "stubs.json").write_text(json.dumps(sorted(set(stubs or []))), encoding="utf-8")
    (pp / "stubbed.json").unlink(missing_ok=True)
    for t in targets:  # targets come from our own code, but never pass anything shell-like
        if not _SAFE_TARGET.match(t) or t.startswith("-"):
            raise ValueError(f"unsafe pytest target: {t!r}")
    safe_label = re.sub(r"[^a-z0-9_-]", "_", label.lower())
    junit_rel = f".patchpilot/junit-{safe_label}.xml"
    # --continue-on-collection-errors: one broken/unloadable test file must not hide every other result
    args = ["-q", "-p", "no:cacheprovider", "-o", "junit_family=xunit2", f"--junitxml={junit_rel}", "--color=no",
            "--continue-on-collection-errors", *targets]
    res = backend.run_python_tool(workdir, "pytest", args, timeout)

    run = TestRun(label=label, status="completed", backend=res.backend, command=res.command,
                  exit_code=res.exit_code, duration_seconds=res.duration, output_tail=res.output[-6000:])
    if res.blocked:
        run.status = "blocked"
        run.blocked_reason = res.blocked_reason
        return run
    if res.timed_out:
        run.status = "timeout"
        run.blocked_reason = f"Test run exceeded {timeout}s and was terminated."
    stubbed_file = pp / "stubbed.json"
    if stubbed_file.is_file():
        try:
            run.stubbed_modules = [str(x) for x in json.loads(stubbed_file.read_text(encoding="utf-8"))][:50]
        except (ValueError, OSError):
            pass
    junit = workdir / junit_rel
    if junit.is_file():
        run.tests = parse_junit(junit)
    run.passed = sum(t.outcome == "passed" for t in run.tests)
    run.failed = sum(t.outcome == "failed" for t in run.tests)
    run.errors = sum(t.outcome == "error" for t in run.tests)
    run.skipped = sum(t.outcome in ("skipped", "xfailed") for t in run.tests)
    if run.status == "completed":
        if res.exit_code == 5:
            run.status = "no_tests"
        elif res.exit_code in (2, 3, 4) and not run.tests:
            run.status = "error"
        elif not junit.is_file():
            run.status = "error"
    return run


def parse_junit(path: Path) -> list[TestCaseResult]:
    try:
        root = ET.parse(path).getroot()  # file written by pytest inside our workspace copy
    except ET.ParseError:
        return []
    out: list[TestCaseResult] = []
    for case in root.iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        nodeid = f"{classname}::{name}" if classname else name
        outcome, message = "passed", ""
        for child in case:
            tag = child.tag
            if tag == "failure":
                outcome, message = "failed", (child.get("message") or "") + "\n" + (child.text or "")
            elif tag == "error":
                outcome, message = "error", (child.get("message") or "") + "\n" + (child.text or "")
            elif tag == "skipped":
                kind = child.get("type", "")
                outcome = "xfailed" if "xfail" in kind else "skipped"
                message = child.get("message") or ""
        if outcome == "error":
            # pytest's collection errors just say "collection failure"; surface the real reason first
            reason = next((ln.strip()[1:].strip() for ln in message.splitlines() if ln.strip().startswith("E ") and ("Error" in ln or "Exception" in ln)), "")
            if reason:
                message = f"Could not load this test file — {reason}\n{message}"
        out.append(TestCaseResult(nodeid=nodeid, outcome=outcome, message=message.strip()[:3000], duration=float(case.get("time", 0) or 0)))
    return out
