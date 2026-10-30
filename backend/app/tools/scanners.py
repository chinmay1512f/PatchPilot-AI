"""Security scanner integrations.

Each scanner returns a ``ScannerRun`` describing whether it actually ran. Missing tools are
reported as ``unavailable`` — never silently replaced with invented results. Static scanners
read files only; they do not execute repository code, so they run on the host.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from ..config import Settings
from ..core.models import Confidence, ScannerRun, SecurityFinding, SecurityReport, Severity, new_id
from ..ingest.indexer import RepoIndex
from ..ingest.secrets import find_secrets, redact
from .malware import run_clamav
from .suspicious import scan_repo

RULES_FILE = Path(__file__).with_name("semgrep_rules.yml")
_TOOL_DIR = str(Path(sys.executable).parent)

# Overlapping rules from different tools collapse into one finding.
_FAMILIES = {
    "command-injection": {"B602", "B604", "B605", "B607", "subprocess-shell-true", "subprocess-shell", "shell-exec"},
    "deserialization": {"B301", "B506", "B302", "pickle-load", "yaml-unsafe-load", "marshal-loads"},
    "code-eval": {"B307", "B102", "eval-input", "dynamic-exec"},
    "sql-injection": {"B608", "sql-string-format"},
    "weak-hash": {"B303", "B324", "weak-hash"},
    "tls": {"B501", "requests-verify-false"},
    "secret": {"B105", "B106", "B107"},
}


def _which(name: str) -> str | None:
    return shutil.which(name, path=_TOOL_DIR + os.pathsep + os.environ.get("PATH", ""))


def _tool_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "AWS_", "GITHUB_", "OPENAI_"))}
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "SEMGREP_SEND_METRICS": "off"})
    return env


def _version(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=_tool_env())
        return (r.stdout or r.stderr).strip().splitlines()[0][:60] if (r.stdout or r.stderr) else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def _sev(value: str | None, default: Severity = Severity.medium) -> Severity:
    v = (value or "").lower()
    return {
        "critical": Severity.critical, "high": Severity.high, "error": Severity.high, "medium": Severity.medium,
        "moderate": Severity.medium, "warning": Severity.medium, "low": Severity.low, "info": Severity.info,
    }.get(v, default)


def _conf(value: str | None) -> Confidence:
    return {"high": Confidence.high, "medium": Confidence.medium, "low": Confidence.low}.get((value or "").lower(), Confidence.medium)


def _snippet(index: RepoIndex | None, path: str | None, line: int | None) -> str:
    if not index or not path or not line:
        return ""
    f = index.resolve(path)
    if not f or not f.text:
        return ""
    lines = f.text.splitlines()
    return redact(lines[line - 1].strip()[:240])[0] if 0 < line <= len(lines) else ""


# --------------------------------------------------------------------------- individual scanners


def run_bandit(root: Path, index: RepoIndex | None, timeout: int) -> tuple[ScannerRun, list[SecurityFinding]]:
    exe = _which("bandit")
    if not exe:
        return ScannerRun(name="bandit", status="unavailable", message="bandit not installed"), []
    start = time.monotonic()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "bandit.json"
        cmd = [exe, "-r", str(root), "-f", "json", "-o", str(out), "-q", "--exit-zero", "-s", "B101", "-x", ".patchpilot"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_tool_env())
        except subprocess.TimeoutExpired:
            return ScannerRun(name="bandit", status="timeout", duration_seconds=timeout), []
        if not out.is_file():
            return ScannerRun(name="bandit", status="failed", message="no report produced"), []
        data = json.loads(out.read_text(encoding="utf-8"))
    findings = []
    for r in data.get("results", []):
        rel = _rel(r["filename"], root)
        cwe = (r.get("issue_cwe") or {}).get("id")
        findings.append(SecurityFinding(
            id=new_id("sec"), scanner="bandit", category="static_analysis", rule_id=r["test_id"],
            title=f"{r['test_id']} {r['test_name']}", severity=_sev(r.get("issue_severity")), confidence=_conf(r.get("issue_confidence")),
            file_path=rel, line=r.get("line_number"), snippet=_snippet(index, rel, r.get("line_number")) or redact(r.get("code", "").strip()[:240])[0],
            description=r.get("issue_text", ""), references=[x for x in [r.get("more_info"), f"CWE-{cwe}" if cwe else None] if x],
        ))
    ver = _version([exe, "--version"])
    return ScannerRun(name="bandit", version=ver, status="completed", findings=len(findings), duration_seconds=round(time.monotonic() - start, 2)), findings


def _disabled(settings: Settings, name: str) -> bool:
    return name in {x.strip().lower() for x in settings.disabled_scanners.split(",") if x.strip()}


def run_semgrep(root: Path, index: RepoIndex | None, settings: Settings, files: list[str] | None = None) -> tuple[ScannerRun, list[SecurityFinding]]:
    """``files``: limit the scan to these repo-relative paths (used for patched files only)."""
    if _disabled(settings, "semgrep"):
        return ScannerRun(name="semgrep", status="skipped", message="disabled by configuration"), []
    exe = _which("semgrep")
    if not exe:
        return ScannerRun(name="semgrep", status="unavailable", message="semgrep not installed"), []
    config = settings.semgrep_config or str(RULES_FILE)
    start = time.monotonic()
    targets = [str(root / f) for f in files if (root / f).is_file()] if files is not None else [str(root)]
    if not targets:
        return ScannerRun(name="semgrep", status="skipped", message="no files to scan"), []
    cmd = [exe, "scan", "--config", config, "--json", "--metrics=off", "--disable-version-check", "--quiet", "--exclude", ".patchpilot", *targets]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=settings.scanner_timeout_seconds, env=_tool_env())
    except subprocess.TimeoutExpired:
        return ScannerRun(name="semgrep", status="timeout", duration_seconds=settings.scanner_timeout_seconds), []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return ScannerRun(name="semgrep", status="failed", message=(r.stderr or "invalid output")[-300:]), []
    findings = []
    for res in data.get("results", []):
        rel = _rel(res["path"], root)
        line = res.get("start", {}).get("line")
        extra = res.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule = res["check_id"].split(".")[-1]
        findings.append(SecurityFinding(
            id=new_id("sec"), scanner="semgrep", category="static_analysis", rule_id=rule, title=rule.replace("-", " "),
            severity=_sev(extra.get("severity")), confidence=Confidence.medium, file_path=rel, line=line,
            snippet=_snippet(index, rel, line), description=extra.get("message", ""),
            references=[str(meta["cwe"])] if meta.get("cwe") else [],
        ))
    ver = _version([exe, "--version"])
    errs = data.get("errors") or []
    msg = f"{len(errs)} parse warnings" if errs else ""
    return ScannerRun(name="semgrep", version=ver, status="completed", findings=len(findings), duration_seconds=round(time.monotonic() - start, 2), message=msg), findings


def run_ruff(root: Path, files: list[str] | None = None, timeout: int = 60) -> tuple[ScannerRun, list[dict]]:
    """Lint (correctness-focused rules). Used by verification, not counted as security findings."""
    exe = _which("ruff")
    if not exe:
        return ScannerRun(name="ruff", status="unavailable", message="ruff not installed"), []
    targets = files or ["."]
    cmd = [exe, "check", "--isolated", "--no-cache", "--output-format", "json", "--select", "E9,F63,F7,F82,F401,F811,F821,F841,B", "--exit-zero", *targets]
    start = time.monotonic()
    try:
        r = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=timeout, env=_tool_env())
        data = json.loads(r.stdout or "[]")
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return ScannerRun(name="ruff", status="failed", message=str(e)[:200]), []
    issues = [{"file": _rel(d["filename"], root), "line": d["location"]["row"], "code": d.get("code") or "syntax", "message": d["message"]} for d in data]
    return ScannerRun(name="ruff", version=_version([exe, "--version"]), status="completed", findings=len(issues), duration_seconds=round(time.monotonic() - start, 2)), issues


def run_builtin_secrets(index: RepoIndex) -> tuple[ScannerRun, list[SecurityFinding]]:
    start = time.monotonic()
    findings = []
    for f in index.files.values():
        if not f.text:
            continue
        for s in find_secrets(f.text):
            sev = _sev(s.severity)
            if f.is_test and sev in (Severity.critical, Severity.high):
                sev = Severity.medium  # fixtures in tests are often fake, but still worth review
            line_text = f.text.splitlines()[s.line - 1] if s.line <= len(f.text.splitlines()) else ""
            findings.append(SecurityFinding(
                id=new_id("sec"), scanner="secrets", category="secret", rule_id=s.rule_id, title=s.title, severity=sev,
                confidence=Confidence.high if s.rule_id not in ("hardcoded-password", "jwt") else Confidence.medium,
                file_path=f.path, line=s.line, snippet=redact(line_text.strip()[:240])[0],
                description=f"Possible {s.title.lower()} committed to the repository (value masked: {s.masked}). Rotate it if real and load it from the environment or a secret manager.",
            ))
    return ScannerRun(name="patchpilot-secrets", version="builtin", status="completed", findings=len(findings), duration_seconds=round(time.monotonic() - start, 2)), findings


def run_gitleaks(root: Path, timeout: int) -> tuple[ScannerRun, list[SecurityFinding]]:
    exe = _which("gitleaks")
    if not exe:
        return ScannerRun(name="gitleaks", status="unavailable", message="gitleaks not on PATH (built-in secret scanner used instead)"), []
    start = time.monotonic()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "gl.json"
        cmd = [exe, "detect", "--no-git", "--source", str(root), "--report-format", "json", "--report-path", str(out), "--redact", "--exit-code", "0", "--no-banner"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_tool_env())
        except subprocess.TimeoutExpired:
            return ScannerRun(name="gitleaks", status="timeout"), []
        data = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else []
    findings = [SecurityFinding(
        id=new_id("sec"), scanner="gitleaks", category="secret", rule_id=d.get("RuleID", "secret"), title=d.get("Description", "Secret"),
        severity=Severity.high, confidence=Confidence.high, file_path=_rel(d.get("File", ""), root), line=d.get("StartLine"),
        snippet=redact((d.get("Match") or "")[:200])[0], description="Secret detected by gitleaks (value redacted).",
    ) for d in data]
    return ScannerRun(name="gitleaks", version=_version([exe, "version"]), status="completed", findings=len(findings), duration_seconds=round(time.monotonic() - start, 2)), findings


def run_suspicious(index: RepoIndex) -> tuple[ScannerRun, list[SecurityFinding]]:
    start = time.monotonic()
    findings = []
    for s in scan_repo(index):
        findings.append(SecurityFinding(
            id=new_id("sec"), scanner="suspicious", category="suspicious_code", rule_id=s.rule_id, title=s.title,
            severity=_sev(s.severity), confidence=_conf(s.confidence), file_path=s.file_path, line=s.line, snippet=s.snippet,
            description=s.description + " Pattern match only — not confirmed malicious.", references=s.tags,
        ))
    return ScannerRun(name="patchpilot-suspicious", version="builtin", status="completed", findings=len(findings), duration_seconds=round(time.monotonic() - start, 2)), findings


def run_osv(index: RepoIndex, settings: Settings, client_factory: Callable[[], httpx.Client] | None = None) -> tuple[ScannerRun, list[SecurityFinding]]:
    deps = index.facts.dependencies
    if not deps:
        return ScannerRun(name="osv", status="skipped", message="no dependency manifests found"), []
    if not settings.osv_enabled or _disabled(settings, "osv"):
        return ScannerRun(name="osv", status="skipped", message="disabled by configuration"), []
    pinned = [d for d in deps if d.version and d.pinned]
    unpinned = [d.name for d in deps if not (d.version and d.pinned)]
    if not pinned:
        return ScannerRun(name="osv", status="skipped", message=f"no pinned versions to check ({len(unpinned)} unpinned)"), []
    start = time.monotonic()
    queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in pinned]
    try:
        with (client_factory() if client_factory else httpx.Client(timeout=20)) as client:
            resp = client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
            resp.raise_for_status()
            results = resp.json().get("results", [])
            pairs = [(dep, v["id"]) for dep, res in zip(pinned, results, strict=False) for v in (res.get("vulns") or [])]

            def detail(vid: str) -> dict:
                try:
                    return client.get(f"https://api.osv.dev/v1/vulns/{vid}").json()
                except (httpx.HTTPError, ValueError):
                    return {}

            ids = list(dict.fromkeys(vid for _, vid in pairs))[:60]
            with ThreadPoolExecutor(max_workers=8) as pool:
                details = dict(zip(ids, pool.map(detail, ids), strict=True))
            findings = []
            for dep, vid in pairs:
                d = details.get(vid, {})
                summary = d.get("summary") or (d.get("details") or "")[:300]
                sev = _sev((d.get("database_specific") or {}).get("severity"), Severity.medium)
                aliases = d.get("aliases") or []
                findings.append(SecurityFinding(
                    id=new_id("sec"), scanner="osv", category="dependency", rule_id=vid,
                    title=f"{dep.name}=={dep.version}: {vid}", severity=sev, confidence=Confidence.high,
                    file_path=dep.manifest, line=None, snippet=f"{dep.name}=={dep.version}",
                    description=(summary or "Known vulnerability in this pinned version.") + (f" Aliases: {', '.join(aliases[:4])}." if aliases else ""),
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                ))
    except (httpx.HTTPError, ValueError) as e:
        return ScannerRun(name="osv", status="failed", message=f"OSV API unreachable: {type(e).__name__}"), []
    msg = f"checked {len(pinned)} pinned packages" + (f"; {len(unpinned)} unpinned not checked" if unpinned else "")
    return ScannerRun(name="osv", version="api.osv.dev v1", status="completed", findings=len(findings), duration_seconds=round(time.monotonic() - start, 2), message=msg), findings


# --------------------------------------------------------------------------- aggregate


def _family(rule_id: str) -> str | None:
    key = rule_id.split(".")[-1]
    for fam, ids in _FAMILIES.items():
        if key in ids:
            return fam
    return None


def dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    order = list(Severity)
    kept: dict[tuple, SecurityFinding] = {}
    out: list[SecurityFinding] = []
    for f in findings:
        fam = _family(f.rule_id)
        key = (f.file_path, f.line, fam) if fam and f.line else None
        if key and key in kept:
            first = kept[key]
            first.references.append(f"also reported by {f.scanner} ({f.rule_id})")
            if order.index(f.severity) < order.index(first.severity):
                first.severity = f.severity
            continue
        if key:
            kept[key] = f
        out.append(f)
    sev_rank = {s: i for i, s in enumerate(order)}
    return sorted(out, key=lambda x: (sev_rank[x.severity], x.file_path or "", x.line or 0))


def fingerprint(f: SecurityFinding) -> tuple:
    return (f.scanner, f.rule_id, f.file_path, re.sub(r"\s+", "", f.snippet))


def run_security_scan(root: Path, index: RepoIndex, settings: Settings, include_osv: bool = True) -> SecurityReport:
    runs: list[ScannerRun] = []
    findings: list[SecurityFinding] = []
    steps: list[Callable[[], tuple[ScannerRun, list[SecurityFinding]]]] = [
        lambda: run_bandit(root, index, settings.scanner_timeout_seconds),
        lambda: run_semgrep(root, index, settings),
        lambda: run_builtin_secrets(index),
        lambda: run_gitleaks(root, settings.scanner_timeout_seconds),
        lambda: run_suspicious(index),
        lambda: run_clamav(root, settings.scanner_timeout_seconds),
    ]
    if include_osv:
        steps.append(lambda: run_osv(index, settings))
    def safe(step: Callable[[], tuple[ScannerRun, list[SecurityFinding]]]) -> tuple[ScannerRun, list[SecurityFinding]]:
        try:
            return step()
        except Exception as e:  # one broken scanner must not hide the others
            return ScannerRun(name=getattr(step, "__name__", "scanner"), status="failed", message=f"{type(e).__name__}: {e}"[:300]), []

    # Scanners are independent read-only tools, so they run at the same time (order of results kept).
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="scanner") as pool:
        for run, found in pool.map(safe, steps):
            runs.append(run)
            findings += found
    return SecurityReport(scanners=runs, findings=dedupe(findings))
