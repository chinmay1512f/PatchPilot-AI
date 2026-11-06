"""PatchPilot Risk Score — a transparent, deterministic score out of 100.

Computed by a fixed formula from scanner and test results only (Claude is not involved), so the same
evidence always gives the same score and every point can be explained. It is PatchPilot's own
assessment, not an industry-standard certification, and a high score never means "secure".

Five parts, each with a maximum deduction:
  vulnerabilities 35 · exposed secrets 20 · dependency risks 20 · code quality 10 · verification 15
Each finding deducts points by severity, weighted by the scanner's confidence; a part's deduction is
capped at its maximum. Parts that could not be measured are marked "not assessed" and the score is
scaled to the parts that were (it never awards points for checks that did not run).
"""

from __future__ import annotations

from collections import Counter

from .models import (
    CodeQualitySummary,
    Confidence,
    JobResults,
    RiskScore,
    RiskScoreReport,
    ScoreComponent,
    SecurityFinding,
    SecurityReport,
    Severity,
    TestRun,
    VerificationResult,
    VerificationStatus,
)

SEVERITY_POINTS = {Severity.critical: 12.0, Severity.high: 6.0, Severity.medium: 3.0, Severity.low: 1.0, Severity.info: 0.25}
CONFIDENCE_WEIGHT = {Confidence.high: 1.0, Confidence.medium: 0.75, Confidence.low: 0.5}
MAX = {"vulnerabilities": 35, "secrets": 20, "dependencies": 20, "code_quality": 10, "verification": 15}
LABELS = {"vulnerabilities": "Code vulnerabilities", "secrets": "Exposed secrets", "dependencies": "Dependency risks",
          "code_quality": "Code quality", "verification": "Verification status"}
VULN_CATEGORIES = {"static_analysis", "suspicious_code", "patch_security"}
LINT_SEVERE = ("E9", "F63", "F7", "F82")
LINT_DENSITY_FOR_MAX = 20.0  # correctness lint issues per 1,000 lines that use up the non-severe lint points


def _ran(report: SecurityReport, names: set[str]) -> bool:
    return any(s.name in names and s.status == "completed" for s in report.scanners)


def _findings_part(key: str, findings: list[SecurityFinding], assessed: bool, what: str) -> ScoreComponent:
    part = ScoreComponent(key=key, label=LABELS[key], max_points=MAX[key], assessed=assessed)
    if not assessed:
        part.detail = f"Not assessed: {what} did not run."
        return part
    points = sum(SEVERITY_POINTS[f.severity] * CONFIDENCE_WEIGHT[f.confidence] for f in findings)
    part.deduction = round(min(MAX[key], points), 1)
    if not findings:
        part.detail = f"No findings from {what}."
    else:
        counts = Counter(f.severity for f in findings)
        part.detail = f"{len(findings)} finding(s) from {what}: " + ", ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s])
        if points > MAX[key]:
            part.detail += f" (capped at {MAX[key]} points)"
    return part


def _code_quality_part(cq: CodeQualitySummary | None, extra_issues: list[str] = ()) -> ScoreComponent:
    part = ScoreComponent(key="code_quality", label=LABELS["code_quality"], max_points=MAX["code_quality"])
    if cq is None or cq.status != "completed":
        part.assessed = False
        part.detail = "Not assessed: " + ("no Python code to lint." if cq and cq.status == "not_applicable" else "the Ruff linter did not run.")
        return part
    extra_codes = [e.split(": ", 1)[1].split(" ", 1)[0] if ": " in e else "" for e in extra_issues]
    severe = cq.severe + sum(1 for c in extra_codes if c == "syntax" or c.startswith(LINT_SEVERE))
    other = cq.issues + len(extra_issues) - severe
    density = other / max(1.0, cq.python_lines / 1000)
    points = 2.0 * severe + (MAX["code_quality"] - 2) * min(1.0, density / LINT_DENSITY_FOR_MAX)
    part.deduction = round(min(MAX["code_quality"], points), 1)
    total = cq.issues + len(extra_issues)
    part.detail = (f"{total} correctness lint issue(s) in {cq.python_lines:,} lines of Python"
                   + (f", {severe} serious (syntax errors / undefined names)" if severe else "")
                   + ("" if total else " — none found") + ".")
    return part


def _verification_before(r: JobResults) -> ScoreComponent:
    part = ScoreComponent(key="verification", label=LABELS["verification"], max_points=MAX["verification"])
    rep = r.reproduction
    if rep and rep.status == "reproduced":
        part.deduction = MAX["verification"]
        part.detail = "A failing test proves a bug in the original code."
        return part
    base: TestRun | None = (rep.baseline_run if rep else None) or (r.verification.baseline_run if r.verification else None)
    total = (base.passed + base.failed + base.errors) if base else 0
    if base and base.status == "completed" and total:
        bad = base.failed + base.errors
        part.deduction = 8.0 if bad else 0.0
        part.detail = f"{bad} of {total} existing tests fail on the original code." if bad else f"All {total} existing tests pass; no bug was proven."
        return part
    part.assessed = False
    part.detail = "Not assessed: no tests were run (none found, execution not allowed, or blocked)."
    return part


def _verification_after(v: VerificationResult) -> ScoreComponent:
    part = ScoreComponent(key="verification", label=LABELS["verification"], max_points=MAX["verification"])
    if v.status == VerificationStatus.verified:
        part.detail = "Patch verified: the reproduction test now passes and the full suite passes with no regressions."
    elif v.status == VerificationStatus.failed:
        part.deduction = MAX["verification"]
        part.detail = "Patch failed verification" + (f": {v.reasons[0]}" if v.reasons else ".")
    else:
        part.deduction = 8.0
        part.detail = f"Patch could not be fully verified ({v.status.value})."
    return part


def _rating(score: int, total_deduction: float) -> str:
    if total_deduction == 0:
        return "No issues found by the checks run"
    if score >= 90:
        return "Low risk"
    if score >= 75:
        return "Moderate risk"
    if score >= 50:
        return "Elevated risk"
    return "High risk"


def _score(basis: str, parts: list[ScoreComponent]) -> RiskScore | None:
    assessed = [p for p in parts if p.assessed]
    possible = sum(p.max_points for p in assessed)
    if not possible:
        return None
    lost = sum(p.deduction for p in assessed)
    score = round(100 * (possible - lost) / possible)  # scaled to the parts that were measured
    return RiskScore(score=score, rating=_rating(score, lost), basis=basis, components=parts, factors_assessed=len(assessed))


def _security_parts(sec: SecurityReport | None, findings: list[SecurityFinding]) -> list[ScoreComponent]:
    if sec is None:
        return [ScoreComponent(key=k, label=LABELS[k], max_points=MAX[k], assessed=False, detail="Not assessed: the security scan was not run.")
                for k in ("vulnerabilities", "secrets", "dependencies")]
    return [
        _findings_part("vulnerabilities", [f for f in findings if f.category in VULN_CATEGORIES],
                       _ran(sec, {"bandit", "semgrep", "patchpilot-suspicious"}), "Bandit, Semgrep and the malware-indicator rules"),
        _findings_part("secrets", [f for f in findings if f.category == "secret"],
                       _ran(sec, {"patchpilot-secrets", "gitleaks"}), "the secret scanners"),
        _dependencies_part(sec, [f for f in findings if f.category == "dependency"]),
    ]


def _dependencies_part(sec: SecurityReport, findings: list[SecurityFinding]) -> ScoreComponent:
    osv = next((s for s in sec.scanners if s.name == "osv"), None)
    if osv and osv.status == "skipped" and osv.message.startswith("no dependency manifests"):
        # Nothing to check is a real result (no third-party code), unlike "could not check".
        return ScoreComponent(key="dependencies", label=LABELS["dependencies"], max_points=MAX["dependencies"],
                              detail="No third-party dependencies declared (no dependency manifests found).")
    part = _findings_part("dependencies", findings, _ran(sec, {"osv"}), "the OSV.dev vulnerability lookup")
    if not part.assessed and osv and osv.message:
        part.detail = f"Not assessed: {osv.message}."
    return part


def compute(r: JobResults) -> RiskScoreReport | None:
    sec = r.security
    before_parts = _security_parts(sec, sec.findings if sec else [])
    before_parts += [_code_quality_part(sec.code_quality if sec else None), _verification_before(r)]
    before = _score("original", before_parts)
    if before is None:
        return None
    report = RiskScoreReport(before=before)

    v = r.verification
    if v is None or not v.patch_id:
        return report
    if v.status == VerificationStatus.failed:
        report.after_note = "PatchPilot's patch failed verification, so no after-patch score is shown."
        return report
    resolved = set(v.resolved_finding_ids)
    after_findings = [f for f in (sec.findings if sec else []) if f.id not in resolved] + list(v.patch_security_findings)
    after_parts = _security_parts(sec, after_findings)
    after_parts += [_code_quality_part(sec.code_quality if sec else None, v.new_lint_issues), _verification_after(v)]
    report.after = _score("patched", after_parts)
    report.after_note = (
        "After-patch score: files changed by the patch were re-scanned (Bandit, secret and malware rules) and re-linted; "
        f"{len(resolved)} finding(s) no longer reported, {len(v.patch_security_findings)} introduced. Findings in unchanged files "
        "and dependency findings carry over unchanged. The patch is applied to a copy only — your repository is not modified."
    )
    return report
