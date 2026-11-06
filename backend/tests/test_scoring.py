"""PatchPilot Risk Score: deterministic, explainable, never rewards checks that did not run."""

from app.core.models import (
    CodeQualitySummary, Confidence, JobResults, Reproduction, ScannerRun, SecurityFinding, SecurityReport, Severity, TestRun,
    VerificationResult, VerificationStatus,
)
from app.core.scoring import compute

ALL_SCANNERS = [ScannerRun(name=n, status="completed") for n in ("bandit", "semgrep", "patchpilot-secrets", "patchpilot-suspicious", "osv")]


def finding(i, category, sev, conf=Confidence.high, path="app.py", scanner="bandit"):
    return SecurityFinding(id=f"sec_{i}", scanner=scanner, category=category, rule_id="R", title="t", severity=sev,
                           confidence=conf, file_path=path, line=1, snippet=f"x{i}")


def run(passed=5, failed=0, status="completed"):
    return TestRun(label="baseline", backend="local", command="pytest", status=status, passed=passed, failed=failed)


def clean_quality(lines=1000, issues=0, severe=0):
    return CodeQualitySummary(status="completed", python_lines=lines, issues=issues, severe=severe)


def test_clean_repository_scores_100_without_claiming_secure():
    r = JobResults(security=SecurityReport(scanners=ALL_SCANNERS, findings=[], code_quality=clean_quality()),
                   reproduction=Reproduction(status="not_reproduced", baseline_run=run()))
    s = compute(r).before
    assert s.score == 100 and s.factors_assessed == 5
    assert s.rating == "No issues found by the checks run" and "secure" not in s.rating.lower()


def test_deductions_by_severity_confidence_and_caps():
    findings = [finding(1, "static_analysis", Severity.high),                       # 6
                finding(2, "static_analysis", Severity.medium, Confidence.low),      # 1.5
                *[finding(10 + i, "secret", Severity.critical, path="cfg.py", scanner="secrets") for i in range(3)],  # 36 -> cap 20
                finding(20, "dependency", Severity.high, scanner="osv")]             # 6
    r = JobResults(security=SecurityReport(scanners=ALL_SCANNERS, findings=findings, code_quality=clean_quality(issues=40, severe=1)),
                   reproduction=Reproduction(status="reproduced", baseline_run=run()))
    parts = {c.key: c for c in compute(r).before.components}
    assert parts["vulnerabilities"].deduction == 7.5
    assert parts["secrets"].deduction == 20 and "capped" in parts["secrets"].detail
    assert parts["dependencies"].deduction == 6
    assert parts["code_quality"].deduction == 2 + 8 * min(1, 39 / 20)  # 1 severe (2 pts) + density 39/KLOC -> full 8
    assert parts["verification"].deduction == 15 and "failing test" in parts["verification"].detail
    assert compute(r).before.score == round(100 - (7.5 + 20 + 6 + 10 + 15))


def test_unassessed_factors_are_excluded_not_free_points():
    # Security scan only: no tests ran -> verification not assessed; score scaled to the 85 measured points.
    r = JobResults(security=SecurityReport(scanners=ALL_SCANNERS, findings=[finding(1, "static_analysis", Severity.critical)],
                                           code_quality=CodeQualitySummary(status="not_applicable")))
    s = compute(r).before
    parts = {c.key: c for c in s.components}
    assert not parts["verification"].assessed and not parts["code_quality"].assessed
    assert s.factors_assessed == 3 and s.score == round(100 * (75 - 12) / 75)
    assert compute(JobResults()) is None  # nothing measured -> no score at all


def test_score_after_verified_patch():
    vuln = finding(1, "static_analysis", Severity.high, path="shop/pricing.py")
    other = finding(2, "static_analysis", Severity.medium, path="shop/cart.py")
    sec = SecurityReport(scanners=ALL_SCANNERS, findings=[vuln, other], code_quality=clean_quality())
    v = VerificationResult(status=VerificationStatus.verified, patch_id="p1", original_bug_status="fixed",
                           resolved_finding_ids=[vuln.id], new_lint_issues=["shop/pricing.py: F401 unused import"])
    r = JobResults(security=sec, reproduction=Reproduction(status="reproduced", baseline_run=run()), verification=v)
    rs = compute(r)
    before, after = {c.key: c for c in rs.before.components}, {c.key: c for c in rs.after.components}
    assert before["verification"].deduction == 15 and after["verification"].deduction == 0
    assert before["vulnerabilities"].deduction == 9 and after["vulnerabilities"].deduction == 3  # resolved finding removed
    assert after["code_quality"].deduction > 0  # the new lint issue counts against the patch
    assert rs.after.score > rs.before.score and "copy only" in rs.after_note


def test_no_after_score_for_failed_patch():
    sec = SecurityReport(scanners=ALL_SCANNERS, findings=[], code_quality=clean_quality())
    v = VerificationResult(status=VerificationStatus.failed, patch_id="p1", original_bug_status="not_fixed", reasons=["tests fail"])
    rs = compute(JobResults(security=sec, verification=v))
    assert rs.after is None and "failed verification" in rs.after_note


def test_dependencies_nothing_to_check_vs_could_not_check():
    none = [ScannerRun(name="osv", status="skipped", message="no dependency manifests found"), *[s for s in ALL_SCANNERS if s.name != "osv"]]
    dep = {c.key: c for c in compute(JobResults(security=SecurityReport(scanners=none, findings=[]))).before.components}["dependencies"]
    assert dep.assessed and dep.deduction == 0 and "No third-party dependencies" in dep.detail
    unpinned = [ScannerRun(name="osv", status="skipped", message="no pinned versions to check (3 unpinned)"), *none[1:]]
    dep = {c.key: c for c in compute(JobResults(security=SecurityReport(scanners=unpinned, findings=[]))).before.components}["dependencies"]
    assert not dep.assessed and "unpinned" in dep.detail


def test_failed_scanner_is_not_assessed():
    scanners = [ScannerRun(name="osv", status="failed"), *[s for s in ALL_SCANNERS if s.name != "osv"]]
    r = JobResults(security=SecurityReport(scanners=scanners, findings=[], code_quality=clean_quality()))
    parts = {c.key: c for c in compute(r).before.components}
    assert not parts["dependencies"].assessed and "did not run" in parts["dependencies"].detail
