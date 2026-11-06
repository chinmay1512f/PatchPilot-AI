"""Attack path analysis: chains must be built from real scanner findings, never invented ones."""

import re

from conftest import FakeLLM
from test_workflows import COMMON, _run

from app.agents.attack_paths import AttackPathDraft, eligible, validate
from app.core.models import AIAssessment, AnalysisType, Confidence, SecurityFinding, SecurityReport, Severity


def f(i, sev=Severity.high, category="static_analysis", verdict=None):
    return SecurityFinding(id=f"sec_{i}", scanner="bandit", category=category, rule_id=f"B{i}", title=f"finding {i}", severity=sev,
                           confidence=Confidence.high, file_path=f"app/m{i}.py", line=10 + i, snippet="x",
                           ai_assessment=AIAssessment(verdict=verdict, rationale="r") if verdict else None)


def step(fid, action="does X"):
    return {"finding_id": fid, "action": action, "gains": "gets Y"}


def path(title, steps, severity="medium"):
    return {"title": title, "attacker": "unauthenticated user", "entry_point": "upload form", "steps": steps, "impact": "data theft",
            "severity": severity, "likelihood": "medium", "confidence": "medium", "preconditions": ["app is internet-facing"],
            "break_the_chain": "validate filenames"}


def test_validate_keeps_only_chains_of_real_findings():
    pool = [f(1, Severity.critical), f(2, Severity.medium), f(3, Severity.low)]
    draft = AttackPathDraft.model_validate({
        "paths": [
            path("real chain", [step("sec_1"), step("sec_2")], severity="medium"),
            path("one real + one invented", [step("sec_3"), step("sec_invented")]),
            path("same finding twice", [step("sec_2"), step("sec_2")]),
        ],
        "entry_points": [{"finding_id": "sec_2", "reason": "public"}, {"finding_id": "sec_ghost", "reason": "x"},
                         {"finding_id": "sec_2", "reason": "dup"}, {"finding_id": "sec_1", "reason": "secret"}],
        "summary": "s"})
    out = validate(draft, pool)
    assert [p.title for p in out.paths] == ["real chain"]
    p = out.paths[0]
    assert p.severity == Severity.critical  # never rated below its worst real finding
    assert p.steps[0].file_path == "app/m1.py" and p.steps[0].line == 11 and p.steps[0].severity == Severity.critical  # tool data
    assert any("do not exist" in d for d in out.dropped) and any("not a chain" in d for d in out.dropped)
    assert [(e.rank, e.finding_id) for e in out.entry_points] == [(1, "sec_2"), (2, "sec_1")]  # ghost and duplicate dropped


def test_internal_ids_in_text_become_locations():
    pool = [f(1), f(2)]
    pool[0].id, pool[1].id = "sec_aaaa111111", "sec_bbbb222222"  # real ids are 10 hex characters
    draft = AttackPathDraft.model_validate({"paths": [path("chain", [step("sec_aaaa111111", "starts at (sec_aaaa111111)"), step("sec_bbbb222222")])],
                                            "entry_points": [], "summary": "see sec_bbbb222222 first"})
    out = validate(draft, pool)
    assert out.paths[0].steps[0].action == "starts at (app/m1.py:11)" and out.summary == "see app/m2.py:12 first"


def test_no_chain_reason_used_when_nothing_survives():
    draft = AttackPathDraft.model_validate({"paths": [], "entry_points": [], "summary": "", "no_chain_reason": "issues are unrelated"})
    out = validate(draft, [f(1), f(2)])
    assert out.status == "completed" and not out.paths and out.summary == "issues are unrelated"


def test_eligible_excludes_lint_and_likely_false_positives():
    report = SecurityReport(scanners=[], findings=[f(1), f(2, category="lint"), f(3, verdict="likely_false_positive"), f(4, Severity.critical)])
    assert [x.id for x in eligible(report, 10)] == ["sec_4", "sec_1"]  # most severe first


def test_attack_paths_in_security_scan(settings):
    def chain(prompt):
        ids = re.findall(r"finding_id=(sec_[a-f0-9]+)", prompt)
        return {"paths": [path("Leaked key to cloud takeover", [step(ids[0]), step(ids[1])], severity="high"),
                          path("hallucinated", [step("sec_doesnotexist"), step(ids[0])])],
                "entry_points": [{"finding_id": ids[0], "reason": "readable by anyone with repo access"}], "summary": "one chain"}
    llm = FakeLLM(script={**COMMON, "AttackPathDraft": [chain]})
    job, _ = _run(settings, "insecure-notes", "repo", AnalysisType.security_scan, "", llm, allow_local=False)
    ap = job.results.security.attack_paths
    assert ap.status == "completed" and ap.findings_considered >= 2
    assert [p.title for p in ap.paths] == ["Leaked key to cloud takeover"]
    ids = {x.id for x in job.results.security.findings}
    assert all(s.finding_id in ids for p in ap.paths for s in p.steps)
    assert ap.entry_points[0].rank == 1 and ap.dropped
    assert any("attack path analysis started" in e.message for e in job.audit)
    md = job.results.report.markdown
    assert "Possible attack paths" in md and "Leaked key to cloud takeover" in md and "not a confirmed exploit" in md.lower()


def test_attack_paths_not_needed_with_fewer_than_two_findings(settings):
    from app.agents.attack_paths import analyse
    from app.agents.base import AgentContext
    report = SecurityReport(scanners=[], findings=[f(1)])
    ctx = AgentContext.__new__(AgentContext)
    ctx.settings, ctx.llm = settings, FakeLLM()
    out = analyse(ctx, report, None)
    assert out.status == "not_needed" and not out.paths
