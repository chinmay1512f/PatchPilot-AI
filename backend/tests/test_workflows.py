"""End-to-end workflows through the orchestrator. Claude is scripted (FakeLLM); everything else
— archive handling, indexing, sandboxed pytest runs, scanners, diffing, verification status —
runs for real against the bundled sample repositories."""

import re

from conftest import SAMPLES, FakeLLM, copy_sample

from app.core.models import AnalysisType, JobOptions
from app.core.store import JobStore
from app.orchestrator import Orchestrator

PRICING = (SAMPLES / "buggy-shop/repo/shop/pricing.py").read_text()
BUG_LINE = next(i for i, l in enumerate(PRICING.splitlines(), 1) if "discounted_subtotal >" in l)
BUG = (SAMPLES / "buggy-shop/SAMPLE.md").read_text().split("bug_description: |", 1)[1]

NARRATIVE = {"overview": "Checkout pricing library.", "architecture": "cart uses pricing.", "important_files": [{"path": "shop/pricing.py", "role": "rules"}],
             "entry_points": ["shop/__init__.py", "shop/imaginary.py"], "initial_security_observations": [], "missing_information": []}
DIAGNOSIS = {"findings": [{"title": "Free-shipping threshold uses strict comparison", "file_path": "shop/pricing.py", "line_start": BUG_LINE, "line_end": BUG_LINE + 1,
                           "function_name": "shipping_cost", "description": "Exactly $50.00 is not > 50.00.", "severity": "medium",
                           "root_cause_hypothesis": "`>` should be `>=`", "evidence": ["docstring says 'or more'"], "reproduction_strategy": "cart of exactly 50.00",
                           "confidence": "high", "is_confirmed_by_reading": True, "recommended_next_step": "fix comparison"}],
             "primary_finding_index": 0, "alternative_hypotheses": ["discount rounding"], "summary": "Boundary bug in shipping_cost."}
REPRO = {"test_file_name": "test_patchpilot_repro.py", "rationale": "boundary", "expected_failure_on_buggy_code": "shipping 4.99",
         "edge_cases_covered": ["exactly 50", "49.99", "discount to 50"], "related_existing_tests": ["tests/test_cart.py::test_large_order_ships_free"],
         "test_code": (
             "from decimal import Decimal\nfrom shop import Cart\n\n"
             "def test_exactly_fifty_ships_free():\n    c = Cart()\n    c.add('T', 'Tee', '25.00', quantity=2)\n    assert c.checkout_totals()['shipping'] == Decimal('0.00')\n\n"
             "def test_just_below_pays_shipping():\n    c = Cart()\n    c.add('T', 'Tee', '49.99')\n    assert c.checkout_totals()['shipping'] == Decimal('4.99')\n")}
GOOD_FIX = {"summary": "Use >= for the free-shipping threshold.", "intended_behaviour": "50.00 ships free", "why_minimal": "one operator", "risk_notes": [],
            "edits": [{"file_path": "shop/pricing.py", "original_snippet": "    if discounted_subtotal > FREE_SHIPPING_THRESHOLD:",
                       "replacement_snippet": "    if discounted_subtotal >= FREE_SHIPPING_THRESHOLD:", "explanation": "inclusive boundary"}]}
BAD_FIX = {"summary": "Always free shipping.", "intended_behaviour": "x", "why_minimal": "x", "risk_notes": [],
           "edits": [{"file_path": "shop/pricing.py", "original_snippet": "    return STANDARD_SHIPPING", "replacement_snippet": "    return Decimal(\"0.00\")", "explanation": "wrong"}]}
COMMON = {
    "RepoNarrative": [NARRATIVE],
    "DiagnosisDraft": [DIAGNOSIS],
    "ReproTestDraft": [REPRO],
    "VerificationInterpretation": [{"assessment": "evidence supports fix", "unresolved_issues": [], "reviewer_notes": []}],
    "ScopeAssessmentDraft": [{"findings": [], "overall_assessment": "appears_minimal", "summary": "one-line change", "limitations": []}],
    "TriageDraft": [{"items": [], "summary": "nothing urgent"}],
    "ReportNarrative": [{"executive_summary": "Fixed.", "key_risks": [], "recommended_next_actions": ["review diff"]}],
    "MalwareDraft": [{"overall": "suspicious_needs_review", "summary": "Telemetry module collects the environment.", "items": [],
                      "recommended_actions": ["Review notes_app/telemetry.py"]}],
}


def _run(settings, sample, part, analysis, bug, llm, allow_local=True, modified=None):
    store = JobStore(settings.db_path)
    orch = Orchestrator(store, settings, llm_factory=lambda s, cb, name: (setattr(llm, "on_usage", cb), llm)[1])
    job, ws = orch.new_job(sample, analysis, bug, JobOptions(allow_local_execution=allow_local))
    ws.original.rmdir()
    copy_sample(sample, part, ws.original)
    if modified:
        copy_sample(sample, modified, ws.modified)
    store.save(job)
    orch.run(job.id)
    return store.get(job.id), ws


def test_full_repair_verified(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [GOOD_FIX]}, tool_script=[("read_file", {"path": "shop/pricing.py"})])
    job, ws = _run(settings, "buggy-shop", "repo", AnalysisType.full_repair, BUG, llm)
    r = job.results
    assert job.execution_backend == "local"
    assert r.repo.narrative.entry_points == ["shop/__init__.py"]  # invented path removed
    assert r.diagnosis.conclusive and r.diagnosis.findings[0].status == "confirmed"
    rp = r.reproduction
    assert rp.status == "reproduced"
    assert rp.baseline_run.passed == 6 and rp.baseline_run.failed == 0
    assert rp.repro_run.failed == 1 and rp.repro_run.passed == 1  # real execution: boundary test fails on buggy code
    v = r.verification
    assert v.status == "verified" and v.original_bug_status == "fixed"
    assert v.repro_after_patch.passed == 2 and v.repro_after_patch.failed == 0
    assert v.patched_run.passed == 8 and not v.new_failures
    p = r.patches[0]
    assert p.files_changed == ["shop/pricing.py"] and p.lines_added == 1 and p.lines_removed == 1
    assert "+    if discounted_subtotal >= FREE_SHIPPING_THRESHOLD:" in p.diff
    assert ">" in (ws.original / "shop/pricing.py").read_text() and ">=" not in (ws.original / "shop/pricing.py").read_text()  # original untouched
    assert r.patch_scope.metrics.implicated_functions == ["shipping_cost"] and not r.patch_scope.metrics.unrelated_function_candidates
    assert r.report and "Patch verified against the configured checks" in r.report.markdown
    assert "bug-free" not in r.report.markdown.replace("not that the code is free of bugs", "")
    assert job.status == "completed"
    assert job.usage.llm_calls > 0
    assert not (ws.runs).exists()  # disposable copies cleaned up


def test_failed_patch_triggers_bounded_retry(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [BAD_FIX, GOOD_FIX]}, tool_script=[])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_repair, BUG, llm)
    r = job.results
    assert len(r.patches) == 2
    first = r.verification_history[0]
    assert first.status == "failed" and first.new_failures  # always-free shipping breaks test_small_order_pays_shipping
    assert any("test_small_order_pays_shipping" in t for t in first.new_failures)
    assert r.verification.status == "verified"
    repair_prompt = [p for (a, m), p in zip(llm.calls, llm.prompts, strict=True) if m == "RepairDraft"][1]
    assert "Newly failing tests: tests.test_cart::test_small_order_pays_shipping" in repair_prompt  # real evidence fed back
    assert "reproduction test still fails" in repair_prompt


def test_retry_limit_enforced(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [BAD_FIX]}, tool_script=[])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_repair, BUG, llm)
    assert len(job.results.patches) == settings.max_repair_attempts
    assert job.results.verification.status == "failed"
    assert job.status == "failed" and job.agents["verification"].status == "failed"


def test_no_sandbox_consent_blocks_execution(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [GOOD_FIX]}, tool_script=[])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_repair, BUG, llm, allow_local=False)
    r = job.results
    assert job.execution_backend == "blocked"
    assert r.reproduction.status == "blocked" and r.reproduction.baseline_run.status == "blocked"
    assert job.agents["reproduction"].status == "blocked"
    assert r.verification.status == "blocked"  # a patch exists but is NOT reported as verified
    assert job.status != "completed"


def test_missing_api_key_degrades_honestly(settings):
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_repair, BUG, FakeLLM(available=False))
    a = job.agents
    assert a["repo_understanding"].status == "blocked" and "ANTHROPIC_API_KEY" in a["repo_understanding"].message
    assert a["bug_investigation"].status == "blocked"
    assert a["repair"].status == "skipped"
    assert job.results.repo.facts.indexed_files > 0  # deterministic facts still produced
    assert job.results.reproduction is None or job.results.reproduction.repro_run is None
    assert job.results.report.narrative is None and job.results.report.markdown
    assert not job.results.patches


def test_security_scan_flow(settings):
    def triage(prompt):
        ids = re.findall(r"finding_id=(sec_[a-f0-9]+)", prompt)
        return {"items": [{"finding_id": i, "verdict": "needs_review", "priority": "high", "rationale": "check"} for i in ids[:3]]
                + [{"finding_id": "sec_invented", "verdict": "likely_false_positive", "priority": "low", "rationale": "x"}], "summary": "review"}
    settings.disabled_scanners = ""  # exercise the real Semgrep integration here
    llm = FakeLLM(script={**COMMON, "TriageDraft": [triage]})
    job, _ = _run(settings, "insecure-notes", "repo", AnalysisType.security_scan, "", llm, allow_local=False)
    sec = job.results.security
    cats = {f.category for f in sec.findings}
    assert {"secret", "suspicious_code", "static_analysis"} <= cats
    assert {s.name for s in sec.scanners} >= {"bandit", "semgrep", "patchpilot-secrets", "patchpilot-suspicious"}
    assert sum(1 for f in sec.findings if f.ai_assessment) == 3  # invented finding id ignored
    assert job.agents["repair"].status == "skipped" and job.agents["reproduction"].status == "skipped"
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.snippet for f in sec.findings)
    assert "not confirmed malware" in job.results.report.markdown
    mw = sec.malware
    assert mw and mw.overall == "suspicious_needs_review" and mw.ai_status == "completed"
    assert "Sending data to webhooks, paste sites or tunnels" in mw.indicators_matched  # fixture's fake Discord webhook
    assert any("exfiltration" in f.references for f in sec.findings if f.category == "suspicious_code")
    assert "Malware check" in job.results.report.markdown and "malware check" in job.agents["verification"].message


def test_patch_review_flow(settings):
    scope = {"findings": [
        {"file_path": "inventory/stock.py", "line_start": 66, "line_end": 69, "category": "unrelated_function", "observation": "format_report rewritten",
         "reasoning": "formatting change unrelated to restock bug", "recommendation": "review", "confidence": "high", "could_be_justified_because": "none apparent"},
        {"file_path": "inventory/not_in_diff.py", "category": "other", "observation": "x", "reasoning": "x", "recommendation": "x", "confidence": "low",
         "could_be_justified_because": "x"}],
        "overall_assessment": "likely_excessive", "summary": "Fix is one operator; patch adds dependency and duplicates validation.", "limitations": []}
    llm = FakeLLM(script={**COMMON, "ScopeAssessmentDraft": [scope]})
    bug = "Items whose quantity equals their reorder level are not flagged: restock_needed() should use <=."
    job, ws = _run(settings, "overbroad-patch", "before", AnalysisType.patch_review, bug, llm, allow_local=False, modified="after")
    ps = job.results.patch_scope
    assert ps.overall_assessment == "likely_excessive"
    assert len(ps.findings) == 1 and ps.findings[0].evidence  # finding on unchanged file dropped; evidence attached
    assert "A smaller correction has not been independently verified" in ps.findings[0].verification_status
    assert (ws.modified / "inventory/stock.py").read_text().count("class InventoryValidator") == 1  # detector never rewrites code
    assert job.agents["repair"].status == "skipped"


def test_full_analysis_with_bug_runs_repair_and_security(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [GOOD_FIX]}, tool_script=[("read_file", {"path": "shop/pricing.py"})])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_analysis, BUG, llm)
    r = job.results
    assert r.verification.status == "verified" and r.security is not None and r.patch_scope is not None
    assert all(job.agents[a].status == "completed" for a in ("bug_investigation", "reproduction", "repair", "verification"))
    assert r.supplied_patch_scope is None  # nothing supplied


def test_full_analysis_without_bug_reviews_supplied_patch(settings):
    scope = {"findings": [], "overall_assessment": "likely_excessive", "summary": "broad", "limitations": []}
    llm = FakeLLM(script={**COMMON, "ScopeAssessmentDraft": [scope]})
    job, _ = _run(settings, "overbroad-patch", "before", AnalysisType.full_analysis, "", llm, allow_local=False, modified="after")
    r = job.results
    assert job.agents["bug_investigation"].status != "skipped"  # autonomous audit runs without a bug report
    assert r.diagnosis.mode == "discovery"
    assert job.agents["repair"].status == "skipped"  # scripted finding points at a file that does not exist here
    assert r.security is not None  # security scan of the original always runs
    sp = r.supplied_patch_scope
    assert sp and sp.subject == "user_supplied_patch" and sp.overall_assessment == "likely_excessive"
    assert "supplied patch" in job.agents["verification"].message
    assert "your supplied patch" in r.report.markdown


def test_full_analysis_discovers_proves_and_fixes_bug_without_description(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [GOOD_FIX]}, tool_script=[("read_file", {"path": "shop/pricing.py"})])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_analysis, "", llm)
    r = job.results
    assert job.bug_description == ""
    assert r.diagnosis.mode == "discovery" and "shop/pricing.py" in r.diagnosis.discovered_issue
    repro_prompt = next(p for (a, m), p in zip(llm.calls, llm.prompts, strict=True) if m == "ReproTestDraft")
    assert "Defect discovered by PatchPilot's code audit" in repro_prompt
    assert r.reproduction.status == "reproduced"  # proven by a real failing test before any patch
    assert r.verification.status == "verified" and r.patch_scope is not None
    assert "Bugs discovered by autonomous code audit" in r.report.markdown


def test_discovery_with_no_findings_does_not_patch(settings):
    empty = {"findings": [], "primary_finding_index": None, "alternative_hypotheses": [], "summary": "No defects found."}
    llm = FakeLLM(script={**COMMON, "DiagnosisDraft": [empty]})
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_analysis, "", llm)
    assert job.agents["bug_investigation"].status == "completed" and "no defect" in job.agents["bug_investigation"].message
    assert job.results.reproduction.status == "skipped" and job.results.reproduction.baseline_run.passed == 6
    assert job.agents["repair"].status == "skipped" and "no defect" in job.agents["repair"].message
    assert not job.results.patches and job.results.security is not None


def test_discovery_unconfirmed_by_test_is_not_patched(settings):
    passing = {**REPRO, "test_code": (
        "from decimal import Decimal\nfrom shop import Cart\n\n"
        "def test_large_order_free():\n    c = Cart()\n    c.add('H', 'Hoodie', '80.00')\n"
        "    assert c.checkout_totals()['shipping'] == Decimal('0.00')\n")}
    llm = FakeLLM(script={**COMMON, "ReproTestDraft": [passing], "RepairDraft": [GOOD_FIX]})
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_analysis, "", llm)
    assert job.results.reproduction.status == "not_reproduced"
    assert job.agents["repair"].status == "skipped" and "not confirmed by a failing test" in job.agents["repair"].message
    assert not job.results.patches


def test_security_lane_runs_in_parallel_with_agent_chain(settings):
    llm = FakeLLM(script={**COMMON, "RepairDraft": [GOOD_FIX]}, tool_script=[])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_analysis, BUG, llm)
    msgs = [(e.agent, e.message) for e in job.audit]
    lane_start = msgs.index(("verification", "[parallel lane] security & malware scan started"))
    understanding_done = next(i for i, (a, m) in enumerate(msgs) if a == "repo_understanding" and m.startswith("stage completed"))
    assert lane_start < understanding_done  # started before Agent 1 finished
    assert job.agents["verification"].lane == "parallel"
    assert any("[parallel lane] Security scan done" in m for _, m in msgs)
    assert job.results.security is not None and job.results.verification.status == "verified"


def test_security_lane_failure_does_not_break_repair(settings, monkeypatch):
    from app.agents import verification as ver

    def boom(ctx, include_osv=True):
        raise RuntimeError("scanner exploded")
    monkeypatch.setattr(ver, "security_review", boom)
    llm = FakeLLM(script={**COMMON, "RepairDraft": [GOOD_FIX]}, tool_script=[])
    job, _ = _run(settings, "buggy-shop", "repo", AnalysisType.full_repair, BUG, llm)
    assert job.results.verification.status == "verified"  # bug lane unaffected
    assert any("Security lane failed: RuntimeError: scanner exploded" in e.message for e in job.audit)
