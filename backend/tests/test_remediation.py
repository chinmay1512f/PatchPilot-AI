"""Security auto-remediation: fixes on a copy, judged only by re-running the scanners and the tests."""

from conftest import FakeLLM
from test_workflows import COMMON, _run

from app.agents.repair import apply_edits
from app.core.models import AnalysisType, FileEditDraft, RepairDraft

CREDS_REDACTED = ('AWS_ACCESS_KEY_ID = "[REDACTED_SECRET]"\nAWS_SECRET_ACCESS_KEY = "[REDACTED_SECRET]"\n'
                  'DB_PASSWORD = "[REDACTED_SECRET]"\n')
CREDS_FIXED = ('import os\n\nAWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")\n'
               'AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")\nDB_PASSWORD = os.environ.get("DB_PASSWORD", "")\n')


def _draft(edits):
    return RepairDraft(summary="s", intended_behaviour="", edits=[FileEditDraft(file_path=p, original_snippet=o, replacement_snippet=n, explanation="e")
                                                                  for p, o, n in edits], why_minimal="", risk_notes=[])


def test_apply_matches_redacted_secrets_but_never_writes_the_marker(tmp_path):
    (tmp_path / "cfg.py").write_text('KEY = "sk-live-123456"\nNAME = "x"\n', encoding="utf-8")
    ok = apply_edits(None, _draft([("cfg.py", 'KEY = "[REDACTED_SECRET]"', 'KEY = os.environ.get("KEY", "")')]), tmp_path)
    assert ok == [] and (tmp_path / "cfg.py").read_text() == 'KEY = os.environ.get("KEY", "")\nNAME = "x"\n'
    bad = apply_edits(None, _draft([("cfg.py", 'NAME = "x"', 'NAME = "[REDACTED_SECRET]"')]), tmp_path)
    assert bad and "redaction marker" in bad[0]
    assert 'NAME = "x"' in (tmp_path / "cfg.py").read_text()


def test_targets_are_spread_across_files():
    from app.agents.remediation import select_targets
    from app.core.models import Confidence, SecurityFinding, SecurityReport, Severity

    def f(i, path, sev, cat="static_analysis"):
        return SecurityFinding(id=f"sec_{i}", scanner="bandit", category=cat, rule_id="R", title="t", severity=sev,
                               confidence=Confidence.high, file_path=path, line=i, snippet="x")
    rep = SecurityReport(scanners=[], findings=[
        f(1, "app/cfg.py", Severity.critical, "secret"), f(2, "app/cfg.py", Severity.high, "secret"), f(3, "app/cfg.py", Severity.high, "secret"),
        f(4, "app/tools.py", Severity.high), f(5, "app/db.py", Severity.medium), f(6, "tests/test_db.py", Severity.critical),
        f(7, "app/sync.py", Severity.critical, "suspicious_code"), f(8, "requirements.txt", Severity.critical, "dependency")])
    assert [x.id for x in select_targets(rep, 3)] == ["sec_1", "sec_4", "sec_5"]  # one per file first; no tests/suspicious/deps
    assert [x.id for x in select_targets(rep, 5)] == ["sec_1", "sec_4", "sec_5", "sec_2", "sec_3"]


def fixer(prompt):
    """Scripted Claude: fix the hard-coded credentials in config.py (copied from the redacted view)."""
    assert "wJalrXUtnFEMI" not in prompt and "Pr0d-Passw0rd" not in prompt  # secrets never reach the model
    assert CREDS_REDACTED in prompt
    return {"summary": "Read credentials from the environment.",
            "edits": [{"file_path": "notes_app/config.py", "original_snippet": CREDS_REDACTED, "replacement_snippet": CREDS_FIXED,
                       "explanation": "no hard-coded secrets"}],
            "fixes": [], "skipped": [], "follow_ups": ["Rotate the AWS key pair."]}


def test_security_scan_remediation_end_to_end(settings):
    llm = FakeLLM(script={**COMMON, "RemediationDraft": [fixer]})
    job, ws = _run(settings, "insecure-notes", "repo", AnalysisType.security_scan, "", llm, allow_local=True, remediate=True)
    rem = job.results.remediation
    assert rem is not None and rem.status in ("verified", "partial"), (rem.status, rem.reasons)
    cleared = [t for t in rem.targets if t.outcome == "no_longer_reported"]
    assert cleared and all(t.file_path == "notes_app/config.py" for t in cleared)
    assert rem.tests_after and rem.tests_after.status == "completed" and not rem.new_failures
    assert rem.findings_after_count < rem.findings_before
    # the original upload is untouched; the shown/downloadable diff hides the secret values
    assert "wJalrXUtnFEMI" in (ws.original / "notes_app/config.py").read_text()
    assert "wJalrXUtnFEMI" not in rem.diff and rem.redacted_lines > 0
    assert any("Rotate" in f for f in rem.follow_ups)
    rs = job.results.risk_score
    assert rs.after_remediation and rs.after_remediation.score > rs.before.score
    assert job.agents["repair"].status == "completed" and "security fixes" in job.agents["repair"].message
    assert "## Security fixes" in job.results.report.markdown


def test_remediation_that_changes_nothing_is_reported_as_failed(settings):
    llm = FakeLLM(script={**COMMON, "RemediationDraft": [{"summary": "nothing safe", "edits": [], "fixes": [], "skipped": []}]})
    job, _ = _run(settings, "insecure-notes", "repo", AnalysisType.security_scan, "", llm, allow_local=False, remediate=True)
    rem = job.results.remediation
    assert rem.status == "failed" and rem.reasons and not rem.diff
    assert job.results.risk_score.after_remediation is None


def test_no_execution_means_untested_never_verified(settings):
    llm = FakeLLM(script={**COMMON, "RemediationDraft": [fixer]})
    job, _ = _run(settings, "insecure-notes", "repo", AnalysisType.security_scan, "", llm, allow_local=False, remediate=True)
    rem = job.results.remediation
    assert rem.status == "untested" and rem.tests_after is None
    assert any("not run" in r for r in rem.reasons)
