"""Typed domain models shared by the agents, orchestrator, API and reports.

Conventions
- Anything produced by Claude is marked with ``source="model"``; anything produced by a real
  tool (test runner, scanner, file index) is ``source="tool"``. The UI and the report keep the
  two visibly separate.
- Severity (impact if real) and confidence (how sure we are) are separate fields on purpose.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- enums


class StageStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"
    blocked = "blocked"
    inconclusive = "inconclusive"


class AnalysisType(StrEnum):
    full_analysis = "full_analysis"  # everything that applies: repair (if a bug is described), security, supplied-patch review
    full_repair = "full_repair"
    investigate_only = "investigate_only"
    security_scan = "security_scan"
    patch_review = "patch_review"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


class VerificationStatus(StrEnum):
    verified = "verified"  # verified against the configured checks — never "bug-free"
    failed = "failed"
    incomplete = "incomplete"
    blocked = "blocked"
    inconclusive = "inconclusive"


AgentName = Literal[
    "repo_understanding",
    "bug_investigation",
    "reproduction",
    "repair",
    "verification",
    "reporting",
]

AGENT_ORDER: list[str] = [
    "repo_understanding",
    "bug_investigation",
    "reproduction",
    "repair",
    "verification",
    "reporting",
]

AGENT_TITLES: dict[str, str] = {
    "repo_understanding": "Repository Understanding",
    "bug_investigation": "Bug Investigation",
    "reproduction": "Reproduction & Test",
    "repair": "Repair",
    "verification": "Verification & Security",
    "reporting": "Evidence & Reporting",
}


# --------------------------------------------------------------------------- agent 1


class LanguageStat(BaseModel):
    language: str
    files: int
    lines: int


class Dependency(BaseModel):
    name: str
    version: str | None = None
    ecosystem: str  # PyPI, npm
    manifest: str
    pinned: bool = False


class SpecialFile(BaseModel):
    path: str
    reason: str


class RepoFacts(BaseModel):
    """Deterministic facts from the indexer (source = tool)."""

    total_files: int
    indexed_files: int
    skipped_files: int
    total_lines: int
    languages: list[LanguageStat]
    frameworks: list[str]
    manifests: list[str]
    dependencies: list[Dependency]
    test_framework: str | None
    test_files: list[str]
    config_files: list[str]
    env_var_references: list[str]
    candidate_entry_points: list[str]
    special_files: list[SpecialFile]
    secrets_redacted: int = 0
    third_party_imports: list[str] = Field(default_factory=list)  # top-level modules the code imports (not stdlib, not local)
    missing_imports: list[str] = Field(default_factory=list)  # of those, not installed in the sandbox interpreter
    tree: list[str] = Field(default_factory=list, description="Indexed file paths (truncated)")


class ImportantFile(BaseModel):
    path: str
    role: str


class RepoNarrative(BaseModel):
    """Claude's interpretation of the repository (source = model)."""

    overview: str = Field(description="2-4 sentence description of what the project does")
    architecture: str = Field(description="How the main modules relate to each other")
    important_files: list[ImportantFile]
    entry_points: list[str] = Field(description="Paths of likely entry points; must be real paths from the index")
    initial_security_observations: list[str]
    missing_information: list[str] = Field(description="Information that limits later analysis")


class RepoSummary(BaseModel):
    facts: RepoFacts
    narrative: RepoNarrative | None = None
    narrative_status: str = "not_run"
    limitations: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- agent 2


class BugFindingDraft(BaseModel):
    """What Claude returns; validated and enriched into BugFinding."""

    title: str
    file_path: str
    line_start: int
    line_end: int
    function_name: str | None = None
    description: str
    severity: Severity
    root_cause_hypothesis: str
    evidence: list[str] = Field(description="Concrete observations from code you actually read")
    reproduction_strategy: str
    confidence: Confidence
    is_confirmed_by_reading: bool = Field(
        description="True only if the defect is evident from code you read, not just plausible"
    )
    recommended_next_step: str


class DiagnosisDraft(BaseModel):
    findings: list[BugFindingDraft]
    primary_finding_index: int | None = Field(
        description="Index into findings of the defect that best explains the reported bug, or null"
    )
    alternative_hypotheses: list[str]
    summary: str


class BugFinding(BaseModel):
    id: str
    title: str
    file_path: str
    line_start: int
    line_end: int
    function_name: str | None = None
    description: str
    severity: Severity
    root_cause_hypothesis: str
    evidence: list[str]
    reproduction_strategy: str
    confidence: Confidence
    status: Literal["confirmed", "suspected", "unverified_location"]
    recommended_next_step: str
    location_verified: bool
    code_excerpt: str = ""
    validation_notes: list[str] = Field(default_factory=list)
    source: Literal["model"] = "model"


class Diagnosis(BaseModel):
    mode: Literal["reported", "discovery"] = "reported"  # discovery = proactive audit, no bug report given
    discovered_issue: str = ""  # discovery mode: the defect description handed to reproduction/repair
    findings: list[BugFinding]
    primary_finding_id: str | None
    alternative_hypotheses: list[str]
    summary: str
    conclusive: bool
    files_read: list[str] = Field(default_factory=list)
    tool_calls: int = 0


# --------------------------------------------------------------------------- tests / agent 3

TestOutcome = Literal["passed", "failed", "error", "skipped", "xfailed", "xpassed"]


class TestCaseResult(BaseModel):
    __test__ = False  # not a pytest test class

    nodeid: str
    outcome: TestOutcome
    message: str = ""
    duration: float = 0.0


class TestRun(BaseModel):
    """Result of an actual test-runner execution (source = tool)."""

    __test__ = False

    label: str
    status: Literal["completed", "blocked", "timeout", "error", "no_tests"]
    backend: str
    command: str
    exit_code: int | None = None
    duration_seconds: float = 0.0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    tests: list[TestCaseResult] = Field(default_factory=list)
    output_tail: str = ""
    blocked_reason: str | None = None
    stubbed_modules: list[str] = Field(default_factory=list)  # missing third-party packages replaced by inert stubs
    source: Literal["tool"] = "tool"

    @property
    def failing_ids(self) -> set[str]:
        return {t.nodeid for t in self.tests if t.outcome in ("failed", "error")}

    @property
    def passing_ids(self) -> set[str]:
        return {t.nodeid for t in self.tests if t.outcome == "passed"}


class ReproTestDraft(BaseModel):
    test_file_name: str = Field(description="File name only, e.g. test_patchpilot_repro.py")
    test_code: str = Field(description="Complete pytest module")
    rationale: str
    expected_failure_on_buggy_code: str
    edge_cases_covered: list[str]
    related_existing_tests: list[str]


class Reproduction(BaseModel):
    status: Literal["reproduced", "not_reproduced", "inconclusive", "blocked", "skipped"]
    test_path: str | None = None
    test_code: str | None = None
    rationale: str = ""
    edge_cases: list[str] = Field(default_factory=list)
    related_existing_tests: list[str] = Field(default_factory=list)
    baseline_run: TestRun | None = None
    repro_run: TestRun | None = None
    attempts: int = 0
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- agent 4


class FileEditDraft(BaseModel):
    file_path: str
    original_snippet: str = Field(description="Exact existing text to replace (copied verbatim, unique in file)")
    replacement_snippet: str
    explanation: str


class RepairDraft(BaseModel):
    summary: str
    intended_behaviour: str
    edits: list[FileEditDraft]
    why_minimal: str
    risk_notes: list[str]


class PatchProposal(BaseModel):
    id: str
    attempt: int
    summary: str
    intended_behaviour: str
    why_minimal: str
    risk_notes: list[str]
    edits: list[FileEditDraft]
    diff: str = ""
    files_changed: list[str] = Field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0
    apply_errors: list[str] = Field(default_factory=list)
    applied: bool = False
    source: Literal["model"] = "model"


# --------------------------------------------------------------------------- security


class AIAssessment(BaseModel):
    verdict: Literal["likely_true_positive", "likely_false_positive", "needs_review"]
    rationale: str
    priority: Literal["urgent", "high", "normal", "low"] = "normal"


class SecurityFinding(BaseModel):
    id: str
    scanner: str  # bandit, semgrep, ruff, secrets, gitleaks, osv, suspicious
    category: Literal[
        "static_analysis", "dependency", "secret", "suspicious_code", "patch_security", "lint"
    ]
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file_path: str | None = None
    line: int | None = None
    snippet: str = ""
    description: str = ""
    references: list[str] = Field(default_factory=list)
    introduced_by_patch: bool = False
    is_malware_confirmed: bool = False  # never set True by pattern matching alone
    ai_assessment: AIAssessment | None = None
    source: Literal["tool"] = "tool"


class ScannerRun(BaseModel):
    name: str
    version: str | None = None
    status: Literal["completed", "unavailable", "failed", "skipped", "timeout"]
    findings: int = 0
    duration_seconds: float = 0.0
    message: str = ""


class MalwareItemVerdict(BaseModel):
    finding_id: str
    verdict: Literal["benign", "suspicious", "likely_malicious"]
    explanation: str


class MalwareDraft(BaseModel):
    """Claude's review of the malware indicators (model output)."""

    overall: Literal["no_malicious_indicators", "suspicious_needs_review", "likely_malicious"]
    summary: str
    items: list[MalwareItemVerdict]
    recommended_actions: list[str]


class MalwareAssessment(BaseModel):
    """Malware check: deterministic indicators (+ optional antivirus signatures) reviewed by Claude."""

    overall: Literal["no_malicious_indicators", "suspicious_needs_review", "likely_malicious"]
    summary: str
    ai_status: str = "not_run"
    indicators_checked: list[str] = Field(default_factory=list)
    indicators_matched: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    items: list[MalwareItemVerdict] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    signature_scan: str = "not_run"  # ClamAV status
    limitations: list[str] = Field(default_factory=list)


class SecurityReport(BaseModel):
    scanners: list[ScannerRun]
    findings: list[SecurityFinding]
    triage_status: str = "not_run"
    triage_summary: str = ""
    malware: MalwareAssessment | None = None


# --------------------------------------------------------------------------- patch scope


class ChangedFunction(BaseModel):
    file_path: str
    name: str
    kind: Literal["modified", "added", "removed"]
    lines_changed: int
    implicated: bool
    change_ratio: float = 0.0


class PatchScopeMetrics(BaseModel):
    files_changed: int
    lines_added: int
    lines_removed: int
    functions_changed: int
    implicated_functions: list[str]
    unrelated_function_candidates: list[str]
    new_imports: list[str]
    new_dependencies: list[str]
    new_definitions: list[str]
    duplicated_blocks: list[str]
    formatting_only_hunks: int
    changed_functions: list[ChangedFunction]


class ScopeFindingDraft(BaseModel):
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    category: Literal[
        "unrelated_file",
        "unrelated_function",
        "excessive_rewrite",
        "duplicated_logic",
        "new_dependency",
        "new_abstraction",
        "formatting_noise",
        "other",
    ]
    observation: str
    reasoning: str
    recommendation: str
    confidence: Confidence
    could_be_justified_because: str = Field(
        description="Legitimate reasons this change might be required (security, correctness, compatibility); 'none apparent' if none"
    )


class ScopeAssessmentDraft(BaseModel):
    findings: list[ScopeFindingDraft]
    overall_assessment: Literal["appears_minimal", "possibly_broader_than_needed", "likely_excessive", "insufficient_information"]
    summary: str
    limitations: list[str]


class PatchScopeFinding(ScopeFindingDraft):
    id: str
    evidence: list[str] = Field(default_factory=list)
    verification_status: str = "A smaller correction has not been independently verified."
    source: Literal["model+tool"] = "model+tool"


class PatchScopeReport(BaseModel):
    subject: Literal["patchpilot_patch", "user_supplied_patch"]
    metrics: PatchScopeMetrics
    findings: list[PatchScopeFinding] = Field(default_factory=list)
    overall_assessment: str = "insufficient_information"
    summary: str = ""
    limitations: list[str] = Field(default_factory=list)
    ai_status: str = "not_run"
    diff: str = ""
    introduced_security: list[SecurityFinding] = Field(default_factory=list)  # findings only present after the change


# --------------------------------------------------------------------------- verification


class VerificationInterpretation(BaseModel):
    assessment: str = Field(description="Plain-language interpretation of the tool evidence")
    unresolved_issues: list[str]
    reviewer_notes: list[str]


class VerificationResult(BaseModel):
    status: VerificationStatus
    patch_id: str | None = None
    original_bug_status: Literal["fixed", "not_fixed", "unknown", "not_applicable"]
    baseline_run: TestRun | None = None
    patched_run: TestRun | None = None
    repro_after_patch: TestRun | None = None
    new_failures: list[str] = Field(default_factory=list)
    fixed_tests: list[str] = Field(default_factory=list)
    syntax_errors: list[str] = Field(default_factory=list)
    new_lint_issues: list[str] = Field(default_factory=list)
    dependency_changes: list[str] = Field(default_factory=list)
    patch_security_findings: list[SecurityFinding] = Field(default_factory=list)
    checks_performed: list[str] = Field(default_factory=list)
    checks_not_performed: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    interpretation: VerificationInterpretation | None = None


# --------------------------------------------------------------------------- report


class ReportNarrative(BaseModel):
    executive_summary: str
    key_risks: list[str]
    recommended_next_actions: list[str]


class Report(BaseModel):
    generated_at: str
    headline: str
    overall_status: str
    narrative: ReportNarrative | None = None
    narrative_status: str = "not_run"
    unresolved_risks: list[str] = Field(default_factory=list)
    checks_not_performed: list[str] = Field(default_factory=list)
    markdown: str = ""


# --------------------------------------------------------------------------- job


class AgentRun(BaseModel):
    agent: str
    title: str
    status: StageStatus = StageStatus.pending
    started_at: str | None = None
    finished_at: str | None = None
    message: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    llm_calls: int = 0
    lane: str | None = None  # "parallel" when the agent ran alongside others


class AuditEvent(BaseModel):
    at: str = Field(default_factory=utcnow)
    kind: str
    agent: str | None = None
    message: str


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    llm_calls: int = 0
    fast_calls: int = 0
    estimated_cost_usd: float = 0.0


class JobResults(BaseModel):
    repo: RepoSummary | None = None
    diagnosis: Diagnosis | None = None
    reproduction: Reproduction | None = None
    patches: list[PatchProposal] = Field(default_factory=list)
    verification: VerificationResult | None = None
    verification_history: list[VerificationResult] = Field(default_factory=list)
    security: SecurityReport | None = None
    patch_scope: PatchScopeReport | None = None  # PatchPilot's own patch (or the supplied one in patch_review jobs)
    supplied_patch_scope: PatchScopeReport | None = None  # user-supplied patch reviewed as part of a full analysis
    report: Report | None = None


class JobOptions(BaseModel):
    allow_local_execution: bool = False
    run_security_scan: bool = True
    max_repair_attempts: int | None = None


class Job(BaseModel):
    id: str
    project_name: str
    analysis_type: AnalysisType
    bug_description: str = ""
    options: JobOptions = Field(default_factory=JobOptions)
    status: StageStatus = StageStatus.pending
    current_stage: str | None = None
    created_at: str = Field(default_factory=utcnow)
    updated_at: str = Field(default_factory=utcnow)
    model: str = ""
    llm_mode: str = "live"
    execution_backend: str = "unknown"
    execution_backend_detail: str = ""
    agents: dict[str, AgentRun] = Field(default_factory=dict)
    results: JobResults = Field(default_factory=JobResults)
    usage: Usage = Field(default_factory=Usage)
    audit: list[AuditEvent] = Field(default_factory=list)
    error: str | None = None
    has_modified_upload: bool = False
    source: str = "upload"  # "upload" or "github:<owner>/<repo>[@ref]"
    modified_source: str | None = None

    def summary(self) -> dict:
        r = self.results
        sec = r.security.findings if r.security else []
        return {
            "id": self.id,
            "project_name": self.project_name,
            "analysis_type": self.analysis_type,
            "status": self.status,
            "current_stage": self.current_stage,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "bugs": len(r.diagnosis.findings) if r.diagnosis else 0,
            "security_findings": len(sec),
            "verification_status": r.verification.status if r.verification else None,
            "llm_mode": self.llm_mode,
            "source": self.source,
        }
