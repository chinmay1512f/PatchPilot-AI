// Mirrors backend/app/core/models.py — only the fields the UI reads.

export type StageStatus = "pending" | "running" | "completed" | "failed" | "skipped" | "blocked" | "inconclusive";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type AnalysisType = "full_analysis" | "full_repair" | "investigate_only" | "security_scan" | "patch_review";

export interface AgentRun {
  agent: string; title: string; status: StageStatus; started_at?: string; finished_at?: string; message: string;
  input_tokens: number; output_tokens: number; llm_calls: number; lane?: string | null;
}
export interface AuditEvent { at: string; kind: string; agent?: string; message: string }

export interface RepoFacts {
  total_files: number; indexed_files: number; skipped_files: number; total_lines: number;
  languages: { language: string; files: number; lines: number }[]; frameworks: string[]; manifests: string[];
  dependencies: { name: string; version?: string; ecosystem: string; manifest: string; pinned: boolean }[];
  test_framework?: string; test_files: string[]; config_files: string[]; env_var_references: string[];
  candidate_entry_points: string[]; special_files: { path: string; reason: string }[]; secrets_redacted: number; tree: string[];
  third_party_imports: string[]; missing_imports: string[];
}
export interface RepoSummary {
  facts: RepoFacts; narrative_status: string; limitations: string[];
  narrative?: { overview: string; architecture: string; important_files: { path: string; role: string }[]; entry_points: string[];
    initial_security_observations: string[]; missing_information: string[] } | null;
}
export interface BugFinding {
  id: string; title: string; file_path: string; line_start: number; line_end: number; function_name?: string; description: string;
  severity: Severity; root_cause_hypothesis: string; evidence: string[]; reproduction_strategy: string; confidence: Confidence;
  status: "confirmed" | "suspected" | "unverified_location"; recommended_next_step: string; location_verified: boolean;
  code_excerpt: string; validation_notes: string[];
}
export interface Diagnosis { mode: "reported" | "discovery"; discovered_issue: string; findings: BugFinding[]; primary_finding_id?: string; alternative_hypotheses: string[]; summary: string; conclusive: boolean; files_read: string[]; tool_calls: number }
export interface TestCase { nodeid: string; outcome: string; message: string; duration: number }
export interface TestRun {
  label: string; status: string; backend: string; command: string; exit_code?: number; duration_seconds: number;
  passed: number; failed: number; errors: number; skipped: number; tests: TestCase[]; output_tail: string; blocked_reason?: string;
  stubbed_modules?: string[];
}
export interface Reproduction {
  status: string; test_path?: string; test_code?: string; rationale: string; edge_cases: string[]; related_existing_tests: string[];
  baseline_run?: TestRun; repro_run?: TestRun; attempts: number; notes: string[];
}
export interface FileEdit { file_path: string; original_snippet: string; replacement_snippet: string; explanation: string }
export interface PatchProposal {
  id: string; attempt: number; summary: string; intended_behaviour: string; why_minimal: string; risk_notes: string[]; edits: FileEdit[];
  diff: string; files_changed: string[]; lines_added: number; lines_removed: number; apply_errors: string[]; applied: boolean;
}
export interface SecurityFinding {
  id: string; scanner: string; category: string; rule_id: string; title: string; severity: Severity; confidence: Confidence;
  file_path?: string; line?: number; snippet: string; description: string; references: string[]; introduced_by_patch: boolean;
  is_malware_confirmed: boolean; ai_assessment?: { verdict: string; rationale: string; priority: string } | null;
}
export interface ScannerRun { name: string; version?: string; status: string; findings: number; duration_seconds: number; message: string }
export interface MalwareAssessment {
  overall: "no_malicious_indicators" | "suspicious_needs_review" | "likely_malicious"; summary: string; ai_status: string;
  indicators_checked: string[]; indicators_matched: string[]; finding_ids: string[];
  items: { finding_id: string; verdict: "benign" | "suspicious" | "likely_malicious"; explanation: string }[];
  recommended_actions: string[]; signature_scan: string; limitations: string[];
}
export interface SecurityReport { scanners: ScannerRun[]; findings: SecurityFinding[]; triage_status: string; triage_summary: string; malware?: MalwareAssessment | null }
export interface ChangedFunction { file_path: string; name: string; kind: string; lines_changed: number; implicated: boolean; change_ratio: number }
export interface PatchScopeFinding {
  id: string; file_path: string; line_start?: number; line_end?: number; category: string; observation: string; reasoning: string;
  recommendation: string; confidence: Confidence; could_be_justified_because: string; evidence: string[]; verification_status: string;
}
export interface PatchScopeReport {
  subject: string; overall_assessment: string; summary: string; limitations: string[]; ai_status: string; diff: string;
  introduced_security: SecurityFinding[];
  findings: PatchScopeFinding[];
  metrics: { files_changed: number; lines_added: number; lines_removed: number; functions_changed: number; implicated_functions: string[];
    unrelated_function_candidates: string[]; new_imports: string[]; new_dependencies: string[]; new_definitions: string[];
    duplicated_blocks: string[]; formatting_only_hunks: number; changed_functions: ChangedFunction[] };
}
export interface VerificationResult {
  status: string; patch_id?: string; original_bug_status: string; baseline_run?: TestRun; patched_run?: TestRun; repro_after_patch?: TestRun;
  new_failures: string[]; fixed_tests: string[]; syntax_errors: string[]; new_lint_issues: string[]; dependency_changes: string[];
  patch_security_findings: SecurityFinding[]; checks_performed: string[]; checks_not_performed: string[]; reasons: string[];
  interpretation?: { assessment: string; unresolved_issues: string[]; reviewer_notes: string[] } | null;
}
export interface Report {
  generated_at: string; headline: string; overall_status: string; narrative_status: string; markdown: string;
  narrative?: { executive_summary: string; key_risks: string[]; recommended_next_actions: string[] } | null;
  unresolved_risks: string[]; checks_not_performed: string[];
}
export interface Job {
  id: string; project_name: string; analysis_type: AnalysisType; bug_description: string; status: StageStatus; current_stage?: string;
  created_at: string; updated_at: string; model: string; llm_mode: string; execution_backend: string; execution_backend_detail: string;
  agents: Record<string, AgentRun>; audit: AuditEvent[]; error?: string; source: string; modified_source?: string | null; has_modified_upload: boolean;
  options: { allow_local_execution: boolean; run_security_scan: boolean };
  usage: { input_tokens: number; output_tokens: number; llm_calls: number; fast_calls?: number; estimated_cost_usd: number };
  results: {
    repo?: RepoSummary; diagnosis?: Diagnosis; reproduction?: Reproduction; patches: PatchProposal[];
    verification?: VerificationResult; verification_history: VerificationResult[]; security?: SecurityReport;
    patch_scope?: PatchScopeReport; supplied_patch_scope?: PatchScopeReport | null; report?: Report;
  };
}
export interface JobSummary {
  id: string; project_name: string; analysis_type: AnalysisType; status: StageStatus; current_stage?: string; created_at: string;
  updated_at: string; bugs: number; security_findings: number; verification_status?: string; llm_mode: string; source?: string;
}
export interface Stats {
  projects_analyzed: number; jobs_total: number; bugs_identified: number; patches_verified: number; security_findings: number;
  running: number; failed_or_incomplete: number;
  severity_counts: Record<string, number>; category_counts: Record<string, number>; outcomes: Record<string, number>;
  projects_with_high_risk: number; highest_risk_project: { name: string; critical_high: number } | null;
  avg_findings_per_scan: number | null; verification_rate: number | null; critical_ratio: number | null;
  llm_cost_usd: number; tests_executed: number;
}
export interface Health {
  model: string; llm_mode: string; api_key_configured: boolean; fast_mode?: boolean;
  execution: { preference: string; docker: { available: boolean; detail: string }; local_restricted: { available: boolean; requires_consent: boolean } };
  scanners: Record<string, boolean>; limits: { max_upload_mb: number; sandbox_timeout_seconds: number; max_repair_attempts: number };
}
export interface Sample { name: string; title: string; analysis_type: AnalysisType; bug_description: string; description: string }
