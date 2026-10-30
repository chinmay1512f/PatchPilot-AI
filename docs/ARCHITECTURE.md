# PatchPilot AI — Architecture & Implementation Plan

## 1. Environment findings (inspected 2026-10-29)

| Item | Status | Consequence |
|---|---|---|
| Project folder | Empty — new project | Clean structure below |
| OS | Windows 11 | Sandbox must work without Linux namespaces |
| Python 3.13, Node 22, git, pytest | Available | Backend in Python/FastAPI, frontend React+Vite |
| Docker / WSL | **Not installed** | Strong container isolation unavailable on this machine (see §5) |
| Semgrep, Gitleaks, OSV-Scanner, Trivy | Not installed | Bandit + Ruff + built-in scanners via pip; external scanners auto-detected if later added to PATH |
| `ANTHROPIC_API_KEY` | Not set | App starts, but AI stages report a configuration error until the key is set |

## 2. Layout

```
patchpilot/
  backend/app/
    main.py              FastAPI app factory, static frontend mount
    config.py            Settings (env vars, limits, model id)
    api/routes.py        HTTP routes only — no business logic
    core/models.py       Pydantic domain models (Job, BugFinding, PatchProposal, ...)
    core/store.py        SQLite persistence (jobs, agent runs, audit events)
    llm/client.py        Claude client: structured output, bounded retries, cost tracking, redaction
    ingest/archive.py    Safe ZIP extraction (path traversal, size, symlink, bomb checks)
    ingest/indexer.py    Repo index, language/framework detection, context selection
    ingest/secrets.py    Secret detection + redaction (used before any text goes to Claude)
    tools/sandbox.py     Execution worker: Docker / Windows Job Object / blocked
    tools/testing.py     Pytest runner via sandbox, JUnit XML parsing
    tools/scanners.py    Bandit, Ruff, Semgrep, Gitleaks, OSV (API), built-in rules
    tools/suspicious.py  AST + regex suspicious-behaviour rules
    tools/diffing.py     Unified diff generation/parsing, function-level change mapping
    agents/              six agents (see §3) + patch_scope.py
    orchestrator.py      Workflow state machine, conditional routing, retry limits
  backend/tests/         PatchPilot's own test suite (mocked Claude)
  frontend/              React + TypeScript + Vite dashboard
  samples/               Demo repos with known, harmless bugs / security issues
```

## 3. Agents and how they communicate

Agents never talk to each other directly. The **orchestrator** owns a `JobState` object and passes each agent only the typed slice it needs. Every agent output is a Pydantic model validated before the next stage runs.

| # | Agent | Claude does | Deterministic tools do |
|---|---|---|---|
| 1 | Repository Understanding | Summarize architecture, entry points, risks | Walk tree, detect languages/frameworks/tests/manifests, flag install hooks |
| 2 | Bug Investigation | Root-cause hypotheses (read-only tool loop: `list_files`, `read_file`, `search_code`) | Verify every cited file + line range actually exists |
| 3 | Reproduction & Test | Write a targeted pytest reproduction test | Run baseline suite + repro test in sandbox, parse JUnit results |
| 4 | Repair | Minimal search/replace edits with rationale | Apply to disposable copy, produce real `git`-style diff |
| 5 | Verification & Security | Interpret scanner output, judge patch scope | Re-run tests, compare to baseline, Bandit/Ruff/Semgrep/secrets/OSV/suspicious rules |
| 6 | Evidence & Reporting | Executive summary + next actions | Assemble report; every claim tagged `tool_evidence` vs `model_interpretation` |

**Unnecessary Patch Detection** (`agents/patch_scope.py`) is run inside Agent 5 for every repair, and standalone for "review an existing patch" jobs. It is read-only: deterministic diff metrics (files/functions touched vs. functions implicated by the diagnosis and failing test traceback, new imports/dependencies, duplicated blocks) + Claude's judgement. It never rewrites code.

### Conditional workflows
- `full_repair`: 1 → 2 → 3 → 4 → 5 → (retry 4→5 at most N times on failure) → 6
- `security_scan`: 1 → 5 (security only) → 6  (2, 3, 4 marked *skipped*)
- `patch_review`: 1 → patch scope + 5 on the supplied patch → 6
- `investigate_only`: 1 → 2 → 3 → 6
- Inconclusive diagnosis (no verified location) → repair is *skipped*, not guessed.

## 4. Claude API integration
- Official `anthropic` SDK, server-side only. Model from `PATCHPILOT_MODEL` (default `claude-opus-5-5`), effort per agent.
- Structured outputs via `messages.parse(output_format=PydanticModel)`; outputs re-validated; malformed → bounded retry → stage `failed`.
- Typed error handling (rate limit, auth, connection, 5xx), SDK retries capped, per-job token + cost ledger.
- **Prompt-injection defence:** repo content is wrapped in `<untrusted_repository_content>` blocks; system prompts state it is data; agents have no shell tool — the only tools are read-only file access scoped to the workspace; all execution is decided by the orchestrator, never by model output.
- **Secret hygiene:** files are passed through the secret redactor before being sent to Claude; findings store masked values only.
- Missing key → AI stages report `blocked: ANTHROPIC_API_KEY not configured`; nothing is fabricated.

## 5. Isolation of untrusted code
The original upload is extracted once into `workspaces/<job>/original` (read-only by convention) and every run uses a fresh copy.

Execution backends (chosen automatically, reported in the UI):
1. **Docker** (preferred, when installed): `--network none --cap-drop ALL --pids-limit --memory --cpus --read-only`, non-root, tmpfs, only the workspace copy mounted.
2. **Local restricted** (Windows Job Object / POSIX rlimits): memory cap, process-count cap, kill-on-close, wall-clock timeout, scrubbed environment (no API key, no HOME/credentials), best-effort socket blocking, no dependency installation. **This is not a security boundary**, so it is used only when the user explicitly ticks “I trust this repository” for that job.
3. Otherwise → execution **blocked**, reported as such. Static analysis still runs.

Repository dependency installation is never performed (no install hooks run).

## 6. Major risks
| Risk | Mitigation |
|---|---|
| No Docker on dev machine | Restricted local mode behind explicit per-job consent; Dockerfile provided |
| Live API failure during demo | Clear errors; optional, clearly-labelled replay of a previously recorded real run |
| Hallucinated locations | Post-validation of every file/line against the index; unverified findings are downgraded |
| Patch applies but breaks other things | Baseline-vs-patched full suite comparison, not just the repro test |
| Model refusals on security content | Detect `stop_reason == "refusal"`, record stage as blocked, continue other stages |
| Large repos | File-size caps, ignore lists, ranked context selection, token budget |

## 7. Phased plan
1. Config, models, store, Claude client, safe ingestion, indexer (✔ first)
2. Sandbox + pytest runner + scanners (deterministic, testable without Claude)
3. Six agents + orchestrator with conditional workflows and bounded retries
4. Sample repos + PatchPilot's own test suite (mocked Claude)
5. React dashboard: upload, live progress, bugs, patch diff, security, patch scope, report
6. End-to-end verification; demo script

**First end-to-end feature:** upload `samples/buggy-shop` → understanding → investigation → repro test fails on original → repair → repro test passes, full suite has no new failures → security scan → report.
