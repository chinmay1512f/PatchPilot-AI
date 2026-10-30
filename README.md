# PatchPilot AI

**Claude-powered bug investigation, repair and security review — where every claim is backed by real execution or labelled as AI interpretation.**

**Live demo:** <https://patch-pilot-ai-kohl.vercel.app> · API: <https://patchpilot-api-tkay.onrender.com/api/health>
(free hosting: the first request after a quiet period can take about a minute while the server wakes up; public demo limited to 5 analyses per hour, one at a time)

AI coding tools write code fast, but their fixes are often unverified, too broad, or quietly insecure. PatchPilot takes a repository and a bug report and answers five questions with evidence:

1. **What is wrong?** — Claude investigates with read-only tools; every cited file/line is checked against the real code.
2. **Why?** — root-cause hypotheses with severity *and* confidence (kept separate).
3. **Can it be fixed?** — a minimal patch, applied only to a disposable copy.
4. **Does the fix actually work?** — a generated test must *really fail* on the original code and *really pass* after the patch, with the full suite re-run for regressions.
5. **What else should I worry about?** — static analysis, secrets, known-vulnerable dependencies, suspicious code, and **unnecessary changes** in AI-written patches.

PatchPilot never modifies your original repository, never reports a test as passed without running it, and never calls code "secure" or "bug-free".

---

## The six agents

| # | Agent | Claude does | Real tools do |
|---|---|---|---|
| 1 | Repository Understanding | Explains architecture, entry points, risks | Indexes files, languages, frameworks, tests, manifests, install hooks; redacts secrets |
| 2 | Bug Investigation | Reads code via `list_files` / `read_file` / `search_code` and diagnoses | Verifies every cited path, line range and function; downgrades hallucinations |
| 3 | Reproduction & Test | Writes a targeted pytest reproduction | Policy-vets the test, runs baseline + repro in the sandbox, parses JUnit |
| 4 | Repair | Proposes minimal search/replace edits | Applies to a copy (rejects test edits, path escapes, ambiguous snippets); diff computed from disk |
| 5 | Verification & Security | Triages findings, judges patch scope, interprets evidence, gives the **malware verdict** | Re-runs repro + full suite, regression diff, Ruff, Bandit, Semgrep, secrets, OSV, suspicious-code rules |
| 6 | Evidence & Reporting | Executive summary, next actions | Assembles the report; every section labelled *tool evidence* vs *AI* |

A central **orchestrator** owns state and decides what runs. Workflows are conditional:

- **Full analysis (recommended, no bug description needed):** 1 → 2 in *audit mode* (Claude hunts for real defects on its own) → 3 proves the top defect with a test that must fail on the original code → 4 → 5 (verify + full security scan) → review of a supplied modified version (if given) → 6. A defect the AI found is only patched once a failing test proves it is real.
- **Bug repair:** 1 → 2 → 3 → 4 → 5 → (bounded retry 4→5 with real failure evidence) → 6
- **Investigate only:** 1 → 2 → 3 → 6
- **Security scan:** 1 → 5 → 6
- **Review an AI patch:** 1 → 5 (unnecessary-change detection + security diff) → 6
- An inconclusive diagnosis **skips repair** rather than guessing.

**Parallel execution.** Agents only wait where they truly depend on each other. The security & malware lane (all scanners, AI triage, malware review) starts immediately and runs alongside Agents 1→2→3→4; the existing test suite runs in the background from the start; scanners run concurrently; the patch's security re-scan (Bandit, secrets, malware rules; Semgrep optional via `PATCHPILOT_PATCH_RECHECK_SEMGREP`, off by default because it takes ~20 s to start on Windows) runs while its tests run; and the unnecessary-change review starts as soon as a patch exists. Patch verification joins the security lane only where it needs the "before" findings. With Claude **fast mode** (`PATCHPILOT_FAST_MODE`, on by default, ~2× token price, automatic fallback to standard speed) a buggy-shop full analysis went from ≈157 s to ≈46 s.

### Malware check (part of Agent 5)
Every security scan includes a dedicated malware check with a plain verdict — *No malicious indicators found*, *Suspicious — needs human review* or *Likely malicious* (never "malware-free"). Static, read-only indicators cover 16 behaviour groups: reverse shells, download-and-run, obfuscated execution, credential theft (browser passwords, SSH/cloud keys, wallets), exfiltration to webhooks/paste sites/tunnels, keylogging and screen/clipboard capture, persistence (Run keys, cron, startup folders, services), shellcode/process injection, disabling antivirus/firewall/logs/backups, ransomware-like encrypt-and-delete loops, cryptomining, destructive commands, install hooks, hidden "Trojan Source" Unicode, compiled binaries committed to the repo, and look-alike (typosquatted) dependency names. If ClamAV is installed its signature scan runs too (otherwise the report says it did not). Claude then reviews each match with its surrounding code and the project's purpose, and labels it benign / suspicious / likely malicious. Code is never executed and payloads are never downloaded to "prove" anything.

### Unnecessary patch detection (detection only)
For PatchPilot's own patches and for patches you upload (original + modified ZIPs), PatchPilot computes deterministic evidence — which functions changed vs. which ones the bug actually implicates (from the diagnosis, the failing traceback and the bug text), new imports/dependencies/classes, duplicated blocks, formatting-only hunks — and Claude judges each change, explicitly recording *why it might be justified* (security, correctness, compatibility). It never rewrites code.

---

## Safety model

| Concern | What PatchPilot does |
|---|---|
| Untrusted code execution | Docker backend (`--network none`, `--cap-drop ALL`, read-only root, pids/memory/CPU limits, non-root) when available. Without Docker, code runs **only if the user ticks "I trust this repository"**, inside a Windows Job Object / POSIX rlimits with a scrubbed environment, process/memory caps, timeout and in-process network blocking — clearly labelled as *not* a hard boundary. Otherwise execution is **blocked** and reported as such. Dependencies are never installed. |
| Your original code | Extracted once to `original/`; every run and patch uses a fresh disposable copy, deleted afterwards. |
| GitHub URLs | Only `github.com/<owner>/<repo>[/tree/<ref>]` is accepted; the download URL is built server-side (no SSRF), the redirect is followed only to `codeload.github.com`, size-capped, then safely extracted. `git` is never run. Public repositories only. |
| Archives | Path traversal, absolute paths, symlinks, zip bombs, size and file-count limits; `.git` and build dirs dropped (git hooks/filters can execute code). |
| Prompt injection | Repository text, tool output and bug reports are wrapped as untrusted data (closing tags neutralised); agents only get read-only, workspace-scoped tools; the orchestrator — not the model — decides what executes. |
| Secrets | Detected and redacted before any text reaches Claude; only masked values are stored or shown. The API key is server-side only and never passed to sandboxed code. |
| Hallucinations | Cited files/lines/functions are verified; generated tests must fail for real; verification status is computed from tool results, never from model output. |
| Runaway agents | Bounded tool turns, repro attempts, repair attempts and a per-job token budget. |

---

## Quick start

Requirements: Python 3.11+, Node 18+. Docker optional.

```bash
cp .env.example .env          # then set ANTHROPIC_API_KEY
python -m venv .venv
.venv/Scripts/pip install -r backend/requirements.txt     # macOS/Linux: .venv/bin/pip
# Semgrep conflicts with FastAPI's dependencies, so it gets its own environment (optional):
python -m venv .venv-semgrep && .venv-semgrep/Scripts/pip install -r backend/requirements-semgrep.txt
cd frontend && npm install && npm run build && cd ..
.venv/Scripts/python -m uvicorn --app-dir backend app.main:app --port 8000
```

Open http://127.0.0.1:8000. Or just run `scripts/start.ps1` (Windows) / `scripts/start.sh`.

Optional stronger isolation: `docker build -t patchpilot-sandbox:latest sandbox/` — PatchPilot detects and uses it automatically.

For frontend development: `cd frontend && npm run dev` (Vite on :5173, proxies `/api` to :8000).

### Tests

```bash
cd backend
../.venv/Scripts/python -m pytest            # mocked Claude, real sandbox/scanners
PATCHPILOT_LIVE_TESTS=1 ../.venv/Scripts/python -m pytest tests/test_live_api.py   # real API (costs cents)
```

The suite covers archive attacks, secret redaction, sandbox isolation (no API key leakage, network blocked, timeout, process cap), JUnit parsing, Claude client errors (missing key, malformed output, refusal, rate limits, token budget, unknown tools), hallucinated-location handling, test-code vetting, patch-application guards (CRLF, test edits, path escapes), prompt-injection wrapping, and full end-to-end workflows on the sample repositories with real test execution.

---

## Demo repositories (`samples/`)

| Sample | Shows |
|---|---|
| `buggy-shop` | A real boundary bug ($50.00 orders charged shipping) that the existing 6 tests miss. Full flow: diagnosis → failing repro test → one-character fix → 8/8 tests pass. |
| `insecure-notes` | Intentionally insecure, harmless fixture: SQL/command injection, pickle, eval, unsafe YAML, AWS *documentation* example keys, vulnerable pinned deps (real CVEs from OSV), env-harvesting "telemetry" to a `.invalid` host, an obfuscated `exec` of a harmless print, a setup.py install hook. |
| `overbroad-patch` | An "AI fix" that changes `<` to `<=` but also rewrites unrelated functions, adds `requests`, duplicates validation in a new class and reformats code. |

Each is available in the UI under **New analysis → Bundled demo repositories** (it is uploaded through the same pipeline as any ZIP). See [docs/DEMO.md](docs/DEMO.md) for the presentation script.

---

## Configuration

All settings are environment variables (see `.env.example`): model (`PATCHPILOT_MODEL`, default `claude-opus-5-5`), effort, refusal fallback, execution backend, sandbox limits, repair attempts, token budget, scanner toggles, and `PATCHPILOT_LLM_MODE=record|replay` for a clearly-labelled replay of a previously recorded real run (tool execution stays live).

Public deployments add usage limits (`PATCHPILOT_MAX_JOBS_PER_HOUR`, `…_PER_DAY`, `…_CONCURRENT_JOBS`), allowed frontend origins (`PATCHPILOT_CORS_ORIGINS` / `PATCHPILOT_CORS_ORIGIN_REGEX`) and a separate unprivileged sandbox user (`PATCHPILOT_SANDBOX_UID`).

## Deployment

Frontend on **Vercel**, backend on **Render** (Docker): see [docs/DEPLOY.md](docs/DEPLOY.md). The backend needs a long-running server with a disk and the ability to run test tools, so it cannot run as Vercel serverless functions.

## Project structure

```
backend/app/
  agents/        six agents + patch_scope (unnecessary-change detection)
  api/routes.py  HTTP layer only
  core/          Pydantic models, SQLite store
  ingest/        safe archive extraction, indexer, secret redaction, workspaces
  llm/client.py  Claude client: structured outputs, tool loop, errors, budget, record/replay
  tools/         sandbox, pytest runner, scanners, suspicious-code rules, diffing
  orchestrator.py
backend/tests/   PatchPilot's own test suite
frontend/        React + TypeScript dashboard
samples/         demo repositories
docs/            architecture and demo script
```

## Known limitations

- Test execution supports Python/pytest today; the runner and scanners are adapter-based for other languages.
- Repository dependencies are never installed in the sandbox (by design: `pip install` can run arbitrary code). Missing third-party packages are replaced at import time by inert stand-ins so the repository's own logic can still be tested; every test run lists which packages were stubbed, and behaviour that depends on those libraries is not tested.
- Without Docker, local execution is resource-limited but not a security boundary; it requires explicit per-job consent.
- Suspicious-code detection is pattern-based and flags behaviour for review; it is not a malware verdict.
- Gitleaks, OSV-Scanner and Trivy are used automatically if installed on `PATH`; otherwise built-in secret detection and the OSV API are used, and the report says which ran.
