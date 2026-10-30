# Demo script (≈5 minutes)

**Before you present** (do this the same day):
1. `.env` contains a working `ANTHROPIC_API_KEY`; start the server; open http://127.0.0.1:8000.
2. Do one full rehearsal of each flow below. Keep those jobs — they are real results you can show if the network fails.
3. Fallback if the API/network fails on stage: `.env` already has `PATCHPILOT_LLM_MODE=record`, so every run saves Claude's outputs to `data/recordings/<job>.json`. A recording of a real buggy-shop run is ready at `data/recordings/demo-buggy-shop.json`. To use it, set in `.env`:
   ```
   PATCHPILOT_LLM_MODE=replay
   PATCHPILOT_REPLAY_FILE=data/recordings/demo-buggy-shop.json
   ```
   restart the server, and run the buggy-shop sample (only that sample matches the recording). The UI shows a **Replay mode** banner — say so out loud; tests and scanners still run live. Switch back to `record` afterwards.

**Measured on 2026-10-29 (live, claude-opus-5-5):** buggy-shop repair ≈ 2.5 min, ~11 Claude calls, ≈ $0.42; patch review ≈ 1 min; security scan ≈ 1 min. Start the buggy-shop run first and talk over it.

---

## 1. The problem (30s)
"AI tools generate fixes that *look* right. Nobody runs them, they touch unrelated code, and they can add vulnerabilities. PatchPilot makes Claude prove its work."

## 2. Bug repair — `buggy-shop` (2 min)
- New analysis → Bundled demo → **Buggy Shop → Use**. Point at the bug report ($50.00 orders charged shipping).
- Safety panel: no Docker here, so tick **"I trust this repository"** — explain the Job Object limits and that the API key is never visible to the code.
- Start. Narrate the six agents as they light up.
- **Bugs tab:** Claude read `shop/pricing.py` with read-only tools; location *verified* by PatchPilot; severity vs confidence.
- **Reproduction & tests:** existing suite 6/6 pass (the bug is invisible to it). Claude writes ~8 edge-case tests; exactly the boundary cases **actually fail** on the original code — that is the proof.
- **Bonus finding:** Claude also flags a second, real latent bug (`Cart.add` ignores a different price when merging the same SKU) — reported as *suspected*, and deliberately not patched.
- **Patch review:** one-character diff computed from disk; verification: repro test now passes, full suite all green (e.g. 16/16), zero regressions, no new security findings. "Verified against the configured checks" — never "bug-free".
- **Unnecessary changes:** PatchPilot's own patch → *appears minimal*, only `shipping_cost` touched.

## 2b. "Just give it a repo" — full analysis, no bug description (1 min, optional)
- New analysis → **Initiate full analysis** → Buggy Shop sample (or paste a GitHub URL) → tick trust → start. No bug description, no project name.
- Agent 2 runs as a **code audit** and finds the $50 boundary bug on its own (plus the suspected `Cart.add` issue); Agent 3's test fails on the original code; Agents 4–5 fix and verify it. Measured live with parallel lanes + fast mode: ≈ 46 s, ≈ $0.71 (was ≈ 157 s sequential).

## 3. Reviewing someone else's AI patch — `overbroad-patch` (1 min)
- Use the **Over-broad AI patch** sample (original + modified ZIPs).
- Security Center: the AI-added `requests==2.32.3` brings known CVEs, flagged **introduced by patch**.
- Unnecessary changes tab: only `restock_needed` is implicated; `total_value`, `format_report` rewritten; `requests` dependency + network call added; validation duplicated in a new class; formatting-only hunk.
- Emphasise: *detection only* — each finding says why it might still be justified; the developer decides.

## 4. Security — `insecure-notes` (1 min)
- Security Center: scanners table (versions, status — gitleaks honestly "unavailable"), real CVEs from OSV, secrets shown masked, injection flaws from Bandit/Semgrep.
- **Malware check** card at the top: verdict *Likely malicious* — env harvesting sent to a Discord webhook, Chrome password DB path, auto-start registry key, obfuscated `exec`, install hook. Point out that Claude noticed the README calls it a test fixture but did **not** accept repository text as proof of safety. Measured live: ≈ 1.5 min, ≈ $0.35.

## 5. Close (30s)
Final report tab → download Markdown. "Every claim is either tool evidence or labelled AI. Original code untouched. Patches are yours to apply."
