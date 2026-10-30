# Deploying PatchPilot AI (Vercel + Render)

| Part | Where | Why |
|---|---|---|
| Frontend (React) | **Vercel** | Static site, free Hobby plan. |
| Backend (FastAPI + agents + tools) | **Render**, Docker web service | Analyses run for minutes in the background, keep files on disk and run Pytest/Bandit/Semgrep — this needs a long-running server, not serverless functions. |

Your Anthropic API key is entered **only** in the Render dashboard. It is never committed, never sent to Vercel and never visible in the browser.

---

## 1. Backend on Render (do this first)

1. Go to <https://render.com> and **sign in with GitHub**.
2. Click **New → Blueprint** and pick the repository **PatchPilot-AI**.
   Render reads [`render.yaml`](../render.yaml) and shows a service called `patchpilot-api` (free plan, Docker).
3. When asked for **`ANTHROPIC_API_KEY`**, paste your key. Click **Apply** / **Deploy Blueprint**.
4. Wait for the first build (about 5–10 minutes). When it shows **Live**, copy the service URL, e.g. `https://patchpilot-api.onrender.com`.
5. Check it: open `https://<your-render-url>/api/health` in a browser. You should see
   `"status":"ok"`, `"api_key_configured":true` and `"demo_limits":{"per_hour":5,"per_day":25,"concurrent":1,…}`.

## 2. Frontend on Vercel

1. Go to <https://vercel.com> and **sign in with GitHub**.
2. **Add New → Project**, import **PatchPilot-AI**.
3. Set **Root Directory** to `frontend` (Framework preset: **Vite**, detected automatically).
4. Under **Environment Variables** add
   `VITE_API_BASE` = your Render URL from step 1.4 (no trailing slash).
5. Click **Deploy**. Your demo link is the Vercel URL, e.g. `https://patch-pilot-ai.vercel.app`.

Any `*.vercel.app` address is already allowed to call the backend (`PATCHPILOT_CORS_ORIGIN_REGEX` in `render.yaml`). If you add a custom domain, also set `PATCHPILOT_CORS_ORIGINS=https://your-domain` on Render.

## 3. Check the live demo

1. Open the Vercel link. The top bar should say **API connected**.
2. **New analysis** shows *"Public demo: up to 5 analyses per hour, 25 per day, one at a time."*
3. Use the **Buggy Shop** sample with **Initiate full analysis**, tick **I trust this repository**, and start.
4. When it finishes, the test runs should report the sandbox as *"separate unprivileged user (uid 10001)"*.
   If tests are instead *blocked* with "could not drop privileges", the host did not allow switching users — no repository code ran; send the message to your developer.

## 4. Protect your spending

* The backend allows **5 analyses per hour, 25 per day, one at a time** (change the `PATCHPILOT_MAX_*` variables in Render → Environment).
* Also set a **monthly spend limit** in the Anthropic Console (Settings → Limits).
* Rough cost: a full analysis is about $1.50–3 with fast mode on (shown as "est. $" on each analysis page).

## Free-tier notes

* Render's free service **sleeps** after about 15 minutes without visits; the first request then takes up to a minute. Open the link yourself shortly before judging.
* The free instance has no persistent disk: analysis history and the usage counters reset when it restarts.
* 512 MB memory: very large repositories may be slow or fail. Upgrading the Render instance removes the sleep and adds memory.

## Updating

Push to `main` on GitHub — Render and Vercel both redeploy automatically.

## Security model on the public server

There is no Docker-in-Docker on Render, so the **local restricted** sandbox is used, hardened for a shared server:

* Untrusted test code runs as a separate unprivileged user (`sandbox`, uid 10001) — it cannot read the server process's environment (the API key), the job database or other jobs' files.
* CPU/memory/process/file-size limits, a timeout, a scrubbed environment and a best-effort in-process network block.
* It is still **not** a hard isolation boundary like a dedicated VM or container per run; only analyse repositories you are willing to execute. Static scans (Bandit, Semgrep, secrets, OSV, malware indicators) never execute the code.
