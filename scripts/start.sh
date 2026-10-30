#!/usr/bin/env sh
# One-command start on macOS/Linux: serves everything on http://127.0.0.1:8000
set -e
cd "$(dirname "$0")/.."
[ -d .venv ] || { python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt; }
[ -d frontend/dist ] || (cd frontend && npm install && npm run build)
exec .venv/bin/python -m uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8000
