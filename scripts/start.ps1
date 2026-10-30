# One-command start on Windows: builds the UI (first run) and serves everything on http://127.0.0.1:8000
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    .\.venv\Scripts\python -m pip install -r backend\requirements.txt
}
if (-not (Test-Path "frontend\dist")) {
    Push-Location frontend; npm install; npm run build; Pop-Location
}
.\.venv\Scripts\python -m uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8000
