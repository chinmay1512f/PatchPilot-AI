"""HTTP routes. Thin layer: validation and serialization only; work happens in the orchestrator."""

from __future__ import annotations

import io
import re
import shutil
import zipfile
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool

from ..config import PROJECT_DIR
from ..core.models import AnalysisType, Job, JobOptions
from ..ingest.archive import SKIP_DIRS, ArchiveError, safe_extract_zip
from ..ingest.github import GitHubError, download_github_zip, parse_github_url
from ..ingest.indexer import build_index
from ..ingest.workspace import Workspace
from ..llm.client import FAST_MODELS
from ..tools.sandbox import DockerBackend
from ..tools.scanners import _which

router = APIRouter(prefix="/api")
SAMPLES_DIR = PROJECT_DIR / "samples"
_NAME_RE = re.compile(r"[^A-Za-z0-9 ._-]")


def _state(request: Request):
    return request.app.state.orchestrator, request.app.state.store, request.app.state.settings


async def _save_upload(upload: UploadFile, dest: Path, max_bytes: int) -> None:
    size = 0
    with open(dest, "wb") as out:
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(413, f"Upload exceeds the {max_bytes // (1024 * 1024)} MB limit.")
            out.write(chunk)


def _extract(settings, zip_path: Path, dest: Path) -> dict:
    try:
        return safe_extract_zip(zip_path, dest, max_total_bytes=settings.max_extracted_mb * 1024 * 1024,
                                max_files=settings.max_files, max_ratio=settings.max_compression_ratio)
    except ArchiveError as e:
        raise HTTPException(400, f"Archive rejected: {e}") from e


def _job_or_404(store, job_id: str) -> Job:
    if not re.fullmatch(r"job_[a-f0-9]{10}", job_id):
        raise HTTPException(404, "job not found")
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job


@router.get("/health")
def health(request: Request):
    _, _, s = _state(request)
    docker_ok, docker_msg = DockerBackend.available(s.docker_image)
    return {
        "status": "ok",
        "model": s.model,
        "fast_mode": bool(s.fast_mode and s.model in FAST_MODELS),
        "llm_mode": s.llm_mode,
        "api_key_configured": s.api_key_configured(),
        "execution": {"preference": s.execution_backend, "docker": {"available": docker_ok, "detail": docker_msg},
                      "local_restricted": {"available": True, "requires_consent": True}},
        "scanners": {name: bool(_which(name)) for name in ("bandit", "semgrep", "ruff", "gitleaks", "osv-scanner", "trivy")}
        | {"osv_api": s.osv_enabled, "builtin_secrets": True, "builtin_suspicious": True},
        "limits": {"max_upload_mb": s.max_upload_mb, "max_extracted_mb": s.max_extracted_mb, "max_files": s.max_files,
                   "sandbox_timeout_seconds": s.sandbox_timeout_seconds, "max_repair_attempts": s.max_repair_attempts},
    }


@router.get("/stats")
def stats(request: Request):
    _, store, _ = _state(request)
    return store.stats()


@router.get("/jobs")
def list_jobs(request: Request):
    _, store, _ = _state(request)
    return [j.summary() for j in store.list(limit=100)]


async def _acquire(s, ws, label: str, upload: UploadFile | None, url: str, dest: Path) -> tuple[dict, str, str]:
    """Get one repository version from either a ZIP upload or a GitHub URL. Returns (info, source, default_name)."""
    max_bytes = s.max_upload_mb * 1024 * 1024
    archive = ws.uploads / f"{label}.zip"
    if upload is not None and (upload.filename or ""):
        if not (upload.filename or "").lower().endswith(".zip"):
            raise HTTPException(400, f"Please upload the {label} repository as a .zip file.")
        await _save_upload(upload, archive, max_bytes)
        source, name = "upload", Path(upload.filename or "repository").stem
    else:
        try:
            gh = await run_in_threadpool(download_github_zip, url, archive, max_bytes=max_bytes)
        except GitHubError as e:
            raise HTTPException(400, str(e)) from e
        source, name = f"github:{gh.display}", gh.repo
    return _extract(s, archive, dest), source, name


@router.post("/jobs", status_code=201)
async def create_job(
    request: Request,
    file: UploadFile | None = None,
    repo_url: str = Form(""),
    analysis_type: AnalysisType = Form(AnalysisType.full_repair),
    project_name: str = Form(""),
    bug_description: str = Form(""),
    allow_local_execution: bool = Form(False),
    run_security_scan: bool = Form(True),
    modified_file: UploadFile | None = None,
    modified_repo_url: str = Form(""),
):
    orch, store, s = _state(request)
    has_file = file is not None and bool(file.filename)
    has_url = bool(repo_url.strip())
    if has_file == has_url:
        raise HTTPException(400, "Provide the repository either as a .zip upload or as a GitHub URL (exactly one).")
    if has_url:
        try:
            parse_github_url(repo_url)
        except GitHubError as e:
            raise HTTPException(400, str(e)) from e
    has_modified = (modified_file is not None and bool(modified_file.filename)) or bool(modified_repo_url.strip())
    if analysis_type == AnalysisType.patch_review and not has_modified:
        raise HTTPException(400, "Patch review needs both the original and the modified version (ZIP or GitHub URL).")
    if analysis_type in (AnalysisType.full_repair, AnalysisType.investigate_only) and len(bug_description.strip()) < 10:
        raise HTTPException(400, "Describe the bug (at least a sentence) for repair or investigation analyses.")
    if analysis_type == AnalysisType.full_analysis:
        run_security_scan = True  # full analysis always includes the security scan
        if bug_description.strip() and len(bug_description.strip()) < 10:
            raise HTTPException(400, "The bug description is too short — write at least a sentence, or leave it empty to skip repair.")
    use_modified = has_modified and analysis_type in (AnalysisType.patch_review, AnalysisType.full_analysis)

    job, ws = orch.new_job("pending", analysis_type, bug_description, JobOptions(allow_local_execution=allow_local_execution, run_security_scan=run_security_scan))
    try:
        info, source, default_name = await _acquire(s, ws, "original", file if has_file else None, repo_url, ws.original)
        job.source = source
        if use_modified:
            _, mod_source, _ = await _acquire(s, ws, "modified", modified_file if modified_file is not None and modified_file.filename else None,
                                             modified_repo_url, ws.modified)
            job.has_modified_upload, job.modified_source = True, mod_source
    except HTTPException:
        ws.delete()
        raise
    job.project_name = _NAME_RE.sub("", project_name or default_name)[:80] or "repository"
    store.save(job)
    where = f"downloaded from GitHub ({source.split(':', 1)[1]})" if source.startswith("github:") else "uploaded"
    store.add_audit(job.id, "upload", f"archive {where} and extracted safely: {info['files_extracted']} files, {info['entries_skipped']} entries skipped (VCS/build dirs)")
    orch.submit(job.id)
    return job.summary()


@router.get("/samples")
def samples():
    out = []
    if SAMPLES_DIR.is_dir():
        for d in sorted(SAMPLES_DIR.iterdir()):
            meta = d / "SAMPLE.md"
            if d.is_dir() and meta.is_file():
                text = meta.read_text(encoding="utf-8")
                fields = dict(re.findall(r"^(\w+):\s*(.+)$", text, re.M))
                out.append({"name": d.name, "title": fields.get("title", d.name), "analysis_type": fields.get("analysis_type", "full_repair"),
                            "bug_description": (re.search(r"^bug_description:\s*\|\n((?:  .*\n?)+)", text, re.M) or [None, ""])[1].replace("\n  ", "\n").strip(),
                            "description": fields.get("description", "")})
    return out


def _zip_dir(src: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src.rglob("*")):
            if p.is_file() and not any(x in SKIP_DIRS for x in p.relative_to(src).parts):
                zf.write(p, p.relative_to(src).as_posix())
    return buf.getvalue()


@router.get("/samples/{name}/download")
def download_sample(name: str, part: str = "repo"):
    d = SAMPLES_DIR / name
    if not re.fullmatch(r"[a-z0-9-]+", name) or not d.is_dir():
        raise HTTPException(404, "sample not found")
    src = d / ("after" if part == "modified" else "before") if (d / "before").is_dir() else d / "repo"
    if not src.is_dir():
        raise HTTPException(404, "sample part not found")
    return Response(_zip_dir(src), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{name}-{part}.zip"'})


@router.get("/jobs/{job_id}")
def get_job(request: Request, job_id: str):
    _, store, _ = _state(request)
    return _job_or_404(store, job_id)


@router.get("/jobs/{job_id}/file")
def get_file(request: Request, job_id: str, path: str, version: str = "original"):
    """Serve an indexed source file (secret-redacted) for the code viewer."""
    orch, store, s = _state(request)
    _job_or_404(store, job_id)
    ws = Workspace(s.workspaces_dir, job_id)
    root = ws.modified if version == "modified" else ws.original
    idx = build_index(root, max_file_kb=s.max_index_file_kb)
    f = idx.resolve(path)
    if f is None or f.text is None:
        raise HTTPException(404, "file not in repository index")
    from ..ingest.secrets import redact
    return PlainTextResponse(redact(f.text)[0])


@router.get("/jobs/{job_id}/report.md")
def report_md(request: Request, job_id: str):
    _, store, _ = _state(request)
    job = _job_or_404(store, job_id)
    if not job.results.report:
        raise HTTPException(409, "report not generated yet")
    return Response(job.results.report.markdown, media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="patchpilot-{job.id}.md"'})


@router.get("/jobs/{job_id}/report.json")
def report_json(request: Request, job_id: str):
    _, store, _ = _state(request)
    job = _job_or_404(store, job_id)
    return Response(job.model_dump_json(indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="patchpilot-{job.id}.json"'})


@router.get("/jobs/{job_id}/patch.diff")
def patch_diff(request: Request, job_id: str, attempt: int | None = None):
    _, store, _ = _state(request)
    job = _job_or_404(store, job_id)
    patches = job.results.patches
    if not patches:
        raise HTTPException(404, "no patch for this job")
    p = next((x for x in patches if x.attempt == attempt), patches[-1])
    return Response(p.diff, media_type="text/x-diff", headers={"Content-Disposition": f'attachment; filename="patchpilot-{job.id}-attempt{p.attempt}.diff"'})


@router.post("/jobs/{job_id}/rerun", status_code=201)
def rerun(request: Request, job_id: str):
    orch, store, s = _state(request)
    old = _job_or_404(store, job_id)
    old_ws = Workspace(s.workspaces_dir, old.id)
    if not old_ws.original.exists():
        raise HTTPException(410, "original upload no longer available")
    job, ws = orch.new_job(old.project_name, old.analysis_type, old.bug_description, old.options)
    shutil.copytree(old_ws.original, ws.original, dirs_exist_ok=True)
    if old_ws.modified.exists():
        shutil.copytree(old_ws.modified, ws.modified, dirs_exist_ok=True)
        job.has_modified_upload, job.modified_source = True, old.modified_source
    job.source = old.source
    store.save(job)
    store.add_audit(job.id, "rerun", f"re-run of {old.id}")
    orch.submit(job.id)
    return job.summary()


@router.delete("/jobs/{job_id}", status_code=204)
def delete_job(request: Request, job_id: str):
    _, store, s = _state(request)
    job = _job_or_404(store, job_id)
    if job.status in ("running", "pending"):
        raise HTTPException(409, "This analysis is still running; wait for it to finish before deleting it.")
    Workspace(s.workspaces_dir, job.id).delete()  # extracted code copy + uploads
    (s.recordings_dir / f"{job.id}.json").unlink(missing_ok=True)  # its replay recording, if any
    store.delete(job.id)
    return Response(status_code=204)
