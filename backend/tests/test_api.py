import io
import time
import zipfile

import pytest
from conftest import SAMPLES, FakeLLM, make_zip
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(settings):
    app = create_app(settings, llm_factory=lambda s, cb, name: FakeLLM(available=False), start_recovery=False)
    with TestClient(app) as c:
        yield c


def _wait(client, job_id, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("pending", "running"):
            return job
        time.sleep(0.5)
    raise AssertionError("job did not finish")


def test_health_reports_configuration(client):
    h = client.get("/api/health").json()
    assert h["api_key_configured"] is False
    assert h["execution"]["local_restricted"]["requires_consent"] is True
    assert "ANTHROPIC" not in str(h).replace("api_key_configured", "")


def test_upload_validation(client, tmp_path):
    r = client.post("/api/jobs", files={"file": ("x.txt", b"hello")}, data={"analysis_type": "security_scan"})
    assert r.status_code == 400
    r = client.post("/api/jobs", files={"file": ("x.zip", b"not a zip")}, data={"analysis_type": "security_scan"})
    assert r.status_code == 400 and "rejected" in r.json()["detail"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape.py", "x")
    r = client.post("/api/jobs", files={"file": ("e.zip", buf.getvalue())}, data={"analysis_type": "security_scan"})
    assert r.status_code == 400 and "traversal" in r.json()["detail"]
    r = client.post("/api/jobs", files={"file": ("e.zip", b"PK")}, data={"analysis_type": "full_repair", "bug_description": "short"})
    assert r.status_code == 400
    r = client.post("/api/jobs", files={"file": ("e.zip", b"PK")}, data={"analysis_type": "patch_review"})
    assert r.status_code == 400 and "modified" in r.json()["detail"]
    assert client.get("/api/jobs").json() == []  # rejected uploads leave no jobs behind


def test_oversized_request_rejected(client, settings):
    big = b"0" * ((settings.max_upload_mb * 2 + 3) * 1024 * 1024)
    r = client.post("/api/jobs", files={"file": ("big.zip", big)}, data={"analysis_type": "security_scan"})
    assert r.status_code == 413


def test_security_job_end_to_end_without_api_key(client, tmp_path):
    z = make_zip(SAMPLES / "insecure-notes/repo", tmp_path / "notes.zip")
    r = client.post("/api/jobs", files={"file": ("notes.zip", z.read_bytes())}, data={"analysis_type": "security_scan", "project_name": "notes"})
    assert r.status_code == 201
    job = _wait(client, r.json()["id"])
    assert job["agents"]["repo_understanding"]["status"] == "blocked"  # honest: no key, no AI summary
    assert job["results"]["security"]["findings"]
    assert job["results"]["security"]["triage_status"] == "unavailable"
    md = client.get(f"/api/jobs/{job['id']}/report.md")
    assert md.status_code == 200 and "Security" in md.text
    f = client.get(f"/api/jobs/{job['id']}/file", params={"path": "notes_app/config.py"})
    assert f.status_code == 200 and "AKIAIOSFODNN7EXAMPLE" not in f.text
    for bad in ("../../../patchpilot.db", "..\\..\\x", "/etc/passwd"):
        assert client.get(f"/api/jobs/{job['id']}/file", params={"path": bad}).status_code == 404
    stats = client.get("/api/stats").json()
    assert stats["jobs_total"] == 1 and stats["security_findings"] == len(job["results"]["security"]["findings"])
    assert sum(stats["severity_counts"].values()) == stats["security_findings"]
    assert sum(stats["outcomes"].values()) == 1 and stats["highest_risk_project"]["name"] == "notes"


def test_job_id_validation(client):
    assert client.get("/api/jobs/..%2F..%2Fetc").status_code == 404
    assert client.get("/api/unknown-endpoint").status_code == 404
    assert client.get("/api/jobs/job_zzzzzzzzzz").status_code == 404


def test_samples_listing_and_download(client):
    names = {s["name"]: s for s in client.get("/api/samples").json()}
    assert {"buggy-shop", "insecure-notes", "overbroad-patch"} <= set(names)
    assert "$50.00" in names["buggy-shop"]["bug_description"]
    r = client.get("/api/samples/overbroad-patch/download", params={"part": "modified"})
    assert r.status_code == 200 and zipfile.is_zipfile(io.BytesIO(r.content))
    assert client.get("/api/samples/..%2F..%2Fbackend/download").status_code == 404


def test_github_url_validation_and_full_analysis(client, tmp_path, monkeypatch):
    r = client.post("/api/jobs", data={"analysis_type": "security_scan", "repo_url": "https://github.com.evil.com/o/r"})
    assert r.status_code == 400 and "GitHub" in r.json()["detail"]
    r = client.post("/api/jobs", data={"analysis_type": "security_scan"})
    assert r.status_code == 400 and "exactly one" in r.json()["detail"]
    z = make_zip(SAMPLES / "insecure-notes/repo", tmp_path / "n.zip")
    r = client.post("/api/jobs", files={"file": ("n.zip", z.read_bytes())}, data={"analysis_type": "security_scan", "repo_url": "https://github.com/o/r"})
    assert r.status_code == 400

    import shutil
    from app.api import routes
    from app.ingest.github import parse_github_url

    def fake_download(url, dest, max_bytes):
        shutil.copy(z, dest)
        return parse_github_url(url)
    monkeypatch.setattr(routes, "download_github_zip", fake_download)
    r = client.post("/api/jobs", data={"analysis_type": "full_analysis", "repo_url": "https://github.com/acme/notes-app"})
    assert r.status_code == 201
    job = _wait(client, r.json()["id"])
    assert job["project_name"] == "notes-app" and job["source"] == "github:acme/notes-app"
    assert job["options"]["run_security_scan"] is True and job["results"]["security"]["findings"]
    assert job["agents"]["repair"]["status"] == "skipped"


def test_delete_job_removes_everything(client, settings, tmp_path):
    z = make_zip(SAMPLES / "insecure-notes/repo", tmp_path / "n.zip")
    job_id = client.post("/api/jobs", files={"file": ("n.zip", z.read_bytes())}, data={"analysis_type": "security_scan"}).json()["id"]
    _wait(client, job_id)
    ws = settings.workspaces_dir / job_id
    rec = settings.recordings_dir / f"{job_id}.json"
    rec.write_text("[]")
    assert ws.exists()
    assert client.delete(f"/api/jobs/{job_id}").status_code == 204
    assert not ws.exists() and not rec.exists()
    assert client.get(f"/api/jobs/{job_id}").status_code == 404
    assert all(j["id"] != job_id for j in client.get("/api/jobs").json())
    assert client.delete(f"/api/jobs/{job_id}").status_code == 404
    assert client.delete("/api/jobs/..%2F..%2Fdata").status_code in (404, 405)  # refused either way
    assert settings.db_path.exists() and settings.workspaces_dir.exists()


def test_cannot_delete_running_job(client, settings):
    from app.core.models import AnalysisType, JobOptions, StageStatus
    orch = client.app.state.orchestrator
    job, _ = orch.new_job("busy", AnalysisType.security_scan, "", JobOptions())
    job.status = StageStatus.running
    client.app.state.store.save(job)
    r = client.delete(f"/api/jobs/{job.id}")
    assert r.status_code == 409 and "still running" in r.json()["detail"]
