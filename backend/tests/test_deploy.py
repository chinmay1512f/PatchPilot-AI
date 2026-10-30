"""Public-deployment safeguards: usage limits, CORS for a separately hosted frontend, sandbox user."""

import os
import time

import pytest
from conftest import SAMPLES, FakeLLM, make_zip
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.limits import JobLimiter, LimitExceeded
from app.main import create_app


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def test_limiter_hourly_daily_and_concurrent():
    clock = Clock()
    lim = JobLimiter(per_hour=2, per_day=3, concurrent=1, clock=clock)
    assert lim.status() == {"per_hour": 2, "per_day": 3, "concurrent": 1, "used_hour": 0, "used_day": 0}
    lim.reserve(active=0)
    with pytest.raises(LimitExceeded, match="already running"):
        lim.reserve(active=0)  # the in-flight reservation counts as running
    lim.commit()
    with pytest.raises(LimitExceeded, match="already running"):
        lim.reserve(active=1)
    lim.reserve(active=0)
    lim.commit()
    with pytest.raises(LimitExceeded, match="2 analyses per hour") as e:
        lim.reserve(active=0)
    assert 3500 < e.value.retry_after <= 3600
    clock.t += 3601  # next hour: hourly window frees up, daily cap still counts both
    lim.reserve(active=0)
    lim.commit()
    with pytest.raises(LimitExceeded, match="3 analyses per day"):
        lim.reserve(active=0)
    clock.t += 86400
    lim.reserve(active=0)  # a day later everything has expired
    lim.release()  # rejected upload: slot given back
    assert lim.status()["used_day"] == 0


def test_limiter_disabled_by_default():
    lim = JobLimiter()
    assert not lim.enabled and lim.status() is None
    for _ in range(50):
        lim.reserve(active=10)
        lim.commit()


def _client(tmp_path, **overrides):
    s = Settings(data_dir=tmp_path / "data", osv_enabled=False, llm_mode="live", disabled_scanners="semgrep", **overrides)
    s.ensure_dirs()
    app = create_app(s, llm_factory=lambda st, cb, name: FakeLLM(available=False), start_recovery=False)
    return TestClient(app), s


def _wait(client, job_id, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        if client.get(f"/api/jobs/{job_id}").json()["status"] not in ("pending", "running"):
            return
        time.sleep(0.3)
    raise AssertionError("job did not finish")


def test_api_enforces_hourly_limit_and_rejected_uploads_do_not_count(tmp_path):
    client, _ = _client(tmp_path, max_jobs_per_hour=1)
    with client:
        assert client.get("/api/health").json()["demo_limits"]["per_hour"] == 1
        bad = client.post("/api/jobs", files={"file": ("x.zip", b"not a zip")}, data={"analysis_type": "security_scan"})
        assert bad.status_code == 400  # rejected before work starts: no slot used
        z = make_zip(SAMPLES / "insecure-notes/repo", tmp_path / "n.zip").read_bytes()
        ok = client.post("/api/jobs", files={"file": ("n.zip", z)}, data={"analysis_type": "security_scan"})
        assert ok.status_code == 201
        _wait(client, ok.json()["id"])
        assert client.delete(f"/api/jobs/{ok.json()['id']}").status_code == 204  # deleting does not refund the slot
        r = client.post("/api/jobs", files={"file": ("n.zip", z)}, data={"analysis_type": "security_scan"})
        assert r.status_code == 429 and "per hour" in r.json()["detail"] and int(r.headers["retry-after"]) > 0
        assert client.get("/api/health").json()["demo_limits"]["used_hour"] == 1


def test_api_enforces_one_analysis_at_a_time(tmp_path):
    client, _ = _client(tmp_path, max_concurrent_jobs=1)
    with client:
        from app.core.models import AnalysisType, JobOptions, StageStatus
        orch = client.app.state.orchestrator
        job, _ = orch.new_job("busy", AnalysisType.security_scan, "", JobOptions())
        job.status = StageStatus.running
        client.app.state.store.save(job)
        z = make_zip(SAMPLES / "insecure-notes/repo", tmp_path / "n.zip").read_bytes()
        r = client.post("/api/jobs", files={"file": ("n.zip", z)}, data={"analysis_type": "security_scan"})
        assert r.status_code == 429 and "already running" in r.json()["detail"]


def test_no_limits_locally(tmp_path):
    client, _ = _client(tmp_path)
    with client:
        assert client.get("/api/health").json()["demo_limits"] is None


def test_cors_allows_configured_frontend_only(tmp_path):
    client, _ = _client(tmp_path, cors_origin_regex=r"^https://[A-Za-z0-9-]+\.vercel\.app$", cors_origins="https://demo.example.org")
    with client:
        for origin, allowed in (("https://patchpilot-ai.vercel.app", True), ("https://demo.example.org", True),
                                ("http://localhost:5173", True), ("https://evil.example.com", False),
                                ("https://vercel.app.evil.com", False)):
            r = client.options("/api/jobs", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
            assert (r.headers.get("access-control-allow-origin") == origin) is allowed, origin


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="POSIX non-root only")
def test_sandbox_user_fails_closed_without_root(tmp_path):
    from app.tools.sandbox import LocalRestrictedBackend
    s = Settings(data_dir=tmp_path / "data", sandbox_uid=10001)
    s.ensure_dirs()
    work = s.workspaces_dir / "job_0123456789" / "runs" / "x"
    work.mkdir(parents=True)
    res = LocalRestrictedBackend(s).run_python_tool(work, "pytest", ["-q"], 30)
    assert res.blocked and "not running as root" in res.blocked_reason
