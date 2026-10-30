"""SQLite persistence. Jobs are stored as validated JSON documents plus a few indexed columns.

Repository source code is never stored in the database — only findings, short code excerpts
and diffs needed to explain results. Secret values are masked before they reach a model.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

from .models import AuditEvent, Job, utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    analysis_type TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
"""


class JobStore:
    def __init__(self, db_path: Path):
        self._path = db_path
        self._lock = threading.RLock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def save(self, job: Job) -> None:
        job.updated_at = utcnow()
        payload = job.model_dump_json()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO jobs (id, project_name, analysis_type, status, created_at, updated_at, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status,
                     updated_at=excluded.updated_at, data=excluded.data""",
                (job.id, job.project_name, job.analysis_type, job.status, job.created_at, job.updated_at, payload),
            )

    def get(self, job_id: str) -> Job | None:
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return Job.model_validate_json(row[0]) if row else None

    def list(self, limit: int = 100) -> list[Job]:
        with self._connect() as conn:
            rows = conn.execute("SELECT data FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        jobs = []
        for (data,) in rows:
            try:
                jobs.append(Job.model_validate_json(data))
            except Exception:  # a schema change should not take down the dashboard
                continue
        return jobs

    def update(self, job_id: str, mutate: Callable[[Job], None]) -> Job:
        """Atomic read-modify-write so the worker thread and API never clobber each other."""
        with self._lock:
            job = self.get(job_id)
            if job is None:
                raise KeyError(job_id)
            mutate(job)
            self.save(job)
            return job

    def count_active(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'running')").fetchone()[0]

    def delete(self, job_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))

    def add_audit(self, job_id: str, kind: str, message: str, agent: str | None = None) -> None:
        self.update(job_id, lambda j: j.audit.append(AuditEvent(kind=kind, message=message, agent=agent)))

    def stats(self) -> dict:
        """Dashboard metrics computed only from stored jobs."""
        jobs = self.list(limit=1000)
        bugs = sum(len(j.results.diagnosis.findings) for j in jobs if j.results.diagnosis)
        verified = sum(1 for j in jobs if j.results.verification and j.results.verification.status == "verified")
        sec = sum(len(j.results.security.findings) for j in jobs if j.results.security)
        projects = len({j.project_name for j in jobs})

        severity = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        categories: dict[str, int] = {}
        risk_by_project: dict[str, int] = {}
        for j in jobs:
            if not j.results.security:
                continue
            for f in j.results.security.findings:
                severity[f.severity] = severity.get(f.severity, 0) + 1
                categories[f.category] = categories.get(f.category, 0) + 1
                if f.severity in ("critical", "high"):
                    risk_by_project[j.project_name] = risk_by_project.get(j.project_name, 0) + 1

        # One outcome per job, from tool evidence (verification) or the job's final status.
        outcomes = {"verified": 0, "failed": 0, "inconclusive": 0, "completed": 0, "running": 0}
        for j in jobs:
            v = j.results.verification
            if j.status in ("running", "pending"):
                outcomes["running"] += 1
            elif v and v.status == "verified":
                outcomes["verified"] += 1
            elif j.status == "failed" or (v and v.status == "failed"):
                outcomes["failed"] += 1
            elif j.status in ("blocked", "inconclusive"):
                outcomes["inconclusive"] += 1
            else:
                outcomes["completed"] += 1

        repair_jobs = [j for j in jobs if j.results.verification]
        scanned = [j for j in jobs if j.results.security]
        highest = max(risk_by_project.items(), key=lambda kv: kv[1]) if risk_by_project else None
        return {
            "projects_analyzed": projects,
            "jobs_total": len(jobs),
            "bugs_identified": bugs,
            "patches_verified": verified,
            "security_findings": sec,
            "running": outcomes["running"],
            "failed_or_incomplete": sum(1 for j in jobs if j.status in ("failed", "blocked", "inconclusive")),
            "severity_counts": severity,
            "category_counts": categories,
            "outcomes": outcomes,
            "projects_with_high_risk": len(risk_by_project),
            "highest_risk_project": {"name": highest[0], "critical_high": highest[1]} if highest else None,
            "avg_findings_per_scan": round(sec / len(scanned), 1) if scanned else None,
            "verification_rate": round(verified / len(repair_jobs) * 100) if repair_jobs else None,
            "critical_ratio": round(severity["critical"] / sec * 100) if sec else None,
            "llm_cost_usd": round(sum(j.usage.estimated_cost_usd for j in jobs), 2),
            "tests_executed": sum(
                (j.results.reproduction.baseline_run.passed + j.results.reproduction.baseline_run.failed
                 if j.results.reproduction and j.results.reproduction.baseline_run else 0)
                + sum(v.patched_run.passed + v.patched_run.failed for v in j.results.verification_history if v.patched_run)
                for j in jobs
            ),
        }

    @staticmethod
    def dumps(obj) -> str:
        return json.dumps(obj, default=str)
