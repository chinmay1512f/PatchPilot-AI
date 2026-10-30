"""Optional integration test against the real Claude API.

Runs only when PATCHPILOT_LIVE_TESTS=1 and ANTHROPIC_API_KEY are set (costs a few cents):
    PATCHPILOT_LIVE_TESTS=1 pytest tests/test_live_api.py -v
"""

import os

import pytest
from conftest import copy_sample

from app.core.models import AnalysisType, JobOptions
from app.core.store import JobStore
from app.orchestrator import Orchestrator

pytestmark = [pytest.mark.live, pytest.mark.skipif(os.environ.get("PATCHPILOT_LIVE_TESTS") != "1" or not os.environ.get("ANTHROPIC_API_KEY"),
                                                   reason="live API tests disabled")]


def test_live_full_repair_on_buggy_shop(settings):
    settings.disabled_scanners = "semgrep"
    store = JobStore(settings.db_path)
    orch = Orchestrator(store, settings)
    bug = "Customers whose cart totals exactly $50.00 are charged $4.99 shipping, but orders of $50 or more should ship free."
    job, ws = orch.new_job("buggy-shop", AnalysisType.full_repair, bug, JobOptions(allow_local_execution=True))
    ws.original.rmdir()
    copy_sample("buggy-shop", "repo", ws.original)
    store.save(job)
    orch.run(job.id)
    job = store.get(job.id)
    assert job.results.diagnosis and any(f.file_path == "shop/pricing.py" for f in job.results.diagnosis.findings)
    assert job.results.reproduction.status == "reproduced"
    assert job.results.verification.status == "verified"
    assert job.usage.llm_calls > 0
