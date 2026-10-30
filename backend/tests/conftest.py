"""Shared fixtures. Routine tests never call the paid Claude API: agents get a scripted FakeLLM
that implements the same interface as ``LLMClient``. Real-API tests live in
test_live_api.py and run only when PATCHPILOT_LIVE_TESTS=1."""

from __future__ import annotations

import os
import shutil
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
SAMPLES = BACKEND.parent / "samples"

from app.config import Settings  # noqa: E402
from app.llm.client import LLMNotConfigured, ToolLoopResult  # noqa: E402


class FakeLLM:
    """Scripted stand-in for LLMClient. ``script`` maps output model name -> list of responses
    (dicts or callables taking the prompt text). ``tool_script`` lists tool calls to perform."""

    mode = "live"

    def __init__(self, script: dict[str, list] | None = None, tool_script: list[tuple[str, dict]] | None = None,
                 available: bool = True, on_usage: Callable | None = None):
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.tool_script = tool_script or []
        self._available = available
        self.on_usage = on_usage
        self.calls: list[tuple[str, str]] = []
        self.prompts: list[str] = []
        self.model = "fake-model"

    def available(self):
        return (True, "ok") if self._available else (False, "ANTHROPIC_API_KEY is not configured on the server. AI reasoning stages cannot run.")

    def _text(self, messages) -> str:
        if isinstance(messages, str):
            return messages
        out = []
        for m in messages:
            c = m["content"]
            out.append(c if isinstance(c, str) else " ".join(str(b.get("text", b.get("content", ""))) if isinstance(b, dict) else str(b) for b in c))
        return "\n".join(out)

    def structured(self, *, agent, system, messages, output_model, effort=None, tools=None):
        if not self._available:
            raise LLMNotConfigured("not configured")
        text = self._text(messages)
        self.calls.append((agent, output_model.__name__))
        self.prompts.append(text)
        if self.on_usage:
            self.on_usage(agent, 100, 50, 0)
        queue = self.script.get(output_model.__name__)
        if not queue:
            raise AssertionError(f"FakeLLM has no scripted response for {output_model.__name__}")
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        data = item(text) if callable(item) else item
        return output_model.model_validate(data)

    def tool_loop(self, *, agent, system, user, tools, max_turns, effort=None):
        if not self._available:
            raise LLMNotConfigured("not configured")
        handlers = {t.name: t.handler for t in tools}
        res = ToolLoopResult(messages=[{"role": "user", "content": user}])
        for name, args in self.tool_script[:max_turns]:
            try:
                out = handlers[name](args)
                err = False
            except Exception as e:  # mirror real client behaviour
                out, err = f"error: {e}", True
            res.tool_calls.append({"tool": name, "input": args, "error": err})
            res.messages.append({"role": "assistant", "content": f"called {name}"})
            res.messages.append({"role": "user", "content": out})
        res.final_text = "investigation notes"
        res.messages.append({"role": "assistant", "content": res.final_text})
        return res

    def save_recording(self, name):
        return None


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path / "data", execution_backend="auto", osv_enabled=False, sandbox_timeout_seconds=60,
                 llm_mode="live", max_repair_attempts=2, disabled_scanners="semgrep")
    s.ensure_dirs()
    return s


@pytest.fixture(autouse=True)
def _no_real_key(monkeypatch):
    if os.environ.get("PATCHPILOT_LIVE_TESTS") != "1":
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)


def make_zip(src: Path, dest: Path) -> Path:
    with zipfile.ZipFile(dest, "w") as zf:
        for p in sorted(src.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                zf.write(p, p.relative_to(src).as_posix())
    return dest


def copy_sample(name: str, part: str, dest: Path) -> Path:
    shutil.copytree(SAMPLES / name / part, dest, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return dest
