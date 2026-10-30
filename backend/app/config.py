"""Application settings. All values come from environment variables (or a local .env file).

The Anthropic API key is intentionally NOT stored on this object: the SDK reads it from the
environment itself, and we only ever check whether it is present. That keeps it out of
serialized settings, logs and API responses.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent

# Per-million-token prices (USD) used for cost *estimates* shown in the UI.
MODEL_PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (10.0, 50.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PATCHPILOT_",
        env_file=(PROJECT_DIR / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Claude ---
    model: str = "claude-opus-5-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    refusal_fallback: bool = True
    fast_mode: bool = True  # Claude fast mode: up to ~2.5x faster output at 2x price; falls back automatically
    llm_timeout_seconds: float = 300.0
    llm_max_retries: int = 2
    max_output_tokens: int = 16000
    # live: real API calls. record: real calls + save outputs. replay: reuse a recorded run
    # (clearly labelled in the UI; tool execution is still real).
    llm_mode: Literal["live", "record", "replay"] = "live"
    replay_file: str = ""
    job_token_budget: int = 600_000

    # --- Storage ---
    data_dir: Path = PROJECT_DIR / "data"

    # --- Upload limits ---
    max_upload_mb: int = 25
    max_extracted_mb: int = 150
    max_files: int = 5000
    max_compression_ratio: int = 100

    # --- Indexing / context ---
    max_index_file_kb: int = 256
    max_context_chars: int = 120_000

    # --- Execution sandbox ---
    execution_backend: Literal["auto", "docker", "local", "disabled"] = "auto"
    docker_image: str = "patchpilot-sandbox:latest"
    sandbox_timeout_seconds: int = 120
    sandbox_memory_mb: int = 1024
    sandbox_max_processes: int = 16
    # POSIX only: run untrusted test code as this unprivileged user id (the server must run as root to
    # switch to it). Used on public deployments so test code cannot read the server's environment
    # (e.g. the API key via /proc). 0 = off (local development).
    sandbox_uid: int = 0

    # --- Public demo protection (0 = no limit). In-memory, so the counters reset on restart. ---
    max_jobs_per_hour: int = 0
    max_jobs_per_day: int = 0
    max_concurrent_jobs: int = 0

    # --- CORS: browser origins allowed to call the API when the frontend is hosted elsewhere ---
    cors_origins: str = ""  # comma-separated, e.g. "https://patchpilot.vercel.app" ("*" = any)
    cors_origin_regex: str = ""  # e.g. "^https://.*\.vercel\.app$"

    # --- Workflow ---
    max_repair_attempts: int = 2
    max_repro_attempts: int = 2
    max_investigation_tool_turns: int = 12

    # --- Scanners ---
    osv_enabled: bool = True
    semgrep_config: str = ""  # empty = bundled local rules (no network)
    disabled_scanners: str = ""  # comma-separated, e.g. "semgrep,osv" — reported as skipped, never faked
    patch_recheck_semgrep: bool = False  # re-run Semgrep on the patched files (slow start on Windows); full-repo Semgrep scan always runs
    semgrep_max_memory_mb: int = 0  # 0 = Semgrep default; set on small servers (e.g. 512 MB hosts)
    scanner_timeout_seconds: int = 180

    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "patchpilot.db"

    @property
    def recordings_dir(self) -> Path:
        return self.data_dir / "recordings"

    def api_key_configured(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.workspaces_dir, self.recordings_dir):
            d.mkdir(parents=True, exist_ok=True)


def _load_dotenv_api_key() -> None:
    """Let ANTHROPIC_API_KEY live in the project .env without exporting it in the shell."""
    for env_file in (PROJECT_DIR / ".env", BACKEND_DIR / ".env"):
        if not env_file.is_file():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN") and value and key not in os.environ:
                os.environ[key] = value


@lru_cache
def get_settings() -> Settings:
    _load_dotenv_api_key()
    s = Settings()
    s.ensure_dirs()
    return s
