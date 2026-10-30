"""FastAPI application factory. Run with:  uvicorn app.main:app --port 8000  (from backend/)."""

from __future__ import annotations

import json
import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router
from .config import PROJECT_DIR, Settings, get_settings
from .core.limits import JobLimiter
from .core.store import JobStore
from .orchestrator import LLMFactory, Orchestrator
from .tools.sandbox import lock_down_data_dir


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": self.formatTime(record), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _setup_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("patchpilot")
    if not root.handlers:
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    logging.getLogger("anthropic").setLevel(logging.WARNING)  # never log request bodies/headers


def create_app(settings: Settings | None = None, llm_factory: LLMFactory | None = None, start_recovery: bool = True) -> FastAPI:
    _setup_logging()
    settings = settings or get_settings()
    if settings.sandbox_uid and os.name != "nt":
        os.umask(0o077)  # server files private by default; only sandbox work dirs are handed to the sandbox user
    settings.ensure_dirs()
    store = JobStore(settings.db_path)
    if settings.sandbox_uid and os.name != "nt":
        lock_down_data_dir(settings)
    orch = Orchestrator(store, settings, llm_factory)
    if start_recovery:
        orch.recover_interrupted()

    app = FastAPI(title="PatchPilot AI", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.settings, app.state.store, app.state.orchestrator = settings, store, orch
    app.state.limiter = JobLimiter(settings.max_jobs_per_hour, settings.max_jobs_per_day, settings.max_concurrent_jobs)

    max_body = (settings.max_upload_mb * 2 + 2) * 1024 * 1024

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > max_body:
            return JSONResponse({"detail": "Request too large."}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # Local dev (Vite) plus any configured origins, e.g. the Vercel-hosted frontend. The API uses no
    # cookies or credentials, so CORS here only controls which websites' browsers may call it.
    origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
    origins += [o.strip().rstrip("/") for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=["*"] if "*" in origins else origins,
                       allow_origin_regex=settings.cors_origin_regex or None,
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"], expose_headers=["Retry-After"])
    app.include_router(router)

    dist = PROJECT_DIR / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path == "api" or full_path.startswith("api/"):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
                return FileResponse(candidate)
            # never cache the HTML shell, so a rebuilt UI is picked up immediately (assets are content-hashed)
            return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})

    return app


_app: FastAPI | None = None


def __getattr__(name: str):
    """Create the app lazily so importing this module (e.g. in tests) has no side effects."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
