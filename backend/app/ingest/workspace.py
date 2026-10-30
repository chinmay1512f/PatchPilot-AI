"""Per-job workspace layout. The extracted upload under ``original/`` is never modified;
every test run and every patch attempt operates on a fresh disposable copy."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from .archive import SKIP_DIRS


class Workspace:
    def __init__(self, base: Path, job_id: str):
        if not job_id.replace("_", "").isalnum():
            raise ValueError("invalid job id")
        self.root = (base / job_id).resolve()
        self.original = self.root / "original"
        self.modified = self.root / "modified"  # user-supplied modified version (patch review)
        self.runs = self.root / "runs"
        self.uploads = self.root / "uploads"

    def create(self) -> None:
        for d in (self.original, self.runs, self.uploads):
            d.mkdir(parents=True, exist_ok=True)

    def fresh_copy(self, name: str, source: Path | None = None) -> Path:
        """Disposable copy of ``source`` (default: original) under runs/<name>."""
        if not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid copy name")
        dest = self.runs / name
        if dest.exists():
            remove_tree(dest)
        shutil.copytree(
            source or self.original,
            dest,
            symlinks=False,
            ignore=shutil.ignore_patterns(*SKIP_DIRS),
        )
        return dest

    def cleanup_runs(self) -> None:
        if self.runs.exists():
            remove_tree(self.runs)

    def delete(self) -> None:
        if self.root.exists():
            remove_tree(self.root)


def _on_rm_error(func, path, _exc):
    # Windows: read-only files (e.g. created by tests) block deletion.
    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, onexc=_on_rm_error)
