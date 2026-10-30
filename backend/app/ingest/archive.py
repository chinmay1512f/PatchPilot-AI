"""Safe ZIP extraction.

Defends against: path traversal (``../``, absolute paths, drive letters), symlinks, zip bombs
(total size and per-entry compression ratio), too many entries, and device/special files.
Nothing is executed and no file permissions (exec bits) are preserved.
"""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path, PurePosixPath

# Directories never extracted: VCS metadata can carry hooks/filters that execute code when git
# runs, and build/dependency folders are noise for analysis.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".idea", ".vscode", ".next",
}


class ArchiveError(ValueError):
    """Raised for any archive that fails validation. Message is safe to show to users."""


def _safe_member_path(name: str) -> PurePosixPath | None:
    name = name.replace("\\", "/")
    if not name or name.endswith("/"):
        return None
    p = PurePosixPath(name)
    if p.is_absolute() or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise ArchiveError(f"Archive entry uses an absolute path: {name!r}")
    if any(part in ("..",) for part in p.parts):
        raise ArchiveError(f"Archive entry attempts path traversal: {name!r}")
    if any(part in SKIP_DIRS for part in p.parts):
        return None
    return p


def _strip_common_root(paths: list[PurePosixPath]) -> int:
    """If every entry lives under one top-level folder (typical GitHub ZIP), strip it."""
    if not paths:
        return 0
    first = {p.parts[0] for p in paths}
    if len(first) == 1 and all(len(p.parts) > 1 for p in paths):
        return 1
    return 0


def safe_extract_zip(
    zip_path: Path,
    dest: Path,
    *,
    max_total_bytes: int,
    max_files: int,
    max_ratio: int,
) -> dict:
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    if not zipfile.is_zipfile(zip_path):
        raise ArchiveError("Upload is not a valid ZIP archive.")

    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > max_files * 2:
            raise ArchiveError(f"Archive has too many entries ({len(infos)}).")

        selected: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        skipped = 0
        total = 0
        for info in infos:
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and (stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode)):
                raise ArchiveError(f"Archive contains a symlink or special file: {info.filename!r}")
            rel = _safe_member_path(info.filename)
            if rel is None:
                skipped += 1
                continue
            if info.flag_bits & 0x1:
                raise ArchiveError("Encrypted archives are not supported.")
            if info.compress_size > 0 and info.file_size / max(info.compress_size, 1) > max_ratio and info.file_size > 1_000_000:
                raise ArchiveError(f"Suspicious compression ratio for {info.filename!r} (possible zip bomb).")
            total += info.file_size
            if total > max_total_bytes:
                raise ArchiveError(f"Extracted size exceeds limit of {max_total_bytes // (1024 * 1024)} MB.")
            selected.append((info, rel))

        if len(selected) > max_files:
            raise ArchiveError(f"Archive has too many files ({len(selected)} > {max_files}).")
        if not selected:
            raise ArchiveError("Archive contains no usable files.")

        strip = _strip_common_root([rel for _, rel in selected])
        written = 0
        for info, rel in selected:
            parts = rel.parts[strip:]
            target = dest.joinpath(*parts).resolve()
            if not target.is_relative_to(dest):
                raise ArchiveError(f"Archive entry escapes destination: {info.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            # Stream with a hard cap in case the header lied about the size.
            remaining = info.file_size + 1
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(65536):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ArchiveError(f"Entry {info.filename!r} is larger than declared.")
                    out.write(chunk)
            written += 1

    return {"files_extracted": written, "entries_skipped": skipped, "bytes": total, "stripped_root": bool(strip)}
