"""Repository indexing and context selection.

The index is built by reading files only — nothing in the repository is imported or executed.
Claude never receives the whole repository: agents ask for specific files/ranges through
read-only tools, and every excerpt passes through secret redaction first.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import Dependency, LanguageStat, RepoFacts, SpecialFile
from .archive import SKIP_DIRS
from .secrets import redact

LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".bat": "Batch", ".cmd": "Batch",
    ".html": "HTML", ".css": "CSS", ".sql": "SQL", ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML",
    ".json": "JSON", ".md": "Markdown",
}
CODE_LANGUAGES = {"Python", "JavaScript", "TypeScript", "Go", "Rust", "Java", "Kotlin", "Ruby", "PHP", "C#", "C", "C++", "Shell", "PowerShell", "Batch"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".whl", ".exe", ".dll", ".so", ".dylib", ".pyc", ".class", ".jar", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".db", ".sqlite"}
CONFIG_NAMES = {"setup.cfg", "tox.ini", "pytest.ini", "pyproject.toml", ".env.example", "Dockerfile", "docker-compose.yml", "Makefile", "tsconfig.json", "package.json", ".flake8", "mypy.ini", "conftest.py"}
FRAMEWORK_HINTS = {
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django", "starlette": "Starlette", "pytest": "pytest",
    "sqlalchemy": "SQLAlchemy", "pydantic": "Pydantic", "requests": "requests", "numpy": "NumPy",
    "pandas": "pandas", "react": "React", "express": "Express", "next": "Next.js", "vue": "Vue",
    "jest": "Jest", "vitest": "Vitest", "click": "Click", "typer": "Typer", "aiohttp": "aiohttp",
}
ENV_RE = re.compile(r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*['"]([A-Z0-9_]+)['"]|os\.getenv\(\s*['"]([A-Z0-9_]+)['"]|process\.env\.([A-Z0-9_]+))""")
REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([A-Za-z0-9_.\-*+]+)?")


def normalize_rel(path: str) -> str:
    """Normalise a model/user supplied relative path without changing its meaning."""
    rel = path.replace("\\", "/").strip()
    while rel.startswith("./"):
        rel = rel[2:]
    return rel.lstrip("/")


@dataclass
class IndexedFile:
    path: str  # posix, relative to repo root
    size: int
    language: str | None
    lines: int
    is_test: bool
    text: str | None = field(default=None, repr=False)  # raw (unredacted) text; never sent as-is


@dataclass
class RepoIndex:
    root: Path
    files: dict[str, IndexedFile]
    skipped: list[str]
    facts: RepoFacts

    # ---- read-only access used by agent tools -------------------------------------------
    def resolve(self, rel_path: str) -> IndexedFile | None:
        return self.files.get(normalize_rel(rel_path))

    def read_numbered(self, rel_path: str, start: int = 1, end: int | None = None, max_lines: int = 400) -> str:
        f = self.resolve(rel_path)
        if f is None or f.text is None:
            raise FileNotFoundError(rel_path)
        lines = f.text.splitlines()
        start = max(1, start)
        end = min(len(lines), end or len(lines), start + max_lines - 1)
        body = "\n".join(f"{i:>5}| {lines[i - 1]}" for i in range(start, end + 1))
        redacted, _ = redact(body)
        more = f"\n... ({len(lines) - end} more lines)" if end < len(lines) else ""
        return f"{f.path} (lines {start}-{end} of {len(lines)})\n{redacted}{more}"

    def excerpt(self, rel_path: str, line_start: int, line_end: int, context: int = 3) -> str:
        f = self.resolve(rel_path)
        if f is None or f.text is None:
            return ""
        lines = f.text.splitlines()
        a, b = max(1, line_start - context), min(len(lines), line_end + context)
        out = "\n".join(f"{i:>5}| {lines[i - 1]}" for i in range(a, b + 1))
        return redact(out)[0]

    def search(self, pattern: str, max_results: int = 40, regex: bool = False) -> list[str]:
        try:
            rx = re.compile(pattern if regex else re.escape(pattern), re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}") from e
        hits: list[str] = []
        for f in self.files.values():
            if f.text is None:
                continue
            for i, line in enumerate(f.text.splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{f.path}:{i}: {redact(line.strip()[:200])[0]}")
                    if len(hits) >= max_results:
                        return hits
        return hits

    def rank_files(self, query: str, limit: int = 8) -> list[str]:
        """Cheap relevance ranking used to seed agents with likely files."""
        words = {w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", query)}
        mentioned = set(re.findall(r"[\w./\\-]+\.py", query))
        scores: dict[str, float] = {}
        for f in self.files.values():
            if f.text is None or f.language not in CODE_LANGUAGES:
                continue
            score = 0.0
            if any(f.path.endswith(m.replace("\\", "/")) for m in mentioned):
                score += 50
            low = f.text.lower()
            stem = Path(f.path).stem.lower()
            for w in words:
                if w in stem:
                    score += 6
                score += min(low.count(w), 10) * 0.5
            if f.is_test:
                score *= 0.5
            if score > 0:
                scores[f.path] = score
        return [p for p, _ in sorted(scores.items(), key=lambda kv: -kv[1])[:limit]]


def _is_test_file(rel: str) -> bool:
    name = Path(rel).name
    parts = rel.split("/")
    return (
        name.startswith("test_") and name.endswith(".py")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
        or "tests" in parts[:-1]
        or "__tests__" in parts[:-1]
    )


def _parse_requirements(text: str, manifest: str) -> list[Dependency]:
    deps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_RE.match(line)
        if m:
            name = re.sub(r"\[.*\]", "", m.group(1))
            deps.append(Dependency(name=name, version=m.group(3), ecosystem="PyPI", manifest=manifest, pinned=m.group(2) == "=="))
    return deps


def _parse_pyproject(text: str, manifest: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    specs = list(data.get("project", {}).get("dependencies", []) or [])
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    deps = _parse_requirements("\n".join(specs), manifest)
    for name, ver in poetry.items():
        if name.lower() == "python":
            continue
        v = ver if isinstance(ver, str) else (ver.get("version") if isinstance(ver, dict) else None)
        pinned = bool(v and re.fullmatch(r"=?=?\d[\w.]*", v))
        deps.append(Dependency(name=name, version=(v or "").lstrip("=^~") or None, ecosystem="PyPI", manifest=manifest, pinned=pinned))
    return deps


def _parse_package_json(text: str, manifest: str) -> tuple[list[Dependency], dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], {}
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            if not isinstance(ver, str):
                continue
            clean = ver.lstrip("^~=v ")
            deps.append(Dependency(name=name, version=clean or None, ecosystem="npm", manifest=manifest, pinned=ver[:1].isdigit()))
    return deps, data.get("scripts") or {}


def third_party_imports(files: dict[str, IndexedFile]) -> tuple[list[str], list[str]]:
    """Top-level modules the repository imports that are neither stdlib nor part of the repo,
    and which of those are not installed for the sandbox interpreter. Parsed with ast, never imported."""
    local: set[str] = set()
    for path in files:
        parts = path.split("/")
        if parts[0] == "src" and len(parts) > 1:
            parts = parts[1:]
        if path.endswith(".py"):
            local.add(parts[0][:-3] if len(parts) == 1 else parts[0])
    found: set[str] = set()
    for f in files.values():
        if not f.path.endswith(".py") or not f.text:
            continue
        try:
            tree = ast.parse(f.text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    third = sorted(n for n in found if n and n not in stdlib and n not in local and n.isidentifier())
    missing = []
    for n in third:
        try:
            if importlib.util.find_spec(n) is None:
                missing.append(n)
        except (ImportError, ValueError):
            missing.append(n)
    return third, missing


def build_index(root: Path, *, max_file_kb: int = 256, max_tree: int = 400) -> RepoIndex:
    root = root.resolve()
    files: dict[str, IndexedFile] = {}
    skipped: list[str] = []
    total = 0
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in rel_parts) or ".patchpilot" in rel_parts:
            continue
        if path.is_symlink():
            skipped.append("/".join(rel_parts) + " (symlink)")
            continue
        if not path.is_file():
            continue
        total += 1
        rel = "/".join(rel_parts)
        size = path.stat().st_size
        ext = path.suffix.lower()
        lang = LANGUAGES.get(ext)
        if path.name == "Dockerfile":
            lang = "Dockerfile"
        if ext in BINARY_EXT or size > max_file_kb * 1024:
            skipped.append(rel)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            skipped.append(rel)
            continue
        files[rel] = IndexedFile(rel, size, lang, text.count("\n") + 1, _is_test_file(rel), text)

    # ---- languages
    lang_stats: dict[str, list[int]] = {}
    for f in files.values():
        if f.language:
            s = lang_stats.setdefault(f.language, [0, 0])
            s[0] += 1
            s[1] += f.lines
    languages = [LanguageStat(language=k, files=v[0], lines=v[1]) for k, v in sorted(lang_stats.items(), key=lambda kv: -kv[1][1])]

    # ---- manifests & dependencies
    deps: list[Dependency] = []
    manifests: list[str] = []
    special: list[SpecialFile] = []
    for f in files.values():
        name = Path(f.path).name
        if re.fullmatch(r"requirements.*\.txt", name):
            manifests.append(f.path)
            deps += _parse_requirements(f.text or "", f.path)
        elif name == "pyproject.toml":
            manifests.append(f.path)
            deps += _parse_pyproject(f.text or "", f.path)
        elif name == "package.json":
            manifests.append(f.path)
            d, scripts = _parse_package_json(f.text or "", f.path)
            deps += d
            for hook in ("preinstall", "install", "postinstall", "prepare"):
                if hook in scripts:
                    special.append(SpecialFile(path=f.path, reason=f"npm '{hook}' script runs on install: {str(scripts[hook])[:120]}"))
        elif name in ("setup.py",):
            manifests.append(f.path)
            special.append(SpecialFile(path=f.path, reason="setup.py executes arbitrary code at install/build time"))
            if "cmdclass" in (f.text or ""):
                special.append(SpecialFile(path=f.path, reason="setup.py overrides install commands (cmdclass)"))
        elif name in ("Pipfile", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "Cargo.toml", "Gemfile"):
            manifests.append(f.path)
        if f.language in ("Shell", "PowerShell", "Batch"):
            special.append(SpecialFile(path=f.path, reason=f"{f.language} script"))
        if name == "conftest.py":
            special.append(SpecialFile(path=f.path, reason="pytest conftest.py runs automatically when tests are collected"))
        if name.endswith(".pth"):
            special.append(SpecialFile(path=f.path, reason=".pth files can execute code at interpreter start-up"))

    # ---- frameworks
    blob_names = " ".join(d.name.lower() for d in deps)
    imports = " ".join((f.text or "")[:4000] for f in files.values() if f.language == "Python")
    frameworks = sorted({v for k, v in FRAMEWORK_HINTS.items() if re.search(rf"\b{k}\b", blob_names) or re.search(rf"^\s*(?:from|import)\s+{k}\b", imports, re.M)})

    # ---- tests
    test_files = sorted(f.path for f in files.values() if f.is_test and f.language in CODE_LANGUAGES)
    test_framework = None
    if any(f.endswith(".py") for f in test_files) or "pytest" in blob_names:
        test_framework = "pytest"
    elif any(re.search(r"\.(test|spec)\.[jt]sx?$", f) for f in test_files):
        test_framework = "jest/vitest"

    # ---- config, env vars, entry points
    config_files = sorted(f.path for f in files.values() if Path(f.path).name in CONFIG_NAMES or Path(f.path).name.startswith(".env"))
    env_vars: set[str] = set()
    entry_points: list[str] = []
    for f in files.values():
        if f.text is None:
            continue
        for m in ENV_RE.finditer(f.text):
            env_vars.add(next(g for g in m.groups() if g))
        if f.language == "Python" and not f.is_test:
            name = Path(f.path).name
            if name in ("main.py", "app.py", "__main__.py", "manage.py", "cli.py", "server.py", "wsgi.py", "asgi.py") or "__name__ == \"__main__\"" in f.text or "__name__ == '__main__'" in f.text:
                entry_points.append(f.path)

    secrets_count = sum(redact(f.text or "")[1] for f in files.values())
    third_party, missing = third_party_imports(files)

    facts = RepoFacts(
        total_files=total,
        indexed_files=len(files),
        skipped_files=len(skipped),
        total_lines=sum(f.lines for f in files.values()),
        languages=languages,
        frameworks=frameworks,
        manifests=sorted(manifests),
        dependencies=deps,
        test_framework=test_framework,
        test_files=test_files,
        config_files=config_files,
        env_var_references=sorted(env_vars),
        candidate_entry_points=sorted(entry_points),
        special_files=special,
        secrets_redacted=secrets_count,
        third_party_imports=third_party,
        missing_imports=missing,
        tree=sorted(files)[:max_tree],
    )
    return RepoIndex(root=root, files=files, skipped=skipped, facts=facts)
