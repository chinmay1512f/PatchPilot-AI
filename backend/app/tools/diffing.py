"""Tree diffing and change analysis (pure Python, no git invocation on untrusted repos).

We deliberately do not run ``git`` against uploaded repositories: a repository's own
``.git/config`` can define hooks, filters and diff drivers that execute commands.
"""

from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..ingest.archive import SKIP_DIRS
from ..ingest.indexer import BINARY_EXT, _parse_package_json, _parse_pyproject, _parse_requirements


@dataclass
class LineRange:
    start: int  # 1-based inclusive
    end: int


@dataclass
class FileChange:
    path: str
    status: str  # added | removed | modified
    old_text: str
    new_text: str
    added: int = 0
    removed: int = 0
    old_ranges: list[LineRange] = field(default_factory=list)
    new_ranges: list[LineRange] = field(default_factory=list)
    formatting_only_hunks: int = 0
    diff: str = ""


def _read_tree(root: Path, max_kb: int = 512) -> dict[str, str]:
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for p in root.rglob("*"):
        parts = p.relative_to(root).parts
        if any(x in SKIP_DIRS for x in parts) or ".patchpilot" in parts or not p.is_file() or p.is_symlink():
            continue
        if p.suffix.lower() in BINARY_EXT or p.stat().st_size > max_kb * 1024:
            continue
        try:
            out["/".join(parts)] = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
    return out


_NORM = re.compile(r"\s+")


def _normalize(line: str) -> str:
    return _NORM.sub("", line).replace('"', "'").rstrip(",")


def compare_texts(path: str, old: str, new: str) -> FileChange:
    status = "added" if not old and new else "removed" if old and not new else "modified"
    a, b = old.splitlines(), new.splitlines()
    ch = FileChange(path=path, status=status, old_text=old, new_text=new)
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace" and [_normalize(x) for x in a[i1:i2] if x.strip()] == [_normalize(x) for x in b[j1:j2] if x.strip()]:
            ch.formatting_only_hunks += 1
        ch.removed += i2 - i1
        ch.added += j2 - j1
        if i2 > i1:
            ch.old_ranges.append(LineRange(i1 + 1, i2))
        else:
            ch.old_ranges.append(LineRange(max(i1, 1), max(i1, 1)))  # pure insertion: anchor line
        if j2 > j1:
            ch.new_ranges.append(LineRange(j1 + 1, j2))
    ch.diff = "".join(difflib.unified_diff(
        [x + "\n" for x in a], [x + "\n" for x in b],
        fromfile=f"a/{path}" if old else "/dev/null", tofile=f"b/{path}" if new else "/dev/null", n=3,
    ))
    return ch


def diff_trees(old_root: Path, new_root: Path) -> list[FileChange]:
    old, new = _read_tree(old_root), _read_tree(new_root)
    changes = []
    for path in sorted(set(old) | set(new)):
        o, n = old.get(path, ""), new.get(path, "")
        if o != n:
            changes.append(compare_texts(path, o, n))
    return changes


def combined_diff(changes: list[FileChange]) -> str:
    return "".join(c.diff for c in changes)


# --------------------------------------------------------------------------- function mapping


@dataclass
class FuncSpan:
    name: str
    start: int
    end: int
    body_hash: str


def function_spans(text: str) -> list[FuncSpan]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    spans: list[FuncSpan] = []

    def walk(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{prefix}{child.name}"
                start = min([d.lineno for d in getattr(child, "decorator_list", [])] + [child.lineno])
                end = getattr(child, "end_lineno", child.lineno) or child.lineno
                if not isinstance(child, ast.ClassDef):
                    spans.append(FuncSpan(qual, start, end, ast.dump(child)))
                walk(child, qual + ".")

    walk(tree)
    return spans


def _overlaps(r: LineRange, s: FuncSpan) -> int:
    return max(0, min(r.end, s.end) - max(r.start, s.start) + 1)


def changed_function_names(change: FileChange) -> dict[str, dict]:
    """Map a Python file change to the functions it touches."""
    if not change.path.endswith(".py"):
        return {}
    old_spans = {s.name: s for s in function_spans(change.old_text)}
    new_spans = {s.name: s for s in function_spans(change.new_text)}
    result: dict[str, dict] = {}
    for name, s in new_spans.items():
        if name not in old_spans:
            result[name] = {"kind": "added", "lines": s.end - s.start + 1, "ratio": 1.0}
    for name, s in old_spans.items():
        if name not in new_spans:
            result[name] = {"kind": "removed", "lines": s.end - s.start + 1, "ratio": 1.0}
    for name in old_spans.keys() & new_spans.keys():
        o, n = old_spans[name], new_spans[name]
        if o.body_hash == n.body_hash:
            continue
        old_lines = change.old_text.splitlines()[o.start - 1 : o.end]
        new_lines = change.new_text.splitlines()[n.start - 1 : n.end]
        sm = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
        changed = sum(max(i2 - i1, j2 - j1) for t, i1, i2, j1, j2 in sm.get_opcodes() if t != "equal")
        if changed == 0:
            continue
        result[name] = {"kind": "modified", "lines": changed, "ratio": min(1.0, round(changed / max(len(old_lines), 1), 2))}
    return result


def enclosing_function(text: str, line: int) -> str | None:
    best = None
    for s in function_spans(text):
        if s.start <= line <= s.end and (best is None or s.start >= best.start):
            best = s
    return best.name if best else None


# --------------------------------------------------------------------------- additions analysis

_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))")


def added_lines(change: FileChange) -> list[str]:
    b = change.new_text.splitlines()
    return [b[i - 1] for r in change.new_ranges for i in range(r.start, r.end + 1) if 0 < i <= len(b)]


def new_imports(change: FileChange) -> list[str]:
    old_imports = {m.group(1) or m.group(2) for m in map(_IMPORT_RE.match, change.old_text.splitlines()) if m}
    out = []
    for line in added_lines(change):
        m = _IMPORT_RE.match(line)
        if m and (m.group(1) or m.group(2)) not in old_imports:
            out.append(f"{change.path}: {line.strip()}")
    return out


def duplicated_blocks(change: FileChange, corpus: dict[str, str], min_lines: int = 4) -> list[str]:
    """Added blocks of >= min_lines that already exist (normalised) elsewhere in the code."""
    b = change.new_text.splitlines()
    out = []
    for r in change.new_ranges:
        block = [_normalize(x) for x in b[r.start - 1 : r.end] if x.strip()]
        if len(block) < min_lines:
            continue
        for i in range(0, len(block) - min_lines + 1):
            window = "\n".join(block[i : i + min_lines])
            for path, text in corpus.items():
                norm = "\n".join(_normalize(x) for x in text.splitlines() if x.strip())
                count = norm.count(window)
                if (path == change.path and count > 1) or (path != change.path and count >= 1):
                    out.append(f"{change.path}:{r.start}-{r.end} duplicates logic already present in {path}")
                    break
            else:
                continue
            break
    return out


def dependency_names(path: str, text: str) -> set[str]:
    name = Path(path).name
    if re.fullmatch(r"requirements.*\.txt", name):
        return {d.name.lower() for d in _parse_requirements(text, path)}
    if name == "pyproject.toml":
        return {d.name.lower() for d in _parse_pyproject(text, path)}
    if name == "package.json":
        return {d.name.lower() for d in _parse_package_json(text, path)[0]}
    return set()


def dependency_changes(changes: list[FileChange]) -> list[str]:
    out = []
    for c in changes:
        before, after = dependency_names(c.path, c.old_text), dependency_names(c.path, c.new_text)
        out += [f"added dependency '{d}' in {c.path}" for d in sorted(after - before)]
        out += [f"removed dependency '{d}' from {c.path}" for d in sorted(before - after)]
    return out


def read_tree_text(root: Path) -> dict[str, str]:
    return _read_tree(root)
