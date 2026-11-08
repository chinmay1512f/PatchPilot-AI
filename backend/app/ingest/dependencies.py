"""Exact dependency versions for the vulnerability check.

Security advisories (OSV.dev) are recorded per exact version, so "next ^15.5.25" cannot be checked as
written. In order of preference:
1. Lock files — the exact versions a project really installs, including indirect packages:
   package-lock.json, yarn.lock, poetry.lock, Pipfile.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock.
2. Version ranges in package.json / requirements.txt / pyproject.toml without a lock file — resolved
   at scan time to the newest version the range allows (what a fresh install gets today), via the npm
   or PyPI registry. These are labelled "resolved" so nobody mistakes them for the installed version.
Lock files are parsed as data only; nothing is installed or executed.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import httpx

from ..core.models import Dependency

MAX_LOCK_BYTES = 30 * 1024 * 1024
LOCK_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "poetry.lock", "Pipfile.lock", "go.mod", "Cargo.lock",
              "Gemfile.lock", "composer.lock"}
# Dependency files PatchPilot recognises but cannot read versions from yet.
UNSUPPORTED = {"pom.xml": "Java (Maven)", "build.gradle": "Java/Kotlin (Gradle)", "build.gradle.kts": "Kotlin (Gradle)",
               "packages.config": ".NET", "Package.swift": "Swift", "pubspec.yaml": "Dart", "mix.exs": "Elixir",
               "pnpm-lock.yaml": "pnpm"}


def _dep(name: str, version: str, eco: str, manifest: str, direct: bool) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=eco, manifest=manifest, pinned=True, direct=direct, source="lockfile")


# --------------------------------------------------------------------------- lock-file parsers


def _npm_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    out: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        root = packages.get("", {}) or {}
        direct = set((root.get("dependencies") or {}) | (root.get("devDependencies") or {}) | (root.get("optionalDependencies") or {}))
        for key, info in packages.items():
            if not key or not isinstance(info, dict) or info.get("link") or "node_modules/" not in key:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[1]
            if info.get("version"):
                out.append(_dep(name, str(info["version"]), "npm", manifest, name in direct and key == f"node_modules/{name}"))
        return out

    def walk(deps: dict, top: bool) -> None:  # lockfileVersion 1
        for name, info in (deps or {}).items():
            if isinstance(info, dict) and info.get("version") and not str(info["version"]).startswith(("file:", "git", "http")):
                out.append(_dep(name, str(info["version"]), "npm", manifest, top))
                walk(info.get("dependencies") or {}, False)
    walk(data.get("dependencies") or {}, True)
    return out


def _yarn_lock(text: str, manifest: str) -> list[Dependency]:
    out = []
    for block in re.split(r"\n(?=\S)", text):
        head, _, body = block.partition("\n")
        spec = head.strip().rstrip(":").split(",")[0].strip().strip('"')
        if not spec or spec.startswith("#") or spec.startswith("__metadata"):
            continue
        name = spec[: spec.index("@", 1)] if "@" in spec[1:] else spec
        m = re.search(r'^\s+version:?\s+"?([^"\s]+)"?', body, re.M)
        if name and m:
            out.append(_dep(name, m.group(1), "npm", manifest, False))
    return out


def _toml_packages(text: str, manifest: str, eco: str) -> list[Dependency]:
    data = tomllib.loads(text)
    return [_dep(p["name"], str(p["version"]), eco, manifest, False) for p in data.get("package", []) if p.get("name") and p.get("version")]


def _pipfile_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            v = (info or {}).get("version", "") if isinstance(info, dict) else ""
            if v.startswith("=="):
                out.append(_dep(name, v[2:], "PyPI", manifest, True))
    return out


def _go_mod(text: str, manifest: str) -> list[Dependency]:
    out = []
    for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-~/]+\.[\w.\-~/]+)\s+(v\d[^\s/]*)(\s*//\s*indirect)?", text, re.M):
        out.append(_dep(m.group(1), m.group(2), "Go", manifest, not m.group(3)))
    return out


def _gemfile_lock(text: str, manifest: str) -> list[Dependency]:
    out = []
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([0-9][^)]*)\)$", line) if in_specs else None
        if m:
            out.append(_dep(m.group(1), m.group(2).split("-")[0], "RubyGems", manifest, False))
    return out


def _composer_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    return [_dep(p["name"], str(p["version"]).lstrip("v"), "Packagist", manifest, False)
            for section in ("packages", "packages-dev") for p in (data.get(section) or []) if p.get("name") and p.get("version")]


PARSERS: dict[str, Callable[[str, str], list[Dependency]]] = {
    "package-lock.json": _npm_lock, "npm-shrinkwrap.json": _npm_lock, "yarn.lock": _yarn_lock,
    "poetry.lock": lambda t, m: _toml_packages(t, m, "PyPI"), "Cargo.lock": lambda t, m: _toml_packages(t, m, "crates.io"),
    "Pipfile.lock": _pipfile_lock, "go.mod": _go_mod, "Gemfile.lock": _gemfile_lock, "composer.lock": _composer_lock,
}
ECOSYSTEM = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "poetry.lock": "PyPI", "Pipfile.lock": "PyPI",
             "go.mod": "Go", "Cargo.lock": "crates.io", "Gemfile.lock": "RubyGems", "composer.lock": "Packagist"}


def merge_lockfiles(root: Path, manifest_deps: list[Dependency], lock_paths: list[str]) -> list[Dependency]:
    """Replace a directory's manifest entries with its lock file's exact versions (same ecosystem)."""
    locked: dict[tuple[str, str], list[Dependency]] = {}
    for rel in lock_paths:
        path = root / rel
        try:
            if path.stat().st_size > MAX_LOCK_BYTES:
                continue
            deps = PARSERS[Path(rel).name](path.read_text(encoding="utf-8", errors="replace"), rel)
        except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError, json.JSONDecodeError):
            continue
        if deps:
            locked.setdefault((str(Path(rel).parent), ECOSYSTEM[Path(rel).name]), []).extend(deps)
    if not locked:
        return manifest_deps
    out: list[Dependency] = []
    for d in manifest_deps:
        if (str(Path(d.manifest).parent), d.ecosystem) not in locked:
            out.append(d)
    requested = {m.name: m.requested for m in manifest_deps if m.requested}
    for (_, _), deps in locked.items():
        # npm lock files, Pipfile.lock and go.mod record which packages are direct; trust that. Formats that
        # do not (yarn.lock, poetry.lock, Cargo.lock, …) are matched by name against the manifest instead.
        knows_direct = any(d.direct for d in deps)
        seen: set[tuple[str, str]] = set()
        named: set[str] = set()
        for d in deps:
            if (d.name, d.version or "") in seen:
                continue
            seen.add((d.name, d.version or ""))
            if not knows_direct and d.name in requested and d.name not in named:
                d.direct = True
                named.add(d.name)
            if d.direct:
                d.requested = requested.get(d.name)
            out.append(d)
    return out


# --------------------------------------------------------------------------- range resolution (no lock file)

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$")


def _ver(v: str) -> tuple[int, int, int] | None:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", v)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None  # prereleases excluded


def _comparators(rng: str) -> list[tuple[str, tuple[int, int, int]]] | None:
    """One npm range (no ||) → list of (op, version); None if not understood."""
    rng = rng.strip()
    if rng in ("", "*", "x", "X", "latest"):
        return []
    m = re.fullmatch(r"(\S+)\s+-\s+(\S+)", rng)
    if m:
        a, b = _ver(m.group(1)), _ver(m.group(2))
        return [(">=", a), ("<=", b)] if a and b else None
    out = []
    for part in rng.split():
        op = re.match(r"^(\^|~>?|>=|<=|>|<|=)?", part).group(1) or ""
        sm = _SEMVER.match(part[len(op):])
        if not sm:
            return None
        major = int(sm.group(1))
        minor = None if sm.group(2) in (None, "x", "X", "*") else int(sm.group(2))
        patch = None if sm.group(3) in (None, "x", "X", "*") else int(sm.group(3))
        base = (major, minor or 0, patch or 0)
        if op == "^":
            upper = (major + 1, 0, 0) if major or minor is None else ((0, minor + 1, 0) if minor or patch is None else (0, 0, (patch or 0) + 1))
            out += [(">=", base), ("<", upper)]
        elif op in ("~", "~>"):
            upper = (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)
            out += [(">=", base), ("<", upper)]
        elif op in ("", "="):
            if minor is None:
                out += [(">=", base), ("<", (major + 1, 0, 0))]
            elif patch is None:
                out += [(">=", base), ("<", (major, minor + 1, 0))]
            else:
                out.append(("=", base))
        else:
            out.append((op, base))
    return out


def npm_max_satisfying(versions: list[str], rng: str) -> str | None:
    alts = [_comparators(r) for r in rng.split("||")]
    if any(a is None for a in alts):
        return None
    ok = lambda v, op, b: {"=": v == b, ">=": v >= b, "<=": v <= b, ">": v > b, "<": v < b}[op]  # noqa: E731
    best = None
    for s in versions:
        v = _ver(s)
        if v and any(all(ok(v, op, b) for op, b in alt) for alt in alts) and (best is None or v > best[0]):
            best = (v, s)
    return best[1] if best else None


def pypi_max_satisfying(releases: dict, spec: str) -> str | None:
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version
    try:
        ss = SpecifierSet(spec.strip() or "")
    except InvalidSpecifier:
        return None
    good = []
    for s, files in releases.items():
        try:
            v = Version(s)
        except InvalidVersion:
            continue
        if v.is_prerelease or (files and all(f.get("yanked") for f in files)):
            continue
        if v in ss:
            good.append(v)
    return str(max(good)) if good else None


def resolve_ranges(deps: list[Dependency], client: httpx.Client) -> tuple[list[Dependency], list[str]]:
    """Newest version allowed by each range (npm / PyPI registries). Returns (resolved, unresolved names)."""
    def one(d: Dependency) -> Dependency | None:
        rng = d.requested if d.requested is not None else (d.version or "")
        try:
            if d.ecosystem == "npm":
                if rng.startswith(("file:", "link:", "git", "http", "workspace:", "npm:")):
                    return None
                r = client.get(f"https://registry.npmjs.org/{quote(d.name, safe='@')}", headers={"Accept": "application/vnd.npm.install-v1+json"})
                data = r.json() if r.status_code == 200 else {}
                v = npm_max_satisfying(list((data.get("versions") or {}).keys()), rng)
            elif d.ecosystem == "PyPI":
                r = client.get(f"https://pypi.org/pypi/{quote(d.name)}/json")
                v = pypi_max_satisfying((r.json() or {}).get("releases") or {}, rng) if r.status_code == 200 else None
            else:
                return None
        except (httpx.HTTPError, ValueError):
            return None
        return d.model_copy(update={"version": v, "pinned": True, "source": "resolved", "requested": rng}) if v else None

    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="resolve") as pool:
        results = list(pool.map(one, deps[:150]))
    resolved = [r for r in results if r]
    unresolved = [d.name for d, r in zip(deps[:150], results, strict=False) if r is None] + [d.name for d in deps[150:]]
    return resolved, unresolved
