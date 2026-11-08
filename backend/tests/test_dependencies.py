"""Exact dependency versions for the vulnerability check: lock files first, then resolved ranges."""

import json

import httpx

from app.config import Settings
from app.ingest.dependencies import npm_max_satisfying, pypi_max_satisfying
from app.ingest.indexer import build_index
from app.tools.scanners import run_osv

NPM_LOCK_V3 = {"name": "app", "lockfileVersion": 3, "packages": {
    "": {"name": "app", "dependencies": {"next": "^15.5.25"}, "devDependencies": {"postcss": "^8.5.0"}},
    "node_modules/next": {"version": "15.5.25"},
    "node_modules/postcss": {"version": "8.5.28", "dev": True},
    "node_modules/next/node_modules/postcss": {"version": "8.4.31"},
    "node_modules/styled-jsx": {"version": "5.1.6"},
    "node_modules/local-lib": {"link": True},
}}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
    return build_index(root)


def test_package_lock_gives_exact_versions_and_marks_direct(tmp_path):
    idx = _write(tmp_path, {"package.json": {"dependencies": {"next": "^15.5.25"}, "devDependencies": {"postcss": "^8.5.0"}},
                            "package-lock.json": NPM_LOCK_V3})
    deps = {(d.name, d.version): d for d in idx.facts.dependencies}
    assert set(deps) == {("next", "15.5.25"), ("postcss", "8.5.28"), ("postcss", "8.4.31"), ("styled-jsx", "5.1.6")}
    assert all(d.source == "lockfile" and d.pinned for d in deps.values())
    assert deps[("next", "15.5.25")].direct and deps[("next", "15.5.25")].requested == "^15.5.25"
    assert deps[("postcss", "8.5.28")].direct and not deps[("postcss", "8.4.31")].direct and not deps[("styled-jsx", "5.1.6")].direct
    assert "package-lock.json" in idx.facts.manifests


def test_other_lock_formats(tmp_path):
    idx = _write(tmp_path, {
        "web/yarn.lock": '# yarn lockfile v1\n\n"lodash@^4.17.0", lodash@^4.17.20:\n  version "4.17.21"\n  resolved "x"\n',
        "py/poetry.lock": '[[package]]\nname = "flask"\nversion = "2.3.3"\n\n[[package]]\nname = "jinja2"\nversion = "3.1.4"\n',
        "pipenv/Pipfile.lock": {"default": {"requests": {"version": "==2.31.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}},
        "go/go.mod": "module x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0\n\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n",
        "rs/Cargo.lock": 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\n',
        "rb/Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n      webrick\n    nokogiri (1.15.4-x86_64-linux)\n\nPLATFORMS\n  ruby\n",
        "php/composer.lock": {"packages": [{"name": "guzzlehttp/guzzle", "version": "v7.8.1"}]},
    })
    got = {(d.ecosystem, d.name, d.version, d.direct) for d in idx.facts.dependencies}
    assert ("npm", "lodash", "4.17.21", False) in got
    assert {("PyPI", "flask", "2.3.3", False), ("PyPI", "requests", "2.31.0", True), ("PyPI", "pytest", "8.0.0", True)} <= got
    assert {("Go", "golang.org/x/text", "v0.3.0", True), ("Go", "github.com/pkg/errors", "v0.9.1", False)} <= got
    assert {("crates.io", "serde", "1.0.200", False), ("RubyGems", "rack", "2.2.8", False), ("RubyGems", "nokogiri", "1.15.4", False),
            ("Packagist", "guzzlehttp/guzzle", "7.8.1", False)} <= got


def test_semver_and_pep440_resolution():
    vs = ["1.2.3", "1.9.0", "2.0.0", "2.1.0-beta.1", "0.4.1", "0.4.9", "0.5.0"]
    assert npm_max_satisfying(vs, "^1.2.0") == "1.9.0"
    assert npm_max_satisfying(vs, "^0.4.1") == "0.4.9"  # caret on 0.x stays within the minor
    assert npm_max_satisfying(["1.2.3", "1.2.9", "1.3.0"], "~1.2.3") == "1.2.9"
    assert npm_max_satisfying(vs, ">=1.0.0 <2") == "1.9.0"
    assert npm_max_satisfying(vs, "0.4.x || 1.x") == "1.9.0"
    assert npm_max_satisfying(vs, "1.2.3 - 1.5.0") == "1.2.3"
    assert npm_max_satisfying(vs, "*") == "2.0.0"  # pre-releases are never picked
    assert npm_max_satisfying(vs, "github:user/repo") is None
    releases = {"2.0.0": [{}], "2.3.3": [{}], "3.0.0": [{}], "3.1.0rc1": [{}], "2.3.4": [{"yanked": True}]}
    assert pypi_max_satisfying(releases, ">=2.0,<3") == "2.3.3"  # yanked and pre-releases skipped
    assert pypi_max_satisfying(releases, "") == "3.0.0"


def _client(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def test_osv_resolves_ranges_without_a_lock_file(tmp_path):
    idx = _write(tmp_path, {"package.json": {"dependencies": {"next": "^15.5.25", "mylib": "file:../mylib"}}})
    queries = []

    def handler(req: httpx.Request):
        if req.url.host == "registry.npmjs.org":
            return httpx.Response(200, json={"versions": {"15.5.25": {}, "15.5.29": {}, "16.0.0": {}}})
        if req.url.path == "/v1/querybatch":
            body = json.loads(req.content)
            queries.extend(body["queries"])
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test"}]}]})
        return httpx.Response(200, json={"summary": "Remote code execution", "database_specific": {"severity": "CRITICAL"}})
    run, findings = run_osv(idx, Settings(osv_enabled=True), client_factory=_client(handler))
    assert run.status == "completed" and "1 resolved from version ranges" in run.message and "1 could not be resolved" in run.message
    assert queries == [{"package": {"name": "next", "ecosystem": "npm"}, "version": "15.5.29"}]
    assert findings[0].title == "next@15.5.29: GHSA-test" and "resolved from '^15.5.25'" in findings[0].description


def test_unsupported_dependency_files_are_not_called_clean(tmp_path):
    idx = _write(tmp_path, {"pom.xml": "<project/>", "src/App.java": "class App {}"})
    run, findings = run_osv(idx, Settings(osv_enabled=True))
    assert run.status == "skipped" and "Java (Maven)" in run.message and "not supported" in run.message and not findings
    idx = _write(tmp_path / "empty", {"main.py": "print(1)"})
    assert run_osv(idx, Settings(osv_enabled=True))[0].message == "no dependency manifests found"
