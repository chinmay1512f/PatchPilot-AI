import httpx
import pytest

from app.ingest.github import GitHubError, download_github_zip, parse_github_url


@pytest.mark.parametrize("url, owner, repo, ref", [
    ("https://github.com/pallets/flask", "pallets", "flask", None),
    ("github.com/pallets/flask.git", "pallets", "flask", None),
    ("https://www.github.com/a-b/c.d_e/", "a-b", "c.d_e", None),
    ("https://github.com/o/r/tree/feature/login-fix", "o", "r", "feature/login-fix"),
])
def test_parse_valid(url, owner, repo, ref):
    gh = parse_github_url(url)
    assert (gh.owner, gh.repo, gh.ref) == (owner, repo, ref)


@pytest.mark.parametrize("url", [
    "https://github.com.evil.com/o/r", "https://evil.com/github.com/o/r", "http://localhost:8000/o/r",
    "https://github.com/o", "https://github.com/o/r/tree/../../x", "file:///etc/passwd", "https://user@github.com/o/r",
    "https://github.com/o/r?x=1", "", "https://gitlab.com/o/r",
])
def test_parse_rejects(url):
    with pytest.raises(GitHubError):
        parse_github_url(url)


def _client(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def test_download_follows_only_codeload(tmp_path):
    seen = []

    def ok(req: httpx.Request):
        seen.append(str(req.url))
        if req.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://codeload.github.com/o/r/legacy.zip/refs/heads/main"})
        return httpx.Response(200, content=b"PK\x05\x06" + b"\0" * 18)
    gh = download_github_zip("https://github.com/o/r", tmp_path / "a.zip", max_bytes=1024, client_factory=_client(ok))
    assert gh.display == "o/r" and (tmp_path / "a.zip").stat().st_size == 22
    assert seen[0] == "https://api.github.com/repos/o/r/zipball"

    def evil(req: httpx.Request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
    with pytest.raises(GitHubError, match="unexpected host"):
        download_github_zip("https://github.com/o/r", tmp_path / "b.zip", max_bytes=1024, client_factory=_client(evil))


def test_download_errors(tmp_path):
    with pytest.raises(GitHubError, match="not found"):
        download_github_zip("https://github.com/o/r", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(lambda r: httpx.Response(404)))
    with pytest.raises(GitHubError, match="rate limit"):
        download_github_zip("https://github.com/o/r", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(lambda r: httpx.Response(403)))

    def big(req: httpx.Request):
        if req.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://codeload.github.com/o/r/zip"})
        return httpx.Response(200, content=b"x" * 5000)
    with pytest.raises(GitHubError, match="exceeds"):
        download_github_zip("https://github.com/o/r", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(big))
