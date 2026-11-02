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


ZIP = b"PK\x05\x06" + b"\0" * 18


def test_download_uses_archive_link_not_api(tmp_path):
    """The plain archive link is not subject to the REST API's anonymous rate limit."""
    seen = []

    def ok(req: httpx.Request):
        seen.append(str(req.url))
        if req.url.host == "github.com":
            return httpx.Response(302, headers={"location": "https://codeload.github.com/o/r/zip/abc123"})
        return httpx.Response(200, content=ZIP)
    gh = download_github_zip("https://github.com/o/r", tmp_path / "a.zip", max_bytes=1024, client_factory=_client(ok))
    assert gh.display == "o/r" and (tmp_path / "a.zip").stat().st_size == 22
    assert seen == ["https://github.com/o/r/archive/HEAD.zip", "https://codeload.github.com/o/r/zip/abc123"]

    seen.clear()
    download_github_zip("https://github.com/o/r/tree/feature/x", tmp_path / "b.zip", max_bytes=1024, client_factory=_client(ok))
    assert seen[0] == "https://github.com/o/r/archive/feature/x.zip"


def test_download_falls_back_to_api_when_archive_is_limited(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    seen = []

    def handler(req: httpx.Request):
        seen.append((str(req.url), req.headers.get("authorization")))
        if req.url.host == "github.com":
            return httpx.Response(429)
        if req.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://codeload.github.com/o/r/legacy.zip/refs/heads/main"})
        return httpx.Response(200, content=ZIP)
    download_github_zip("https://github.com/o/r", tmp_path / "a.zip", max_bytes=1024, client_factory=_client(handler))
    assert seen[1] == ("https://api.github.com/repos/o/r/zipball", "Bearer test-token")
    assert seen[0][1] is None  # the token is only ever sent to the GitHub API


def test_download_refuses_unexpected_redirects(tmp_path):
    def evil(req: httpx.Request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
    with pytest.raises(GitHubError, match="unexpected host"):
        download_github_zip("https://github.com/o/r", tmp_path / "b.zip", max_bytes=1024, client_factory=_client(evil))


def test_download_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(GitHubError, match="not found"):
        download_github_zip("https://github.com/o/r", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(lambda r: httpx.Response(404)))
    with pytest.raises(GitHubError, match="Branch or tag “dev”"):
        download_github_zip("https://github.com/o/r/tree/dev", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(lambda r: httpx.Response(404)))
    def unknown_branch(req: httpx.Request):  # github.com redirects without checking; codeload 404s
        if req.url.host == "github.com":
            return httpx.Response(302, headers={"location": "https://codeload.github.com/o/r/zip/nope"})
        return httpx.Response(404)
    with pytest.raises(GitHubError, match="Branch or tag “nope”"):
        download_github_zip("https://github.com/o/r/tree/nope", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(unknown_branch))
    with pytest.raises(GitHubError, match="temporarily limiting"):  # both the archive link and the API are limited
        download_github_zip("https://github.com/o/r", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(lambda r: httpx.Response(403)))

    def big(req: httpx.Request):
        if req.url.host == "github.com":
            return httpx.Response(302, headers={"location": "https://codeload.github.com/o/r/zip"})
        return httpx.Response(200, content=b"x" * 5000)
    with pytest.raises(GitHubError, match="exceeds"):
        download_github_zip("https://github.com/o/r", tmp_path / "x.zip", max_bytes=1024, client_factory=_client(big))
