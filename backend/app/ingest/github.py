"""Fetch a public GitHub repository as a ZIP archive.

Safety
- Only URLs that parse as ``github.com/<owner>/<repo>[/tree/<ref>]`` are accepted; the
  download URL is built by us, never taken from the user, so the server cannot be pointed at
  internal hosts (SSRF).
- The GitHub API redirect is followed manually and only to ``codeload.github.com``.
- The archive is streamed with a hard size cap, then goes through the same safe extraction as
  uploads. ``git`` is never run: a repository's own git config/hooks can execute commands.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[A-Za-z0-9._/-]{1,200}))?/?$"
)
_ALLOWED_DOWNLOAD_HOSTS = {"codeload.github.com"}


class GitHubError(ValueError):
    """Message is safe to show to users."""


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    repo: str
    ref: str | None

    @property
    def display(self) -> str:
        return f"{self.owner}/{self.repo}" + (f"@{self.ref}" if self.ref else "")


def parse_github_url(url: str) -> GitHubRepo:
    url = (url or "").strip()
    m = _URL_RE.match(url)
    if not m:
        raise GitHubError("Enter a public GitHub repository URL like https://github.com/owner/repo (optionally …/tree/branch).")
    owner, repo, ref = m.group("owner"), m.group("repo"), m.group("ref")
    if repo in (".", "..") or (ref and (".." in ref or ref.startswith("/") or ref.endswith("/"))):
        raise GitHubError("Invalid repository or branch name.")
    return GitHubRepo(owner, repo, ref.rstrip("/") if ref else None)


def download_github_zip(
    url: str,
    dest: Path,
    *,
    max_bytes: int,
    client_factory: Callable[[], httpx.Client] | None = None,
    timeout: float = 60.0,
) -> GitHubRepo:
    gh = parse_github_url(url)
    api_url = f"https://api.github.com/repos/{gh.owner}/{gh.repo}/zipball" + (f"/{gh.ref}" if gh.ref else "")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "PatchPilot-AI"}
    try:
        with (client_factory() if client_factory else httpx.Client(timeout=timeout)) as client:
            r = client.get(api_url, headers=headers, follow_redirects=False)
            if r.status_code == 404:
                raise GitHubError(f"Repository {gh.display} was not found, or it is private (only public repositories are supported).")
            if r.status_code in (403, 429):
                raise GitHubError("GitHub rate limit reached for anonymous downloads. Try again later or upload a ZIP instead.")
            if r.status_code not in (301, 302, 303, 307, 308):
                raise GitHubError(f"GitHub returned an unexpected response ({r.status_code}).")
            location = r.headers.get("location", "")
            parts = urlsplit(location)
            if parts.scheme != "https" or parts.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
                raise GitHubError("GitHub redirected to an unexpected host; download refused.")
            size = 0
            with client.stream("GET", location, headers={"User-Agent": "PatchPilot-AI"}, follow_redirects=False) as resp:
                if resp.status_code != 200:
                    raise GitHubError(f"Archive download failed ({resp.status_code}).")
                declared = resp.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise GitHubError(f"Repository archive exceeds the {max_bytes // (1024 * 1024)} MB limit.")
                with open(dest, "wb") as out:
                    for chunk in resp.iter_bytes(65536):
                        size += len(chunk)
                        if size > max_bytes:
                            raise GitHubError(f"Repository archive exceeds the {max_bytes // (1024 * 1024)} MB limit.")
                        out.write(chunk)
    except httpx.HTTPError as e:
        raise GitHubError(f"Could not reach GitHub ({type(e).__name__}).") from e
    return gh
