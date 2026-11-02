"""Fetch a public GitHub repository as a ZIP archive.

Safety
- Only URLs that parse as ``github.com/<owner>/<repo>[/tree/<ref>]`` are accepted; the
  download URL is built by us, never taken from the user, so the server cannot be pointed at
  internal hosts (SSRF).
- GitHub's archive redirect is followed manually and only to ``codeload.github.com``.
- The archive is streamed with a hard size cap, then goes through the same safe extraction as
  uploads. ``git`` is never run: a repository's own git config/hooks can execute commands.
"""

from __future__ import annotations

import os
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


_REDIRECTS = (301, 302, 303, 307, 308)
_RATE_LIMITED = (403, 429)


def _not_found(gh: GitHubRepo) -> str:
    what = f"Branch or tag “{gh.ref}” of {gh.owner}/{gh.repo}" if gh.ref else f"Repository {gh.display}"
    return f"{what} was not found, or the repository is private (only public repositories are supported)."


def _resolve_archive(client: httpx.Client, gh: GitHubRepo) -> str:
    """Return the codeload.github.com URL of the repository archive.

    First the plain archive link (what "Download ZIP" uses) — it is not counted against the GitHub
    REST API's 60 requests/hour per IP for anonymous clients, which shared cloud IPs exhaust quickly.
    Only if GitHub limits that too, fall back to the REST API (authenticated when GITHUB_TOKEN is set).
    """
    ua = {"User-Agent": "PatchPilot-AI"}
    ref = gh.ref or "HEAD"  # HEAD = the repository's default branch
    attempts = [(f"https://github.com/{gh.owner}/{gh.repo}/archive/{ref}.zip", ua)]
    api_headers = {**ua, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        api_headers["Authorization"] = f"Bearer {token}"
    attempts.append((f"https://api.github.com/repos/{gh.owner}/{gh.repo}/zipball" + (f"/{gh.ref}" if gh.ref else ""), api_headers))

    for i, (url, headers) in enumerate(attempts):
        r = client.get(url, headers=headers, follow_redirects=False)
        if r.status_code in _RATE_LIMITED and i + 1 < len(attempts):
            continue
        if r.status_code == 404:
            raise GitHubError(_not_found(gh))
        if r.status_code in _RATE_LIMITED:
            raise GitHubError("GitHub is temporarily limiting downloads from this server. Please try again in a few minutes, "
                              "or upload the repository as a ZIP instead.")
        if r.status_code not in _REDIRECTS:
            raise GitHubError(f"GitHub returned an unexpected response ({r.status_code}).")
        location = r.headers.get("location", "")
        parts = urlsplit(location)
        if parts.scheme != "https" or parts.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
            raise GitHubError("GitHub redirected to an unexpected host; download refused.")
        return location
    raise GitHubError("Could not download the repository from GitHub.")  # unreachable


def download_github_zip(
    url: str,
    dest: Path,
    *,
    max_bytes: int,
    client_factory: Callable[[], httpx.Client] | None = None,
    timeout: float = 60.0,
) -> GitHubRepo:
    gh = parse_github_url(url)
    try:
        with (client_factory() if client_factory else httpx.Client(timeout=timeout)) as client:
            location = _resolve_archive(client, gh)
            size = 0
            with client.stream("GET", location, headers={"User-Agent": "PatchPilot-AI"}, follow_redirects=False) as resp:
                if resp.status_code == 404:  # github.com redirects even for unknown branches; codeload then 404s
                    raise GitHubError(_not_found(gh))
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
