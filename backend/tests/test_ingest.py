import stat
import zipfile

import pytest
from conftest import SAMPLES

from app.ingest.archive import ArchiveError, safe_extract_zip
from app.ingest.indexer import build_index
from app.ingest.secrets import REDACTED, find_secrets, redact

LIMITS = dict(max_total_bytes=5 * 1024 * 1024, max_files=100, max_ratio=100)


def _zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


# --------------------------------------------------------------------------- archive


def test_extracts_and_strips_common_root(tmp_path):
    z = _zip(tmp_path / "a.zip", {"proj-main/src/app.py": "x=1", "proj-main/README.md": "hi"})
    info = safe_extract_zip(z, tmp_path / "out", **LIMITS)
    assert (tmp_path / "out/src/app.py").read_text() == "x=1"
    assert info["stripped_root"] is True


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/passwd", "C:/Windows/evil.py", "..\\evil.py"])
def test_rejects_path_traversal(tmp_path, name):
    z = _zip(tmp_path / "a.zip", {"ok.py": "1", name: "pwned"})
    with pytest.raises(ArchiveError):
        safe_extract_zip(z, tmp_path / "out", **LIMITS)
    assert not (tmp_path / "evil.py").exists()


def test_rejects_symlink_entries(tmp_path):
    z = tmp_path / "s.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ArchiveError, match="symlink"):
        safe_extract_zip(z, tmp_path / "out", **LIMITS)


def test_rejects_oversized_and_too_many(tmp_path):
    big = _zip(tmp_path / "big.zip", {"big.txt": "a" * (6 * 1024 * 1024)})
    with pytest.raises(ArchiveError):
        safe_extract_zip(big, tmp_path / "o1", **LIMITS)
    many = _zip(tmp_path / "many.zip", {f"f{i}.py": "1" for i in range(150)})
    with pytest.raises(ArchiveError, match="too many"):
        safe_extract_zip(many, tmp_path / "o2", **LIMITS)


def test_rejects_non_zip_and_skips_git_dir(tmp_path):
    bad = tmp_path / "x.zip"
    bad.write_text("not a zip")
    with pytest.raises(ArchiveError):
        safe_extract_zip(bad, tmp_path / "o", **LIMITS)
    z = _zip(tmp_path / "g.zip", {"app.py": "1", ".git/hooks/post-checkout": "rm -rf /", "node_modules/x/index.js": "1"})
    safe_extract_zip(z, tmp_path / "o3", **LIMITS)
    assert (tmp_path / "o3/app.py").exists()
    assert not (tmp_path / "o3/.git").exists() and not (tmp_path / "o3/node_modules").exists()


# --------------------------------------------------------------------------- secrets


def test_secret_detection_and_redaction():
    text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\napi_key = "q8Z!x7Lm2Pv9Rt"\npassword = "changeme"\n-----BEGIN RSA PRIVATE KEY-----'
    found = {s.rule_id for s in find_secrets(text)}
    assert {"aws-access-key-id", "hardcoded-password", "private-key"} <= found
    red, n = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in red and "q8Z!x7Lm2Pv9Rt" not in red
    assert REDACTED in red and n >= 3
    assert "changeme" in red  # placeholders are not secrets


def test_masked_value_never_full():
    s = find_secrets('token = "ghp_' + "a1B2" * 9 + '"')[0]
    assert s.masked.startswith("ghp_") and "a1B2a1B2a1B2a1B2" not in s.masked


# --------------------------------------------------------------------------- indexer


def test_index_buggy_shop():
    idx = build_index(SAMPLES / "buggy-shop/repo")
    f = idx.facts
    assert f.languages[0].language == "Python"
    assert f.test_framework == "pytest"
    assert "tests/test_cart.py" in f.test_files
    assert idx.resolve("./shop/pricing.py") is not None
    assert idx.resolve("../secret.txt") is None
    assert "shipping_cost" in idx.read_numbered("shop/pricing.py")
    assert idx.rank_files("charged shipping at checkout")[0] in ("shop/pricing.py", "shop/cart.py")


def test_index_flags_install_hooks_and_redacts():
    idx = build_index(SAMPLES / "insecure-notes/repo")
    reasons = " ".join(s.reason for s in idx.facts.special_files)
    assert "cmdclass" in reasons
    assert {d.name for d in idx.facts.dependencies} >= {"PyYAML", "requests"}
    assert all(d.pinned for d in idx.facts.dependencies)
    text = idx.read_numbered("notes_app/config.py")
    assert "AKIAIOSFODNN7EXAMPLE" not in text and REDACTED in text
    assert idx.facts.secrets_redacted >= 2
