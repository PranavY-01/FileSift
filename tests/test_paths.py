import hashlib
import os
import sys

import pytest

from filesift.paths import UnsafePathError, ancestors, root_fingerprint, validate_entry_set, validate_rel_path


@pytest.mark.parametrize("p", [
    "a", "a/b", "dir with space/ünïcødé.txt", ".hidden", "a/.b/c", "..a", "a..", "*.log", "cache/*",
])
def test_accepts_canonical_paths(p):
    assert validate_rel_path(p) == p


@pytest.mark.parametrize("p", [
    "", "/etc/passwd", "a//b", "a/", "./a", "a/./b", "a/../b", "..", ".", "a\\b", "C:/x", "c:x",
    "\\\\server\\share\\x", "//server/share", "a\x00b", "bad\udcff",
])
def test_rejects_unsafe_paths(p):
    with pytest.raises(UnsafePathError):
        validate_rel_path(p)


def test_ancestors():
    assert list(ancestors("a/b/c")) == ["a", "a/b"]
    assert list(ancestors("a")) == []


def test_case_collision_detected_on_case_insensitive_platform(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(UnsafePathError, match="case-insensitive"):
        validate_entry_set(["Readme.md", "README.md"], [])


@pytest.mark.skipif(os.name == "nt", reason="Windows is always treated as case-insensitive")
def test_case_variants_allowed_on_case_sensitive_platform(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    validate_entry_set(["Readme.md", "README.md"], [])


def test_prefix_conflict_rejected():
    with pytest.raises(UnsafePathError, match="not a directory"):
        validate_entry_set(["a/b", "a/b/c"], [])


def test_siblings_with_shared_prefix_are_not_conflicts():
    validate_entry_set(["a/b", "a/bc", "a/c/d"], [])


def test_entry_equal_to_gap_rejected():
    with pytest.raises(UnsafePathError, match="unverified"):
        validate_entry_set(["secret"], ["secret"])


def test_entry_under_gap_rejected():
    with pytest.raises(UnsafePathError, match="unverified"):
        validate_entry_set(["secret/a.txt"], ["secret"])


def test_entry_next_to_gap_allowed():
    validate_entry_set(["secretive/a.txt", "a"], ["secret"])


def test_gap_must_be_a_safe_path():
    with pytest.raises(UnsafePathError):
        validate_entry_set([], ["../outside"])


def test_root_fingerprint_formula(tmp_path):
    root_r = tmp_path.resolve()
    expected = "sha256:" + hashlib.sha256(os.fsencode(os.path.normcase(str(root_r)))).hexdigest()
    assert root_fingerprint(root_r) == expected
    other = (tmp_path / "other")
    other.mkdir()
    assert root_fingerprint(other.resolve()) != expected
