import os

import pytest

from filesift.errors import ConfigError
from filesift.exclusions import ExclusionPolicy, artifact_key, validate_patterns


def test_patterns_deduplicated_and_sorted():
    assert validate_patterns(["b/*", "*.log", "b/*"]) == ("*.log", "b/*")


@pytest.mark.parametrize("bad", ["/abs/*", "../x", "a/../b", "a\\b", "C:/x", "", "a//b"])
def test_invalid_patterns_rejected(bad):
    with pytest.raises(ConfigError):
        validate_patterns([bad])


def test_pattern_matches_at_depth(tmp_path):
    policy = ExclusionPolicy(tmp_path, ("*.log",), ())
    assert policy.classify("a.log", True) == "pattern"
    assert policy.classify("x/y/z.log", True) == "pattern"
    assert policy.classify("x/y/z.txt", True) is None


def test_directory_pattern(tmp_path):
    policy = ExclusionPolicy(tmp_path, ("cache/*",), ())
    assert policy.classify("cache/a", True) == "pattern"
    assert policy.classify("cache", False) is None          # the directory itself is listed, its children excluded


def test_matching_is_case_sensitive(tmp_path):
    policy = ExclusionPolicy(tmp_path, ("*.log",), ())
    assert policy.classify("A.LOG", True) is None


def test_artifact_excluded_only_by_exact_path_and_only_when_regular(tmp_path):
    root = tmp_path.resolve()
    key = artifact_key(root / "state" / "baseline.json")
    policy = ExclusionPolicy(root, (), {key})
    assert policy.classify("state/baseline.json", True) == "artifact"
    assert policy.classify("state/baseline.json", False) is None        # a symlink/dir at that path is inventoried
    assert policy.classify("other/baseline.json", True) is None         # decoy name elsewhere


def test_artifact_key_resolves_parent_but_not_name(tmp_path):
    (tmp_path / "d").mkdir()
    p = tmp_path / "d" / ".." / "d" / "baseline.json"
    assert artifact_key(p) == os.path.normcase(str(tmp_path.resolve() / "d" / "baseline.json"))
