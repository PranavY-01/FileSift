import json
import os
import re
import sys
from pathlib import Path

import pytest

from conftest import SHA_A, baseline_dict, file_entry, write_json
from filesift import baseline as baseline_io
from filesift import outputs
from filesift.baseline import build_baseline_dict, load_baseline, serialize_baseline, write_baseline
from filesift.errors import (BaselineCorruptError, BaselineExistsError, BaselineInvalidError, BaselineMissingError,
                             ConfigError, OperationalError)
from filesift.exclusions import ExclusionPolicy
from filesift.models import TIMESTAMP_PATTERN
from filesift.scanner import Inventory, build_inventory


def _inventory(root):
    root_r = root.resolve()
    return root_r, build_inventory(root_r, ExclusionPolicy(root_r, (), ()))


def _load(tmp_path, obj):
    return load_baseline(write_json(tmp_path / "baseline.json", obj), None)


def test_round_trip(tmp_path, make_tree):
    root_r, inv = _inventory(make_tree({"a.txt": "x", "d": {"b.txt": "y"}}))
    doc = build_baseline_dict(root_r, inv, ("*.log",), None)
    data = serialize_baseline(doc)
    path = tmp_path / "baseline.json"
    write_baseline(path, data, force=False)
    loaded, raw, authenticated = load_baseline(path, None)
    assert raw == data
    assert authenticated is False
    assert loaded.entries == inv.entries
    assert loaded.policy.exclusions == ["*.log"]
    assert loaded.coverage.complete is True
    assert loaded.root.label == root_r.name
    assert re.match(TIMESTAMP_PATTERN, loaded.created_at)
    assert data == (json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def test_valid_fixture_loads(tmp_path):
    doc, _, _ = _load(tmp_path, baseline_dict())
    assert doc.entries["a.txt"].sha256 == SHA_A


def test_missing_baseline(tmp_path):
    with pytest.raises(BaselineMissingError) as exc:
        load_baseline(tmp_path / "nope.json", None)
    assert exc.value.exit_code == 3


@pytest.mark.parametrize("raw", [b"\xff\xfe{", b"{", b"", b'{"a": }'])
def test_corrupt_bytes(tmp_path, raw):
    path = tmp_path / "baseline.json"
    path.write_bytes(raw)
    with pytest.raises(BaselineCorruptError):
        load_baseline(path, None)


def test_duplicate_top_level_key(tmp_path):
    text = json.dumps(baseline_dict())[:-1] + ', "tool": "FileSift"}'
    path = tmp_path / "baseline.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(BaselineInvalidError, match="duplicate"):
        load_baseline(path, None)


def test_duplicate_entry_key_smuggling(tmp_path):
    """T10: a second copy of an entry must not silently override the first."""
    good = json.dumps(file_entry())
    text = json.dumps(baseline_dict()).replace('"entries": {', f'"entries": {{"a.txt": {good}, ', 1)
    path = tmp_path / "baseline.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(BaselineInvalidError, match="duplicate"):
        load_baseline(path, None)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(extra=1),
    lambda d: d["entries"]["a.txt"].update(owner="root"),
    lambda d: d["policy"].update(defaults=[]),
    lambda d: d["coverage"].update(note="x"),
    lambda d: d["root"].update(path="/"),
])
def test_unknown_fields_rejected(tmp_path, mutate):
    d = baseline_dict()
    mutate(d)
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, d)


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n", "g" * 64, ""])
def test_bad_digests_rejected(tmp_path, digest):
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict({"a.txt": file_entry(sha=digest)}))


@pytest.mark.parametrize("field, value", [
    ("schema_version", 2), ("schema_version", "1"), ("schema_version", True),
    ("tool", "FileSentinel"), ("hash_algorithm", "md5"),
    ("created_at", "2026-10-25 12:00:00"), ("created_at", "2026-10-25T12:00:00+00:00"),
    ("integrity", {"algorithm": "hmac-md5", "mac": SHA_A}),
])
def test_bad_header_fields_rejected(tmp_path, field, value):
    d = baseline_dict()
    d[field] = value
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, d)


@pytest.mark.parametrize("mutate", [
    lambda d: d["policy"].update(follow_symlinks=0),
    lambda d: d["policy"].update(follow_symlinks=True),
    lambda d: d["coverage"].update(complete=1),
    lambda d: d["root"].update(fingerprint="sha256:" + "0" * 63),
])
def test_strict_nested_values_rejected(tmp_path, mutate):
    d = baseline_dict()
    mutate(d)
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, d)


def test_missing_required_field_rejected(tmp_path):
    d = baseline_dict()
    del d["integrity"]
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, d)


@pytest.mark.parametrize("entry", [
    {**file_entry(), "size_bytes": "1"},
    {**file_entry(), "size_bytes": -1},
    {**file_entry(), "size_bytes": True},
    {**file_entry(), "mtime_ns": 1},
    {**file_entry(), "mode": "644"},
    {**file_entry(), "mode": "0948"},
    {"type": "file", "size_bytes": 1, "mode": "0644", "mtime_ns": "1"},
    {"type": "symlink"},
    {"type": "special", "kind": "door"},
    {"type": "directory"},
    {"type": "symlink", "target": "x", "sha256": SHA_A},
])
def test_inconsistent_entries_rejected(tmp_path, entry):
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict({"a.txt": entry}))


@pytest.mark.parametrize("key", ["/etc/passwd", "../x", "a\\b", "C:/x", "a\x00b", "a//b", "./a", ""])
def test_unsafe_entry_paths_rejected(tmp_path, key):
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict({key: file_entry()}))


def test_prefix_conflict_rejected(tmp_path):
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict({"a": file_entry(), "a/b": file_entry()}))


def test_case_collision_rejected_on_case_insensitive_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict({"README": file_entry(), "readme": file_entry()}))


def test_complete_true_with_unverified_rejected(tmp_path):
    """E5: complete=true and a non-empty unverified list contradict each other."""
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict(unverified=["x"], complete=True))


def test_complete_false_with_empty_unverified_allowed(tmp_path):
    doc, _, _ = _load(tmp_path, baseline_dict(complete=False))
    assert doc.coverage.complete is False


def test_entry_under_gap_rejected(tmp_path):
    """E4: no entry may equal or lie under a recorded gap."""
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, baseline_dict({"secret/a.txt": file_entry()}, unverified=["secret"]))


@pytest.mark.parametrize("gaps", [["../x"], ["b", "a"], ["a", "a"]])
def test_gap_list_must_be_canonical(tmp_path, gaps):
    d = baseline_dict()
    d["coverage"] = {"complete": False, "unverified": gaps}
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, d)


@pytest.mark.parametrize("patterns", [["/abs"], ["b", "a"], ["*.log", "*.log"]])
def test_stored_exclusions_must_be_canonical(tmp_path, patterns):
    d = baseline_dict()
    d["policy"]["exclusions"] = patterns
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, d)


def test_top_level_not_an_object(tmp_path):
    with pytest.raises(BaselineInvalidError):
        _load(tmp_path, [baseline_dict()])


def test_exclusive_create_refuses_existing(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_bytes(b"original")
    with pytest.raises(BaselineExistsError) as exc:
        write_baseline(path, b"new", force=False)
    assert exc.value.exit_code == 2
    assert path.read_bytes() == b"original"


def test_force_replaces_atomically_and_keeps_backup(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_bytes(b"original")
    write_baseline(path, b"new", force=True)
    assert path.read_bytes() == b"new"
    assert (tmp_path / "baseline.json.bak").read_bytes() == b"original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["baseline.json", "baseline.json.bak"]


def test_force_without_existing_file_creates_no_backup(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, b"new", force=True)
    assert path.read_bytes() == b"new"
    assert not (tmp_path / "baseline.json.bak").exists()


def test_forced_write_failure_leaves_original_intact(tmp_path, monkeypatch):
    path = tmp_path / "baseline.json"
    path.write_bytes(b"original")
    real_replace = os.replace

    def failing_replace(src, dst):
        if Path(dst) == path:
            raise OSError(28, "No space left on device")
        return real_replace(src, dst)

    monkeypatch.setattr(outputs.os, "replace", failing_replace)
    with pytest.raises(OperationalError) as exc:
        write_baseline(path, b"new", force=True)
    assert exc.value.exit_code == 4
    assert path.read_bytes() == b"original"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".filesift-tmp-")]


def test_exclusive_write_failure_leaves_no_partial_file(tmp_path, monkeypatch):
    path = tmp_path / "baseline.json"

    def failing_fsync(fd):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(baseline_io.os, "fsync", failing_fsync)
    with pytest.raises(OperationalError):
        write_baseline(path, b"new", force=False)
    assert not path.exists()


def test_missing_output_directory(tmp_path):
    with pytest.raises(ConfigError):
        write_baseline(tmp_path / "missing" / "baseline.json", b"x", force=False)


def test_gaps_recorded_when_incomplete(tmp_path):
    inv = Inventory()
    inv.unreadable["b.txt"] = "Permission denied"
    inv.unverified_prefixes.add("locked")
    inv.unstable.add("c.txt")
    doc = build_baseline_dict(tmp_path.resolve(), inv, (), None)
    assert doc["coverage"] == {"complete": False, "unverified": ["b.txt", "c.txt", "locked"]}
    loaded, _, _ = _load(tmp_path, doc)
    assert loaded.coverage.unverified == ["b.txt", "c.txt", "locked"]


def test_undecodable_names_mark_baseline_incomplete(tmp_path):
    """E5: undecodable names cannot be stored, yet the baseline must not claim completeness."""
    inv = Inventory()
    inv.undecodable = 1
    doc = build_baseline_dict(tmp_path.resolve(), inv, (), None)
    assert doc["coverage"] == {"complete": False, "unverified": []}


def test_source_never_uses_model_validate_json():
    """Invariant 7: model_validate_json would bypass the duplicate-key hook."""
    src = Path(baseline_io.__file__).parent
    for py in src.glob("*.py"):
        assert "model_validate_json" not in py.read_text(encoding="utf-8"), py.name
