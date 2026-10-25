import hashlib
import os
import socket
import stat

import pytest

from conftest import linux_only, needs_fifo, needs_symlink, patch_scandir, posix_only, posix_perms
from filesift import hasher
from filesift.errors import RootUnreadableError
from filesift.exclusions import ExclusionPolicy, artifact_key
from filesift.models import FileEntry, SpecialEntry, SymlinkEntry
from filesift.scanner import build_inventory, kind_from_mode


def _scan(root, patterns=(), artifacts=()):
    root_r = root.resolve()
    return build_inventory(root_r, ExclusionPolicy(root_r, patterns, artifacts))


def test_files_nested_hidden_and_unicode(make_tree):
    root = make_tree({
        "a.txt": "x",
        ".hidden": "h",
        "sp ace ü.txt": "u",
        "d": {"e": {"f.bin": b"\x00\x01"}},
    })
    inv = _scan(root)
    assert set(inv.entries) == {"a.txt", ".hidden", "sp ace ü.txt", "d/e/f.bin"}
    entry = inv.entries["d/e/f.bin"]
    assert isinstance(entry, FileEntry)
    assert entry.sha256 == hashlib.sha256(b"\x00\x01").hexdigest()
    assert entry.size_bytes == 2
    assert inv.complete


def test_empty_directory_has_no_entries(make_tree):
    root = make_tree({"empty": {}})
    inv = _scan(root)
    assert inv.entries == {}
    assert inv.complete


def test_mode_and_mtime_encoding(make_tree):
    root = make_tree({"a.txt": "x"})
    st = os.lstat(root / "a.txt")
    entry = _scan(root).entries["a.txt"]
    assert entry.mode == f"{stat.S_IMODE(st.st_mode):04o}"
    assert entry.mtime_ns == str(st.st_mtime_ns)


def test_deterministic_inventory(make_tree):
    root = make_tree({"b": {"x": "1", "y": "2"}, "a": "3", "c": {"d": {"e": "4"}}})
    first = {k: v.model_dump() for k, v in _scan(root).entries.items()}
    second = {k: v.model_dump() for k, v in _scan(root).entries.items()}
    assert first == second


@needs_symlink
def test_symlink_to_file_recorded_not_followed(make_tree, monkeypatch):
    root = make_tree({"a.txt": "x"})
    os.symlink("a.txt", root / "link")
    opened = []
    real_hash = hasher.hash_stable
    monkeypatch.setattr(hasher, "hash_stable", lambda p, pre: opened.append(os.path.basename(p)) or real_hash(p, pre))
    inv = _scan(root)
    assert inv.entries["link"] == SymlinkEntry(type="symlink", target="a.txt")
    assert opened == ["a.txt"]


@needs_symlink
def test_symlink_to_directory_not_descended(make_tree):
    root = make_tree({"real": {"inner.txt": "x"}})
    os.symlink("real", root / "ldir", target_is_directory=True)
    inv = _scan(root)
    assert isinstance(inv.entries["ldir"], SymlinkEntry)
    assert "ldir/inner.txt" not in inv.entries
    assert "real/inner.txt" in inv.entries


@needs_symlink
def test_symlink_pointing_outside_root_records_target_only(tmp_path, make_tree):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    root = make_tree({})
    os.symlink(str(outside), root / "escape")
    inv = _scan(root)
    assert inv.entries == {"escape": SymlinkEntry(type="symlink", target=str(outside))}


@needs_fifo
def test_fifo_recorded_as_special(make_tree):
    root = make_tree({"a.txt": "x"})
    os.mkfifo(root / "pipe")
    inv = _scan(root)
    assert inv.entries["pipe"] == SpecialEntry(type="special", kind="fifo")


@posix_only
def test_socket_recorded_as_special(make_tree):
    root = make_tree({})
    path = str(root / "s")
    if len(path) > 100:
        pytest.skip("socket path too long for AF_UNIX")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(path)
        inv = _scan(root)
    finally:
        sock.close()
    assert inv.entries["s"] == SpecialEntry(type="special", kind="socket")


def test_kind_from_mode_covers_every_type():
    assert kind_from_mode(stat.S_IFREG | 0o644) == "file"
    assert kind_from_mode(stat.S_IFDIR | 0o755) == "dir"
    assert kind_from_mode(stat.S_IFLNK | 0o777) == "symlink"
    assert kind_from_mode(stat.S_IFIFO) == "fifo"
    assert kind_from_mode(stat.S_IFSOCK) == "socket"
    assert kind_from_mode(stat.S_IFCHR) == "char_device"
    assert kind_from_mode(stat.S_IFBLK) == "block_device"
    assert kind_from_mode(0) == "other"


@posix_perms
def test_unreadable_directory_real(make_tree):
    root = make_tree({"ok.txt": "x", "locked": {"inner.txt": "y"}})
    (root / "locked").chmod(0)
    try:
        inv = _scan(root)
    finally:
        (root / "locked").chmod(0o700)
    assert inv.unverified_prefixes == {"locked"}
    assert [e.kind for e in inv.errors] == ["DIR_UNREADABLE"]
    assert "locked/inner.txt" not in inv.entries
    assert not inv.complete


def test_unreadable_directory_injected(make_tree, monkeypatch):
    root = make_tree({"ok.txt": "x", "locked": {"inner.txt": "y"}})
    patch_scandir(monkeypatch, fail_dirs=[root.resolve() / "locked"])
    inv = _scan(root)
    assert inv.unverified_prefixes == {"locked"}
    assert inv.errors[0].kind == "DIR_UNREADABLE"
    assert inv.errors[0].subject == "locked"
    assert set(inv.entries) == {"ok.txt"}
    assert inv.gaps() == ["locked"]


def test_root_unreadable_is_fatal(make_tree, monkeypatch):
    root = make_tree({"a.txt": "x"})
    patch_scandir(monkeypatch, fail_dirs=[root.resolve()])
    with pytest.raises(RootUnreadableError) as exc:
        _scan(root)
    assert exc.value.exit_code == 4


def test_unstatable_entry_is_unreadable(make_tree, monkeypatch):
    root = make_tree({"a.txt": "x", "b.txt": "y"})
    patch_scandir(monkeypatch, fail_stat=[root.resolve() / "a.txt"])
    inv = _scan(root)
    assert "Permission denied" in inv.unreadable["a.txt"]
    assert set(inv.entries) == {"b.txt"}


def test_unopenable_file_is_unreadable(make_tree, monkeypatch):
    root = make_tree({"a.txt": "x"})

    def denied(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hasher.os, "open", denied)
    inv = _scan(root)
    assert set(inv.unreadable) == {"a.txt"}
    assert inv.entries == {}


@posix_perms
def test_unreadable_file_real(make_tree):
    root = make_tree({"a.txt": "x"})
    (root / "a.txt").chmod(0)
    try:
        inv = _scan(root)
    finally:
        (root / "a.txt").chmod(0o600)
    assert set(inv.unreadable) == {"a.txt"}


def test_unstable_file_recorded(make_tree, monkeypatch):
    root = make_tree({"a.txt": "x"})
    monkeypatch.setattr(hasher, "hash_stable", lambda p, pre: hasher.HashOutcome("unstable"))
    inv = _scan(root)
    assert inv.unstable == {"a.txt"}
    assert not inv.complete


@linux_only
def test_undecodable_name_is_a_coverage_gap(make_tree):
    root = make_tree({"ok.txt": "x"})
    fd = os.open(os.fsencode(str(root)) + b"/bad\xff", os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    inv = _scan(root)
    assert inv.undecodable == 1
    assert [e.kind for e in inv.errors] == ["UNDECODABLE_NAME"]
    assert set(inv.entries) == {"ok.txt"}
    assert inv.gaps() == []
    assert not inv.complete


def test_pattern_exclusions_prune_and_count(make_tree):
    root = make_tree({
        "cache": {"x": "1", "sub": {"y": "2"}},
        "a.log": "",
        "d": {"b.log": "", "keep.txt": ""},
        "keep.txt": "",
    })
    inv = _scan(root, patterns=("*.log", "cache"))
    assert set(inv.entries) == {"keep.txt", "d/keep.txt"}
    assert inv.excluded_by_pattern == 3


def test_artifact_excluded_but_decoy_inventoried(make_tree):
    root = make_tree({"baseline.json": "{}", "sub": {"baseline.json": "decoy"}})
    key = artifact_key(root.resolve() / "baseline.json")
    inv = _scan(root, artifacts={key})
    assert set(inv.entries) == {"sub/baseline.json"}
    assert inv.artifacts_excluded == 1


@needs_symlink
def test_symlink_pointing_at_baseline_is_inventoried(tmp_path, make_tree):
    """E2: entry paths are never resolved, so a link to the baseline is not mistaken for it."""
    state = tmp_path / "state"
    state.mkdir()
    baseline = state / "baseline.json"
    baseline.write_bytes(b"{}")
    root = make_tree({"a.txt": "x"})
    os.symlink(str(baseline), root / "evil")
    keys = {artifact_key(baseline), artifact_key(root / "evil")}   # even if the link's own path were the artifact
    inv = _scan(root, artifacts=keys)
    assert inv.entries["evil"] == SymlinkEntry(type="symlink", target=str(baseline))
    assert inv.artifacts_excluded == 0
