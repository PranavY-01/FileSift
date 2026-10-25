import hashlib
import os
import stat
import tracemalloc

import pytest

from conftest import needs_fifo, needs_symlink, posix_only, posix_perms
from filesift import hasher
from filesift.hasher import hash_stable

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def _hash(p):
    return hash_stable(p, os.lstat(p))


def test_known_vector_abc(tmp_path):
    p = tmp_path / "abc"
    p.write_bytes(b"abc")
    outcome = _hash(p)
    assert outcome.status == "ok"
    assert outcome.digest == ABC_SHA256


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert _hash(p).digest == EMPTY_SHA256


def test_binary_file_hashed_as_bytes(tmp_path):
    data = bytes(range(256)) * 1000 + b"\r\n\x00\r"
    p = tmp_path / "bin"
    p.write_bytes(data)
    assert _hash(p).digest == hashlib.sha256(data).hexdigest()


def test_multi_megabyte_file(tmp_path):
    data = os.urandom(5 * 1024 * 1024 + 7)
    p = tmp_path / "multi"
    p.write_bytes(data)
    assert _hash(p).digest == hashlib.sha256(data).hexdigest()


def test_large_file_constant_memory(tmp_path):
    p = tmp_path / "large"
    expected = hashlib.sha256()
    chunk = os.urandom(1024 * 1024)
    with open(p, "wb") as f:
        for _ in range(32):
            f.write(chunk)
            expected.update(chunk)
    del chunk
    tracemalloc.start()
    try:
        outcome = _hash(p)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert outcome.digest == expected.hexdigest()
    assert peak < 8 * 1024 * 1024


def test_outcome_carries_stat_of_successful_attempt(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"12345")
    outcome = _hash(p)
    assert stat.S_ISREG(outcome.stat.st_mode)
    assert outcome.stat.st_size == 5
    assert outcome.stat.st_mtime_ns == os.lstat(p).st_mtime_ns


@posix_perms
def test_unreadable_file_real(tmp_path):
    p = tmp_path / "secret"
    p.write_bytes(b"x")
    p.chmod(0)
    try:
        outcome = _hash(p)
    finally:
        p.chmod(0o600)
    assert outcome.status == "unreadable"
    assert outcome.digest is None


def test_unreadable_file_injected(tmp_path, monkeypatch):
    p = tmp_path / "secret"
    p.write_bytes(b"x")
    pre = os.lstat(p)

    def denied(*args, **kwargs):
        raise PermissionError(13, "Permission denied", str(p))

    monkeypatch.setattr(hasher.os, "open", denied)
    outcome = hash_stable(p, pre)
    assert outcome.status == "unreadable"
    assert "Permission denied" in outcome.error
    assert outcome.digest is None


def test_file_vanishes_between_listing_and_open(tmp_path):
    p = tmp_path / "gone"
    p.write_bytes(b"x")
    pre = os.lstat(p)
    p.unlink()
    outcome = hash_stable(p, pre)
    assert outcome.status == "unreadable"
    assert outcome.digest is None


def _appending_digest(monkeypatch, path, times):
    real = hashlib.file_digest
    calls = {"n": 0}

    def digest_then_modify(fileobj, name):
        result = real(fileobj, name)
        calls["n"] += 1
        if calls["n"] <= times:
            with open(path, "ab") as f:
                f.write(b"-more")
        return result

    monkeypatch.setattr(hasher.hashlib, "file_digest", digest_then_modify)
    return calls


def test_change_during_first_attempt_succeeds_on_retry(tmp_path, monkeypatch):
    p = tmp_path / "busy"
    p.write_bytes(b"content")
    pre = os.lstat(p)
    calls = _appending_digest(monkeypatch, p, times=1)
    outcome = hash_stable(p, pre)
    assert calls["n"] == 2
    assert outcome.status == "ok"
    assert outcome.digest == hashlib.sha256(b"content-more").hexdigest()


def test_persistent_change_is_unstable(tmp_path, monkeypatch):
    p = tmp_path / "busy"
    p.write_bytes(b"content")
    pre = os.lstat(p)
    _appending_digest(monkeypatch, p, times=99)
    outcome = hash_stable(p, pre)
    assert outcome.status == "unstable"
    assert outcome.digest is None


def test_non_regular_after_open_is_unstable(tmp_path, monkeypatch):
    p = tmp_path / "f"
    p.write_bytes(b"x")
    pre = os.lstat(p)
    directory_stat = os.stat(tmp_path)
    monkeypatch.setattr(hasher.os, "fstat", lambda fd: directory_stat)
    outcome = hash_stable(p, pre)
    assert outcome.status == "unstable"
    assert outcome.digest is None


@posix_only
@needs_symlink
def test_file_swapped_for_symlink_is_refused(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"x")
    other = tmp_path / "other"
    other.write_bytes(b"outside content")
    pre = os.lstat(p)
    p.unlink()
    os.symlink(other, p)
    outcome = hash_stable(p, pre)
    assert outcome.status in ("unreadable", "unstable")      # O_NOFOLLOW -> ELOOP, or identity mismatch
    assert outcome.digest is None


@needs_fifo
def test_file_swapped_for_fifo_does_not_hang(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"x")
    pre = os.lstat(p)
    p.unlink()
    os.mkfifo(p)
    outcome = hash_stable(p, pre)
    assert outcome.status == "unstable"
    assert outcome.digest is None
