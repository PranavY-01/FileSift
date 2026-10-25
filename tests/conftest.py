"""Shared fixtures, tree builder, platform skip markers, and failure-injection helpers."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest


def _can_symlink() -> bool:
    with tempfile.TemporaryDirectory() as d:
        try:
            os.symlink("target", os.path.join(d, "link"))
        except (OSError, NotImplementedError):
            return False
    return True


IS_POSIX = os.name == "posix"
IS_ROOT = IS_POSIX and os.geteuid() == 0

posix_only = pytest.mark.skipif(not IS_POSIX, reason="POSIX filesystem semantics required")
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="Linux only: undecodable byte filenames")
needs_symlink = pytest.mark.skipif(not _can_symlink(), reason="symlinks not supported or not permitted")
needs_fifo = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo unavailable (non-POSIX)")
posix_perms = pytest.mark.skipif(not IS_POSIX or IS_ROOT,
                                 reason="needs POSIX permissions as a non-root user (root bypasses chmod 000)")

SHA_A = "a" * 64
SHA_B = "b" * 64
FINGERPRINT = "sha256:" + "0" * 64


def build_tree(root: Path, spec: dict[str, Any]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, value in spec.items():
        p = root / name
        if isinstance(value, dict):
            build_tree(p, value)
        elif isinstance(value, bytes):
            p.write_bytes(value)
        else:
            p.write_bytes(value.encode("utf-8"))
    return root


@pytest.fixture
def make_tree(tmp_path):
    def _make(spec: dict[str, Any], name: str = "target") -> Path:
        return build_tree(tmp_path / name, spec)
    return _make


def file_entry(sha: str = SHA_A, size: int = 1, mode: str = "0644") -> dict[str, Any]:
    return {"type": "file", "sha256": sha, "size_bytes": size, "mode": mode, "mtime_ns": "1"}


def baseline_dict(entries: dict[str, Any] | None = None, *, unverified=(), complete: bool | None = None,
                  exclusions=()) -> dict[str, Any]:
    unverified = sorted(unverified)
    return {
        "schema_version": 1,
        "tool": "FileSift",
        "tool_version": "1.0.0",
        "hash_algorithm": "sha256",
        "created_at": "2026-10-25T12:00:00Z",
        "root": {"fingerprint": FINGERPRINT, "label": "target"},
        "policy": {"exclusions": list(exclusions), "follow_symlinks": False},
        "coverage": {"complete": (not unverified) if complete is None else complete, "unverified": unverified},
        "entries": {"a.txt": file_entry()} if entries is None else entries,
        "integrity": None,
    }


def write_json(path: Path, obj: Any) -> Path:
    path.write_bytes(json.dumps(obj).encode("utf-8"))
    return path


def run_cli(*args, cwd=None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    full_env.pop("FILESIFT_KEY", None)
    full_env["COLUMNS"] = "200"
    full_env.update(env or {})
    return subprocess.run([sys.executable, "-m", "filesift", *map(str, args)], capture_output=True, text=True,
                          encoding="utf-8", timeout=60, cwd=cwd, env=full_env)


@pytest.fixture
def run_main(monkeypatch, capsys):
    """Run ``cli.main()`` in-process so engine functions can be monkeypatched."""
    from filesift import cli

    monkeypatch.delenv("FILESIFT_KEY", raising=False)

    def _run(*args) -> tuple[int, str, str]:
        monkeypatch.setattr(sys, "argv", ["filesift", *map(str, args)])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        captured = capsys.readouterr()
        return exc.value.code, captured.out, captured.err
    return _run


def patch_scandir(monkeypatch, *, fail_dirs=(), fail_stat=()) -> None:
    """Inject PermissionError into directory listing or ``DirEntry.stat`` for chosen paths (E17)."""
    real_scandir = os.scandir
    fail_dirs = {os.path.normcase(os.fspath(p)) for p in fail_dirs}
    fail_stat = {os.path.normcase(os.fspath(p)) for p in fail_stat}

    class Entry:
        def __init__(self, real: os.DirEntry) -> None:
            self._real = real
            self.name = real.name
            self.path = real.path

        def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
            if os.path.normcase(self.path) in fail_stat:
                raise PermissionError(13, "Permission denied", self.path)
            return self._real.stat(follow_symlinks=follow_symlinks)

        def is_junction(self) -> bool:
            return False

    class Listing:
        def __init__(self, entries: list[Entry]) -> None:
            self._entries = entries

        def __enter__(self):
            return iter(self._entries)

        def __exit__(self, *exc_info) -> bool:
            return False

    def fake_scandir(path="."):
        if os.path.normcase(os.fspath(path)) in fail_dirs:
            raise PermissionError(13, "Permission denied", os.fspath(path))
        with real_scandir(path) as it:
            return Listing([Entry(e) for e in it])

    monkeypatch.setattr(os, "scandir", fake_scandir)


def scan_json(target: Path, baseline: Path, *extra) -> tuple[subprocess.CompletedProcess, dict | None]:
    proc = run_cli("scan", target, "--baseline", baseline, "--format", "json", *extra)
    return proc, (json.loads(proc.stdout) if proc.stdout else None)


def events(report: dict) -> list[tuple[str, str]]:
    return [(f["event"], f["subject"]) for f in report["findings"]]
