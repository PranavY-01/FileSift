"""Stability-checked streaming SHA-256 (Spec §6.3, E6).

This is the only module that opens monitored files.
"""

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_FLAGS = (os.O_RDONLY
          | getattr(os, "O_BINARY", 0)
          | getattr(os, "O_NOFOLLOW", 0)
          | getattr(os, "O_NONBLOCK", 0))


class FileUnstable(Exception):
    """The file's identity, size, or mtime changed while it was being hashed."""


@dataclass(frozen=True)
class HashOutcome:
    status: Literal["ok", "unreadable", "unstable"]
    digest: str | None = None
    error: str | None = None
    stat: os.stat_result | None = None   # the post-hash lstat of the successful attempt


def _same_identity(a: os.stat_result, b: os.stat_result) -> bool:
    if a.st_ino and b.st_ino and (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
        return False
    return True


def _hash_once(path: str, pre: os.stat_result) -> tuple[str, os.stat_result]:
    fd = os.open(path, _FLAGS)
    try:
        f = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with f:
        opened = os.fstat(f.fileno())
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(pre, opened):
            raise FileUnstable(path)
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    post = os.lstat(path)
    if (post.st_size, post.st_mtime_ns) != (pre.st_size, pre.st_mtime_ns) or not _same_identity(pre, post):
        raise FileUnstable(path)
    return digest, post


def hash_stable(path: str | Path, pre: os.stat_result) -> HashOutcome:
    """Hash a regular file, retrying once if it changes underneath us.

    A failure is never converted into a digest.
    """
    path = os.fspath(path)
    for attempt in (1, 2):
        try:
            digest, post = _hash_once(path, pre)
            return HashOutcome("ok", digest=digest, stat=post)
        except FileUnstable:
            if attempt == 2:
                return HashOutcome("unstable")
            try:
                pre = os.lstat(path)
            except OSError as exc:
                return HashOutcome("unreadable", error=str(exc))
            if not stat.S_ISREG(pre.st_mode):
                return HashOutcome("unstable")
        except OSError as exc:            # PermissionError, ELOOP from O_NOFOLLOW, vanished file ...
            return HashOutcome("unreadable", error=str(exc))
    raise AssertionError("unreachable")
