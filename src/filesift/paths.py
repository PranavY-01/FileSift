"""Canonical relative-path rules (Spec §6.4) and the root fingerprint (E15).

Stored paths are canonical relative POSIX strings. Non-canonical input is rejected, never normalized.
"""

import hashlib
import os
import re
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

_DRIVE = re.compile(r"^[A-Za-z]:")


class UnsafePathError(ValueError):
    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"unsafe path {path!r}: {reason}")
        self.path = path
        self.reason = reason


def validate_rel_path(p: str) -> str:
    if not p or "\x00" in p or "\\" in p:
        raise UnsafePathError(p, "empty, NUL, or backslash")
    if p.startswith("/") or _DRIVE.match(p):
        raise UnsafePathError(p, "absolute, UNC, or drive-qualified")
    if any(part in ("", ".", "..") for part in p.split("/")):
        raise UnsafePathError(p, "empty, '.', or '..' segment")
    try:
        p.encode("utf-8")
    except UnicodeEncodeError:
        raise UnsafePathError(p, "not valid UTF-8") from None
    return p


def ancestors(p: str) -> Iterator[str]:
    """Yield the proper ancestors of a relative path: ``a/b/c`` -> ``a``, ``a/b``."""
    parts = p.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[:i])


def is_at_or_under(p: str, prefixes: set[str] | frozenset[str]) -> bool:
    return p in prefixes or any(a in prefixes for a in ancestors(p))


def _case_insensitive_platform() -> bool:
    return os.name == "nt" or sys.platform == "darwin"


def validate_entry_set(keys: Iterable[str], gaps: Iterable[str]) -> None:
    """Cross-entry checks: case collisions, prefix conflicts, and entries inside baseline gaps (E4)."""
    keys = sorted(keys)
    key_set = set(keys)
    gap_set = {validate_rel_path(g) for g in gaps}

    if _case_insensitive_platform():
        seen: dict[str, str] = {}
        for k in keys:
            folded = k.casefold()
            if folded in seen:
                raise UnsafePathError(k, f"collides with {seen[folded]!r} on a case-insensitive filesystem")
            seen[folded] = k

    for k in keys:
        for a in ancestors(k):
            if a in key_set:
                raise UnsafePathError(k, f"lies under entry {a!r}, which is not a directory")
        if is_at_or_under(k, gap_set):
            raise UnsafePathError(k, "is at or under a path recorded as unverified")


def root_fingerprint(root_r: Path) -> str:
    normalized = os.path.normcase(str(root_r))
    return "sha256:" + hashlib.sha256(os.fsencode(normalized)).hexdigest()


def backup_path(p: Path) -> Path:
    return p.with_name(p.name + ".bak")
