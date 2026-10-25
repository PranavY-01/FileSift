"""Inventory walker (Spec §6.1, §6.2).

A custom iterative ``os.scandir`` walker. Entries are classified from ``lstat`` data only; symlinks are
never followed and non-regular files are never opened. Inside the target tree only ``DirEntry`` methods
with ``follow_symlinks=False`` and ``os.lstat``/``os.readlink`` are used.
"""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from filesift import hasher
from filesift.errors import RootUnreadableError
from filesift.exclusions import ExclusionPolicy
from filesift.models import Entry, FileEntry, ScanError, SpecialEntry, SymlinkEntry
from filesift.paths import ancestors

_SPECIAL_KINDS = {
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
    stat.S_IFCHR: "char_device",
    stat.S_IFBLK: "block_device",
}


@dataclass
class Inventory:
    entries: dict[str, Entry] = field(default_factory=dict)
    unreadable: dict[str, str] = field(default_factory=dict)
    unstable: set[str] = field(default_factory=set)
    unverified_prefixes: set[str] = field(default_factory=set)
    errors: list[ScanError] = field(default_factory=list)
    undecodable: int = 0
    excluded_by_pattern: int = 0
    artifacts_excluded: int = 0

    def under_unverified_prefix(self, path: str) -> bool:
        return any(a in self.unverified_prefixes for a in ancestors(path))

    def gaps(self) -> list[str]:
        """Relative paths that could not be verified: unreadable/unstable files and unlistable directories."""
        return sorted(set(self.unreadable) | self.unstable | self.unverified_prefixes)

    @property
    def complete(self) -> bool:
        return not self.gaps() and self.undecodable == 0


def kind_from_mode(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return _SPECIAL_KINDS.get(stat.S_IFMT(mode), "other")


def _is_junction(entry: os.DirEntry, st: os.stat_result) -> bool:
    is_junction = getattr(entry, "is_junction", None)          # Python 3.12+
    if is_junction is not None and is_junction():
        return True
    mount_point_tag = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", None)
    return mount_point_tag is not None and getattr(st, "st_reparse_tag", 0) == mount_point_tag


def _classify(entry: os.DirEntry, st: os.stat_result) -> str:
    if _is_junction(entry, st):
        return "symlink"
    return kind_from_mode(st.st_mode)


def _utf8_ok(s: str) -> bool:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def build_inventory(root_r: Path, policy: ExclusionPolicy) -> Inventory:
    inv = Inventory()
    stack: list[str] = [""]                      # relative POSIX dir paths; "" is the root
    while stack:
        rel_dir = stack.pop()
        abs_dir = root_r.joinpath(*rel_dir.split("/")) if rel_dir else root_r
        try:
            with os.scandir(abs_dir) as it:
                listing = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            if rel_dir == "":
                raise RootUnreadableError(f"cannot list target directory {root_r}: {exc}") from exc
            inv.unverified_prefixes.add(rel_dir)
            inv.errors.append(ScanError(kind="DIR_UNREADABLE", subject=rel_dir, message=str(exc)))
            continue

        for entry in listing:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            if not _utf8_ok(rel):                # surrogate-escaped (undecodable) names
                inv.undecodable += 1
                inv.errors.append(ScanError(kind="UNDECODABLE_NAME", subject=repr(rel),
                                            message="name is not valid UTF-8"))
                continue
            _visit(inv, policy, rel, entry, stack)
    return inv


def _visit(inv: Inventory, policy: ExclusionPolicy, rel: str, entry: os.DirEntry, stack: list[str]) -> None:
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError as exc:
        if policy.matches_pattern(rel):
            inv.excluded_by_pattern += 1
        else:
            inv.unreadable[rel] = str(exc)
        return

    verdict = policy.classify(rel, stat.S_ISREG(st.st_mode))
    if verdict == "pattern":
        inv.excluded_by_pattern += 1
        return
    if verdict == "artifact":
        inv.artifacts_excluded += 1
        return

    kind = _classify(entry, st)
    if kind == "dir":
        stack.append(rel)
    elif kind == "file":
        outcome = hasher.hash_stable(entry.path, st)
        if outcome.status == "ok":
            hashed = outcome.stat
            inv.entries[rel] = FileEntry(
                type="file",
                sha256=outcome.digest,
                size_bytes=hashed.st_size,
                mode=f"{stat.S_IMODE(hashed.st_mode):04o}",
                mtime_ns=str(hashed.st_mtime_ns),
            )
        elif outcome.status == "unstable":
            inv.unstable.add(rel)
        else:
            inv.unreadable[rel] = outcome.error
    elif kind == "symlink":
        try:
            target = os.readlink(entry.path)
        except OSError as exc:
            inv.unreadable[rel] = str(exc)
            return
        if not _utf8_ok(target):
            inv.unreadable[rel] = "symlink target is not valid UTF-8"
            return
        inv.entries[rel] = SymlinkEntry(type="symlink", target=target)
    else:
        inv.entries[rel] = SpecialEntry(type="special", kind=kind)     # recorded, never opened
