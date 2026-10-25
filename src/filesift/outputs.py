"""Path safety for the target and for tool output files (Spec §9.4, E10, E13)."""

import json
import os
import stat
import tempfile
from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import Path

from filesift.errors import BaselineMissingError, ConfigError
from filesift.paths import ancestors, backup_path

REPORT_GUARD_MAX_BYTES = 16 * 1024 * 1024
_GUARD_FLAGS = (os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0))


def _absolute(path: Path) -> Path:
    """Absolute path with the parent resolved and the final component left as is."""
    return path.parent.resolve() / path.name


def _key(p: Path) -> str:
    return os.path.normcase(str(p))


def _lstat_or_none(p: Path) -> os.stat_result | None:
    try:
        return os.lstat(p)
    except FileNotFoundError:
        return None


def _describe(st: os.stat_result) -> str:
    if stat.S_ISLNK(st.st_mode):
        return "a symlink"
    if stat.S_ISDIR(st.st_mode):
        return "a directory"
    return "not a regular file"


def _require_parent(abs_p: Path, original: Path) -> None:
    if not os.path.isdir(abs_p.parent):
        raise ConfigError(f"output directory does not exist: {original.parent} (create it first)")


def relative_inside(abs_p: Path, root_r: Path) -> str | None:
    """Relative POSIX path of ``abs_p`` inside ``root_r``, "" for the root itself, None if outside."""
    s, r = _key(abs_p), _key(root_r)
    if s == r:
        return ""
    prefix = r if r.endswith(os.sep) else r + os.sep
    if not s.startswith(prefix):
        return None
    return str(abs_p)[len(prefix):].replace(os.sep, "/")


def inside_target(path: Path, root_r: Path) -> bool:
    return relative_inside(_absolute(path), root_r) is not None


def check_target(path: Path) -> Path:
    """Resolve TARGET once (a symlinked TARGET is the user's explicit choice, E15)."""
    try:
        root_r = path.resolve(strict=True)
    except FileNotFoundError:
        raise ConfigError(f"target does not exist: {path}") from None
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"cannot resolve target {path}: {exc}") from exc
    try:
        st = os.stat(root_r)
    except OSError as exc:
        raise ConfigError(f"cannot stat target {path}: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise ConfigError(f"target is not a directory: {path}")
    return root_r


def check_baseline_path(path: Path, root_r: Path | None, *, creating: bool) -> Path:
    """Validate the baseline location. ``root_r`` is None for ``verify-baseline``."""
    abs_p = _absolute(path)
    if root_r is not None and _key(abs_p) == _key(root_r):
        raise ConfigError(f"baseline path is the target directory itself: {path}")
    if creating:
        _require_parent(abs_p, path)
        for candidate in (abs_p, backup_path(abs_p)):
            st = _lstat_or_none(candidate)
            if st is not None and not stat.S_ISREG(st.st_mode):
                raise ConfigError(f"refusing to write {candidate}: it is {_describe(st)}")
        return abs_p
    st = _lstat_or_none(abs_p)
    if st is None:
        raise BaselineMissingError(f"baseline not found: {path} (create one with 'filesift init-baseline')")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"refusing to read baseline {path}: it is {_describe(st)}")
    return abs_p


def _pattern_excluded(rel: str, patterns: Iterable[str]) -> bool:
    candidates = [*ancestors(rel), rel]
    return any(fnmatchcase(c, pat) for c in candidates for pat in patterns)


def check_report_path(path: Path, root_r: Path, baseline_path: Path, patterns: Iterable[str], *,
                      force_report: bool) -> Path:
    abs_p = _absolute(path)
    _require_parent(abs_p, path)
    if _key(abs_p) in {_key(baseline_path), _key(backup_path(baseline_path))}:
        raise ConfigError(f"report path collides with the baseline or its backup: {path}")
    rel = relative_inside(abs_p, root_r)
    if rel is not None and (rel == "" or not _pattern_excluded(rel, patterns)):
        raise ConfigError(f"report path is inside TARGET: {path} (write it outside the monitored directory, "
                          "or under a path excluded by a stored --exclude pattern)")
    ensure_report_overwritable(abs_p, force_report=force_report)
    return abs_p


def _is_filesift_report(path: Path) -> bool:
    try:
        fd = os.open(path, _GUARD_FLAGS)
    except OSError:
        return False                     # cannot be shown to be a FileSift report
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return False
        data = f.read(REPORT_GUARD_MAX_BYTES + 1)
    if len(data) > REPORT_GUARD_MAX_BYTES:
        return False
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        return False
    envelope = doc.get("envelope") if isinstance(doc, dict) else None
    return isinstance(envelope, dict) and envelope.get("tool") == "FileSift"


def ensure_report_overwritable(path: Path, *, force_report: bool) -> None:
    """Report-overwrite guard (E13). Directories, symlinks and special files are always refused."""
    st = _lstat_or_none(path)
    if st is None:
        return
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"refusing to write report {path}: it is {_describe(st)}")
    if force_report:
        return
    if not _is_filesift_report(path):
        raise ConfigError(f"refusing to overwrite {path}: it is not a FileSift report "
                          "(pass --force-report to overwrite it)")


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file in the same directory, fsync, then os.replace."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".filesift-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
