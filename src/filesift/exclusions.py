"""Exclusion engine (Spec §6.5, E2).

Tool artifacts are excluded by exact path key, and only when the entry is a regular file.
User patterns are explicit, validated, and stored in the baseline. There are no default exclusions.
"""

import os
from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal

from filesift.errors import ConfigError
from filesift.paths import UnsafePathError, validate_rel_path


def validate_patterns(patterns: Iterable[str]) -> tuple[str, ...]:
    clean: set[str] = set()
    for pat in patterns:
        try:
            clean.add(validate_rel_path(pat))
        except UnsafePathError as exc:
            raise ConfigError(f"invalid --exclude pattern: {exc}") from exc
    return tuple(sorted(clean))


def artifact_key(p: Path) -> str:
    """Key for a tool artifact: the parent is resolved, the final component is not (E2)."""
    return os.path.normcase(str(p.parent.resolve() / p.name))


class ExclusionPolicy:
    def __init__(self, root_r: Path, patterns: Iterable[str], artifact_keys: Iterable[str]) -> None:
        self.root_r = root_r
        self.patterns = tuple(patterns)
        self.artifact_keys = frozenset(artifact_keys)

    def matches_pattern(self, rel: str) -> bool:
        return any(fnmatchcase(rel, pat) for pat in self.patterns)

    def classify(self, rel: str, is_regular: bool) -> Literal["pattern", "artifact"] | None:
        if self.matches_pattern(rel):
            return "pattern"
        # Entry paths are never resolved: a symlink pointing at the baseline is not an artifact.
        if is_regular and self.artifact_keys and os.path.normcase(str(self.root_r / rel)) in self.artifact_keys:
            return "artifact"
        return None
