"""Baseline parse, validate, build and write (Spec §6.8, E3, E4, E5, E14)."""

import json
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from filesift import __version__, integrity
from filesift.errors import (BaselineCorruptError, BaselineError, BaselineExistsError, BaselineInvalidError,
                             BaselineMissingError, ConfigError, OperationalError)
from filesift.models import BaselineDocument, utc_now
from filesift.outputs import atomic_write
from filesift.paths import backup_path, root_fingerprint
from filesift.scanner import Inventory


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        raise BaselineInvalidError(f"baseline contains duplicate keys: {dupes}")
    return dict(pairs)


def _describe_validation(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors(include_url=False)[:5]:
        loc = ".".join(str(x) for x in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    more = exc.error_count() - len(parts)
    return "; ".join(parts) + (f"; and {more} more" if more > 0 else "")


def parse_baseline(raw: bytes, key: bytes | None, source: Path) -> tuple[BaselineDocument, bool]:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BaselineCorruptError(f"baseline is not valid UTF-8 JSON: {source}: {exc}") from exc
    try:
        doc = BaselineDocument.model_validate(data)
    except ValidationError as exc:
        raise BaselineInvalidError(f"baseline failed validation: {source}: {_describe_validation(exc)}") from exc
    authenticated = integrity.verify(data, key)
    return doc, authenticated


def load_baseline(path: Path, key: bytes | None) -> tuple[BaselineDocument, bytes, bool]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise BaselineMissingError(f"baseline not found: {path}") from None
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    doc, authenticated = parse_baseline(raw, key, path)
    return doc, raw, authenticated


def build_baseline_dict(root_r: Path, inventory: Inventory, patterns: tuple[str, ...],
                        key: bytes | None) -> dict[str, Any]:
    gaps = inventory.gaps()
    doc: dict[str, Any] = {
        "schema_version": 1,
        "tool": "FileSift",
        "tool_version": __version__,
        "hash_algorithm": "sha256",
        "created_at": utc_now(),
        "root": {"fingerprint": root_fingerprint(root_r), "label": root_r.name},
        "policy": {"exclusions": list(patterns), "follow_symlinks": False},
        "coverage": {"complete": inventory.complete, "unverified": gaps},
        "entries": {rel: entry.model_dump() for rel, entry in sorted(inventory.entries.items())},
        "integrity": None,
    }
    if key is not None:
        integrity.sign(doc, key)
    BaselineDocument.model_validate(doc)          # never write what we could not load back
    return doc


def serialize_baseline(doc: dict[str, Any]) -> bytes:
    return (json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_baseline(path: Path, data: bytes, *, force: bool) -> None:
    if not os.path.isdir(path.parent):
        raise ConfigError(f"output directory does not exist: {path.parent}")
    if not force:
        try:
            f = open(path, "xb")                  # O_EXCL: atomic "create only if absent"
        except FileExistsError:
            raise BaselineExistsError(f"baseline already exists: {path} (use --force to replace it; "
                                      "the previous file is kept as .bak)") from None
        except OSError as exc:
            raise OperationalError(f"cannot create baseline {path}: {exc}") from exc
        try:
            with f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException as exc:
            path.unlink(missing_ok=True)          # never leave a partial baseline
            if isinstance(exc, OSError):
                raise OperationalError(f"cannot write baseline {path}: {exc}") from exc
            raise
        return
    try:
        if os.path.lexists(path):
            atomic_write(backup_path(path), path.read_bytes())
        atomic_write(path, data)
    except OSError as exc:
        raise OperationalError(f"cannot write baseline {path}: {exc}") from exc
