"""Pydantic v2 data models (Spec §8). All models are strict and reject unknown fields."""

from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from filesift.paths import validate_entry_set, validate_rel_path

# ASCII-only character classes: `\d` would also accept non-ASCII digits.
TIMESTAMP_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"

Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Mode = Annotated[str, StringConstraints(pattern=r"^[0-7]{4}$")]
MtimeNs = Annotated[str, StringConstraints(pattern=r"^[0-9]+$")]
Timestamp = Annotated[str, StringConstraints(pattern=TIMESTAMP_PATTERN)]
Fingerprint = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]

SpecialKind = Literal["fifo", "socket", "char_device", "block_device", "other"]
Event = Literal[
    "ADDED", "MODIFIED", "DELETED", "TYPE_CHANGED", "PERMISSIONS_CHANGED",
    "UNREADABLE", "UNSTABLE", "UNVERIFIED",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class FileEntry(_Strict):
    type: Literal["file"]
    sha256: Sha256Hex
    size_bytes: int = Field(ge=0)
    mode: Mode
    mtime_ns: MtimeNs

    def summary(self) -> dict[str, Any]:
        return {"type": self.type, "sha256": self.sha256, "size_bytes": self.size_bytes}


class SymlinkEntry(_Strict):
    type: Literal["symlink"]
    target: str

    def summary(self) -> dict[str, Any]:
        return {"type": self.type, "target": self.target}


class SpecialEntry(_Strict):
    type: Literal["special"]
    kind: SpecialKind

    def summary(self) -> dict[str, Any]:
        return {"type": self.type, "kind": self.kind}


Entry = Annotated[Union[FileEntry, SymlinkEntry, SpecialEntry], Field(discriminator="type")]


def _require_canonical_list(values: list[str], what: str) -> list[str]:
    for v in values:
        validate_rel_path(v)
    if values != sorted(set(values)):
        raise ValueError(f"{what} must be sorted and free of duplicates")
    return values


class Integrity(_Strict):
    algorithm: Literal["hmac-sha256"]
    mac: Sha256Hex


class Policy(_Strict):
    exclusions: list[str]
    follow_symlinks: bool                # strict bool: unlike Literal[False], rejects JSON `0`

    @field_validator("exclusions")
    @classmethod
    def _canonical_patterns(cls, v: list[str]) -> list[str]:
        return _require_canonical_list(v, "exclusions")

    @field_validator("follow_symlinks")
    @classmethod
    def _never_follow(cls, v: bool) -> bool:
        if v:
            raise ValueError("follow_symlinks must be false: FileSift never follows symlinks")
        return v


class Root(_Strict):
    fingerprint: Fingerprint
    label: str


class Coverage(_Strict):
    complete: bool
    unverified: list[str]

    @field_validator("unverified")
    @classmethod
    def _canonical_gaps(cls, v: list[str]) -> list[str]:
        return _require_canonical_list(v, "unverified")

    @model_validator(mode="after")
    def _consistent(self) -> "Coverage":
        if self.complete and self.unverified:
            raise ValueError("coverage.complete is true but coverage.unverified is not empty")
        return self


class BaselineDocument(_Strict):
    schema_version: int                  # strict int: unlike Literal[1], rejects JSON `true`
    tool: Literal["FileSift"]
    tool_version: str
    hash_algorithm: Literal["sha256"]
    created_at: Timestamp
    root: Root
    policy: Policy
    coverage: Coverage
    entries: dict[str, Entry]
    integrity: Integrity | None

    @field_validator("schema_version")
    @classmethod
    def _supported_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"unsupported schema_version {v} (this FileSift reads version 1)")
        return v

    @model_validator(mode="after")
    def _check_paths(self) -> "BaselineDocument":
        for key in self.entries:
            validate_rel_path(key)
        validate_entry_set(self.entries.keys(), self.coverage.unverified)
        return self


class Finding(_Strict):
    event: Event
    category: Literal["integrity", "coverage"]
    subject: str
    details: dict[str, Any]


class ScanError(_Strict):
    kind: Literal["DIR_UNREADABLE", "UNDECODABLE_NAME"]
    subject: str
    message: str
