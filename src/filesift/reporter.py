"""Scan report assembly in the shared ``7d7b-report`` envelope (Spec §8.3, §8.5, E13, E16)."""

import json
from pathlib import Path
from typing import Any

from filesift import __version__
from filesift.comparator import Outcome
from filesift.errors import OperationalError
from filesift.models import BaselineDocument, Finding
from filesift.outputs import atomic_write, ensure_report_overwritable
from filesift.paths import root_fingerprint
from filesift.scanner import Inventory

ENVELOPE_SCHEMA = "7d7b-report"
ENVELOPE_SCHEMA_VERSION = 1

_SUMMARY_KEYS = (
    ("added", "ADDED"),
    ("modified", "MODIFIED"),
    ("deleted", "DELETED"),
    ("type_changed", "TYPE_CHANGED"),
    ("permissions_changed", "PERMISSIONS_CHANGED"),
    ("unreadable", "UNREADABLE"),
    ("unstable", "UNSTABLE"),
    ("unverified", "UNVERIFIED"),
)


def build_report(*, run_id: str, started_at: str, completed_at: str, outcome: Outcome, root_r: Path,
                 baseline: BaselineDocument, baseline_sha256: str, authenticated: bool, root_match: bool,
                 inv: Inventory, findings: list[Finding]) -> dict[str, Any]:
    summary = {key: sum(1 for f in findings if f.event == event) for key, event in _SUMMARY_KEYS}
    summary["errors"] = len(inv.errors)
    return {
        "envelope": {
            "schema": ENVELOPE_SCHEMA,
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "tool": "FileSift",
            "tool_version": __version__,
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "status": outcome.status,
        "result": outcome.result,
        "target": {
            "label": root_r.name,
            "root_fingerprint": root_fingerprint(root_r),
        },
        "baseline": {
            "sha256": baseline_sha256,
            "created_at": baseline.created_at,
            "authenticated": authenticated,
            "root_match": root_match,
        },
        "coverage": {
            "complete": outcome.coverage_complete,
            "entries_inventoried": len(inv.entries),
            "excluded_by_pattern": inv.excluded_by_pattern,
            "artifacts_excluded": inv.artifacts_excluded,
            "exclusions_applied": list(baseline.policy.exclusions),
            "unverified_prefixes": sorted(inv.unverified_prefixes),
        },
        "summary": summary,
        "findings": [f.model_dump() for f in findings],
        "errors": [e.model_dump() for e in sorted(inv.errors, key=lambda e: (e.subject, e.kind))],
    }


def dumps_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def write_report(path: Path, report: dict[str, Any], *, force_report: bool) -> None:
    ensure_report_overwritable(path, force_report=force_report)      # re-checked: the scan took time
    try:
        atomic_write(path, dumps_report(report).encode("utf-8"))
    except OSError as exc:
        raise OperationalError(f"cannot write report {path}: {exc}") from exc
