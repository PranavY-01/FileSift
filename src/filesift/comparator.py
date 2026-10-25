"""Evidence-based comparison and outcome derivation (Spec §5.3, §6.6, §6.7, E4, E5)."""

from dataclasses import dataclass
from typing import Any, Literal

from filesift.models import BaselineDocument, Finding
from filesift.paths import ancestors, is_at_or_under
from filesift.scanner import Inventory

INTEGRITY_EVENTS = frozenset({"ADDED", "MODIFIED", "DELETED", "TYPE_CHANGED", "PERMISSIONS_CHANGED"})
COVERAGE_EVENTS = frozenset({"UNREADABLE", "UNSTABLE", "UNVERIFIED"})


def _finding(event: str, subject: str, details: dict[str, Any]) -> Finding:
    category = "integrity" if event in INTEGRITY_EVENTS else "coverage"
    return Finding(event=event, category=category, subject=subject, details=details)


def compare(baseline: BaselineDocument, inv: Inventory) -> list[Finding]:
    base = baseline.entries
    cur = inv.entries
    gaps = frozenset(baseline.coverage.unverified)
    subjects = base.keys() | cur.keys() | inv.unreadable.keys() | inv.unstable
    findings: list[Finding] = []

    for path in subjects:
        b, c = base.get(path), cur.get(path)

        if path in inv.unreadable:
            findings.append(_finding("UNREADABLE", path, {"error": inv.unreadable[path]}))
        elif path in inv.unstable:
            findings.append(_finding("UNSTABLE", path, {}))
        elif is_at_or_under(path, gaps):
            findings.append(_finding("UNVERIFIED", path, {"reason": "unverified in baseline"}))
        elif b is None:
            findings.append(_finding("ADDED", path, c.summary()))
        elif c is None:
            if inv.under_unverified_prefix(path):
                findings.append(_finding("UNVERIFIED", path, {"reason": "parent directory not listable"}))
            else:
                findings.append(_finding("DELETED", path, b.summary()))
        elif b.type != c.type:
            findings.append(_finding("TYPE_CHANGED", path, {"old_type": b.type, "new_type": c.type}))
        elif b.type == "file" and b.sha256 != c.sha256:
            findings.append(_finding("MODIFIED", path, {
                "old_sha256": b.sha256, "new_sha256": c.sha256,
                "old_size": b.size_bytes, "new_size": c.size_bytes,
                "mode_changed": b.mode != c.mode}))
        elif b.type == "symlink" and b.target != c.target:
            findings.append(_finding("MODIFIED", path, {"old_target": b.target, "new_target": c.target}))
        elif b.type == "special" and b.kind != c.kind:
            findings.append(_finding("TYPE_CHANGED", path, {"old_type": b.kind, "new_type": c.kind}))
        elif b.type == "file" and b.mode != c.mode:
            findings.append(_finding("PERMISSIONS_CHANGED", path, {"old_mode": b.mode, "new_mode": c.mode}))

    # A baseline gap with nothing observed at or under it is still reported, so gaps are always visible.
    touched: set[str] = set()
    for path in subjects:
        touched.add(path)
        touched.update(ancestors(path))
    for gap in gaps - touched:
        findings.append(_finding("UNVERIFIED", gap, {"reason": "unverified in baseline"}))

    findings.sort(key=lambda f: (f.subject, f.event))
    return findings


@dataclass(frozen=True)
class Outcome:
    status: Literal["clean", "changes_detected", "incomplete"]
    result: Literal["clean", "changes_detected"]
    coverage_complete: bool
    exit_code: int


def derive(findings: list[Finding], inv: Inventory, baseline: BaselineDocument) -> Outcome:
    coverage_complete = baseline.coverage.complete and not (
        inv.unverified_prefixes or inv.undecodable or inv.unreadable or inv.unstable
        or any(f.event in COVERAGE_EVENTS for f in findings))
    result = "changes_detected" if any(f.event in INTEGRITY_EVENTS for f in findings) else "clean"
    if not coverage_complete:
        return Outcome("incomplete", result, False, 4)
    if result == "changes_detected":
        return Outcome("changes_detected", result, True, 1)
    return Outcome("clean", result, True, 0)
