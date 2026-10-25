import json
import os
import re
import uuid

import pytest

from conftest import needs_symlink
from filesift import outputs
from filesift.baseline import build_baseline_dict, serialize_baseline
from filesift.comparator import compare, derive
from filesift.errors import ConfigError, OperationalError
from filesift.exclusions import ExclusionPolicy
from filesift.models import TIMESTAMP_PATTERN, BaselineDocument
from filesift.paths import root_fingerprint
from filesift.reporter import build_report, dumps_report, write_report
from filesift.scanner import build_inventory


@pytest.fixture
def scanned(make_tree):
    root = make_tree({"keep.txt": "same", "mod.txt": "before", "gone.txt": "bye", "x.log": "excluded"})
    root_r = root.resolve()
    policy = ExclusionPolicy(root_r, ("*.log",), ())
    doc_dict = build_baseline_dict(root_r, build_inventory(root_r, policy), ("*.log",), None)
    raw = serialize_baseline(doc_dict)
    doc = BaselineDocument.model_validate(doc_dict)
    (root / "mod.txt").write_bytes(b"after!")
    (root / "gone.txt").unlink()
    (root / "new.txt").write_bytes(b"hello")
    inv = build_inventory(root_r, policy)
    findings = compare(doc, inv)
    outcome = derive(findings, inv, doc)
    report = build_report(run_id=str(uuid.uuid4()), started_at="2026-10-25T12:30:00Z",
                          completed_at="2026-10-25T12:30:01Z", outcome=outcome, root_r=root_r, baseline=doc,
                          baseline_sha256="d" * 64, authenticated=False, root_match=True, inv=inv,
                          findings=findings)
    return report, raw, root_r


def test_report_is_valid_json_round_trip(scanned):
    report, _, _ = scanned
    assert json.loads(dumps_report(report)) == report


def test_envelope_fields(scanned):
    env = scanned[0]["envelope"]
    assert env["schema"] == "7d7b-report"
    assert env["schema_version"] == 1
    assert env["tool"] == "FileSift"
    assert env["tool_version"] == "1.0.0"
    assert uuid.UUID(env["run_id"]).version == 4
    assert re.match(TIMESTAMP_PATTERN, env["started_at"])
    assert re.match(TIMESTAMP_PATTERN, env["completed_at"])


def test_counts_match_findings(scanned):
    report = scanned[0]
    assert [(f["event"], f["subject"]) for f in report["findings"]] == [
        ("DELETED", "gone.txt"), ("MODIFIED", "mod.txt"), ("ADDED", "new.txt")]
    summary = report["summary"]
    assert summary == {"added": 1, "modified": 1, "deleted": 1, "type_changed": 0, "permissions_changed": 0,
                       "unreadable": 0, "unstable": 0, "unverified": 0, "errors": 0}
    assert sum(summary.values()) == len(report["findings"]) + len(report["errors"])
    assert all(set(f) == {"event", "category", "subject", "details"} for f in report["findings"])


def test_provenance_fields(scanned):
    report, _, root_r = scanned
    assert report["status"] == "changes_detected"
    assert report["result"] == "changes_detected"
    assert report["target"] == {"label": root_r.name, "root_fingerprint": root_fingerprint(root_r)}
    assert report["baseline"]["sha256"] == "d" * 64
    assert re.match(TIMESTAMP_PATTERN, report["baseline"]["created_at"])
    assert report["baseline"]["authenticated"] is False
    assert report["baseline"]["root_match"] is True
    assert report["coverage"] == {"complete": True, "entries_inventoried": 3, "excluded_by_pattern": 1,
                                  "artifacts_excluded": 0, "exclusions_applied": ["*.log"],
                                  "unverified_prefixes": []}
    assert report["errors"] == []


def test_write_new_report(tmp_path, scanned):
    path = tmp_path / "scan.json"
    write_report(path, scanned[0], force_report=False)
    assert json.loads(path.read_text(encoding="utf-8")) == scanned[0]


def test_existing_filesift_report_is_overwritten(tmp_path, scanned):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"envelope": {"tool": "FileSift"}, "old": True}), encoding="utf-8")
    write_report(path, scanned[0], force_report=False)
    assert "old" not in json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("content", [
    b"important notes",
    b"[1, 2, 3]",
    b'{"envelope": {"tool": "OtherTool"}}',
    b'{"envelope": "FileSift"}',
    b"\xff\xfe\x00",
])
def test_non_filesift_file_is_not_overwritten(tmp_path, scanned, content):
    path = tmp_path / "scan.json"
    path.write_bytes(content)
    with pytest.raises(ConfigError, match="--force-report"):
        write_report(path, scanned[0], force_report=False)
    assert path.read_bytes() == content
    write_report(path, scanned[0], force_report=True)
    assert json.loads(path.read_text(encoding="utf-8"))["envelope"]["tool"] == "FileSift"


def test_oversized_existing_file_is_not_trusted(tmp_path, scanned):
    path = tmp_path / "scan.json"
    padding = b" " * (outputs.REPORT_GUARD_MAX_BYTES + 1)
    path.write_bytes(b'{"envelope": {"tool": "FileSift"}}' + padding)
    with pytest.raises(ConfigError):
        write_report(path, scanned[0], force_report=False)


def test_directory_at_report_path_refused_even_with_force(tmp_path, scanned):
    (tmp_path / "scan.json").mkdir()
    with pytest.raises(ConfigError, match="directory"):
        write_report(tmp_path / "scan.json", scanned[0], force_report=True)


@needs_symlink
def test_symlink_at_report_path_refused_even_with_force(tmp_path, scanned):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"keep me")
    os.symlink(victim, tmp_path / "scan.json")
    with pytest.raises(ConfigError, match="symlink"):
        write_report(tmp_path / "scan.json", scanned[0], force_report=True)
    assert victim.read_bytes() == b"keep me"


def test_disk_full_leaves_no_partial_report(tmp_path, scanned, monkeypatch):
    path = tmp_path / "scan.json"
    original = json.dumps({"envelope": {"tool": "FileSift"}}).encode()
    path.write_bytes(original)

    def disk_full(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(outputs.os, "fsync", disk_full)
    with pytest.raises(OperationalError) as exc:
        write_report(path, scanned[0], force_report=False)
    assert exc.value.exit_code == 4
    assert path.read_bytes() == original
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".filesift-tmp-")] == []
