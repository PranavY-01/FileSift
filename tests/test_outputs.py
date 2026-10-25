import json
import os

import pytest

from conftest import needs_symlink
from filesift.errors import BaselineMissingError, ConfigError
from filesift.outputs import check_baseline_path, check_report_path, check_target, inside_target


@pytest.fixture
def layout(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    return target.resolve(), state, reports


# TARGET

def test_target_missing(tmp_path):
    with pytest.raises(ConfigError, match="does not exist"):
        check_target(tmp_path / "nope")


def test_target_not_a_directory(tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    with pytest.raises(ConfigError, match="not a directory"):
        check_target(tmp_path / "f")


def test_target_resolved(tmp_path):
    (tmp_path / "t").mkdir()
    assert check_target(tmp_path / "t" / ".." / "t") == (tmp_path / "t").resolve()


@needs_symlink
def test_symlinked_target_is_resolved_once(tmp_path):
    (tmp_path / "real").mkdir()
    os.symlink(tmp_path / "real", tmp_path / "alias", target_is_directory=True)
    assert check_target(tmp_path / "alias") == (tmp_path / "real").resolve()


# Baseline

def test_baseline_parent_missing(layout, tmp_path):
    with pytest.raises(ConfigError, match="output directory does not exist"):
        check_baseline_path(tmp_path / "missing" / "b.json", layout[0], creating=True)


def test_baseline_existing_directory_refused(layout):
    target, state, _ = layout
    (state / "b.json").mkdir()
    with pytest.raises(ConfigError, match="directory"):
        check_baseline_path(state / "b.json", target, creating=True)
    with pytest.raises(ConfigError, match="directory"):
        check_baseline_path(state / "b.json", target, creating=False)


def test_baseline_backup_directory_refused(layout):
    target, state, _ = layout
    (state / "b.json.bak").mkdir()
    with pytest.raises(ConfigError):
        check_baseline_path(state / "b.json", target, creating=True)


@needs_symlink
def test_baseline_symlink_refused(layout, tmp_path):
    target, state, _ = layout
    (tmp_path / "elsewhere.json").write_bytes(b"{}")
    os.symlink(tmp_path / "elsewhere.json", state / "b.json")
    with pytest.raises(ConfigError, match="symlink"):
        check_baseline_path(state / "b.json", target, creating=True)
    with pytest.raises(ConfigError, match="symlink"):
        check_baseline_path(state / "b.json", target, creating=False)


def test_baseline_ok_returns_absolute_path(layout):
    target, state, _ = layout
    result = check_baseline_path(state / "b.json", target, creating=True)
    assert result.is_absolute()
    assert result.name == "b.json"


def test_baseline_missing_for_reading_is_exit_3(layout):
    with pytest.raises(BaselineMissingError) as exc:
        check_baseline_path(layout[1] / "b.json", layout[0], creating=False)
    assert exc.value.exit_code == 3


def test_baseline_equal_to_target_refused(layout):
    with pytest.raises(ConfigError):
        check_baseline_path(layout[0], layout[0], creating=True)


def test_inside_target(layout):
    target, state, _ = layout
    assert inside_target(target / "b.json", target)
    assert inside_target(target / "sub" / "b.json", target)
    assert not inside_target(state / "b.json", target)


# Report

def _check_report(layout, path, patterns=(), force_report=False):
    target, state, _ = layout
    return check_report_path(path, target, (state / "b.json").resolve(), patterns, force_report=force_report)


def test_report_parent_missing(layout, tmp_path):
    with pytest.raises(ConfigError, match="output directory"):
        _check_report(layout, tmp_path / "missing" / "r.json")


def test_report_equal_to_baseline(layout):
    with pytest.raises(ConfigError, match="collides"):
        _check_report(layout, layout[1] / "b.json")


def test_report_equal_to_baseline_backup(layout):
    with pytest.raises(ConfigError, match="collides"):
        _check_report(layout, layout[1] / "b.json.bak")


@pytest.mark.skipif(os.name != "nt", reason="case-insensitive path comparison applies on Windows")
def test_report_collision_is_case_insensitive_on_windows(layout):
    with pytest.raises(ConfigError, match="collides"):
        _check_report(layout, layout[1] / "B.JSON")


def test_report_inside_target_refused(layout):
    target = layout[0]
    with pytest.raises(ConfigError, match="inside TARGET"):
        _check_report(layout, target / "r.json")
    with pytest.raises(ConfigError, match="inside TARGET"):
        _check_report(layout, target)


def test_report_inside_target_allowed_when_pattern_excluded(layout):
    target = layout[0]
    (target / "reports").mkdir()
    assert _check_report(layout, target / "reports" / "r.json", patterns=("reports",))
    assert _check_report(layout, target / "r.json", patterns=("*.json",))


def test_report_outside_target_ok(layout):
    assert _check_report(layout, layout[2] / "r.json").name == "r.json"


def test_report_existing_non_filesift_file(layout):
    path = layout[2] / "r.json"
    path.write_bytes(b"precious")
    with pytest.raises(ConfigError, match="not a FileSift report"):
        _check_report(layout, path)
    assert _check_report(layout, path, force_report=True)


def test_report_existing_filesift_report_ok(layout):
    path = layout[2] / "r.json"
    path.write_text(json.dumps({"envelope": {"tool": "FileSift"}}), encoding="utf-8")
    assert _check_report(layout, path)


def test_report_existing_directory(layout):
    (layout[2] / "r.json").mkdir()
    with pytest.raises(ConfigError, match="directory"):
        _check_report(layout, layout[2] / "r.json", force_report=True)
