"""End-to-end tests. Most run the real entry point in a subprocess so exit codes are true process exit codes;
failure-injection tests run ``cli.main()`` in-process so engine functions can be monkeypatched."""

import ast
import hashlib
import importlib.metadata
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import (build_tree, events, linux_only, needs_fifo, needs_symlink, patch_scandir, posix_only,
                      posix_perms, run_cli, scan_json)
from filesift import __version__
from filesift.render import render_scan, safe_display

KEY = "k" * 32
CORE_MODULES = ("models", "errors", "paths", "hasher", "exclusions", "scanner", "baseline", "integrity",
                "comparator", "reporter", "outputs")


@pytest.fixture
def ws(tmp_path):
    """A target tree (the Spec §15.2 demo data) plus state/ and reports/ directories outside it."""
    target = build_tree(tmp_path / "target", {
        "config": {"settings.json": '{"debug": false}'},
        "scripts": {"backup.py": 'print("backup")\n'},
        "old_script.py": 'print("legacy")\n',
    })
    (tmp_path / "state").mkdir()
    (tmp_path / "reports").mkdir()
    return SimpleNamespace(tmp=tmp_path, target=target, baseline=tmp_path / "state" / "baseline.json",
                           reports=tmp_path / "reports")


def _init(ws, *extra, env=None):
    return run_cli("init-baseline", ws.target, "--baseline", ws.baseline, *extra, env=env)


@pytest.fixture
def based(ws):
    proc = _init(ws)
    assert proc.returncode == 0, proc.stderr
    return ws


# ---------------------------------------------------------------- version, help, usage

def test_version_matches_package_metadata():
    proc = run_cli("--version")
    assert proc.returncode == 0
    assert proc.stdout.strip() == "filesift 1.0.0"
    assert __version__ == importlib.metadata.version("filesift") == "1.0.0"


def test_help():
    proc = run_cli("--help")
    assert proc.returncode == 0
    for command in ("init-baseline", "scan", "verify-baseline"):
        assert command in proc.stdout
    scan_help = run_cli("scan", "--help")
    assert scan_help.returncode == 0
    assert "--allow-root-mismatch" in scan_help.stdout


def test_usage_error_is_exit_2(ws):
    proc = run_cli("scan", ws.target)                      # --baseline is required
    assert proc.returncode == 2
    assert proc.stdout == ""


def test_bad_format_value_is_exit_2(based):
    assert run_cli("scan", based.target, "--baseline", based.baseline, "--format", "xml").returncode == 2


# ---------------------------------------------------------------- Spec §12.3 workflow

def test_init_prints_baseline_digest_and_verify_agrees(ws):
    proc = _init(ws)
    assert proc.returncode == 0, proc.stderr
    digest = hashlib.sha256(ws.baseline.read_bytes()).hexdigest()
    assert digest in proc.stdout
    assert "3 recorded" in proc.stdout
    doc = json.loads(ws.baseline.read_text(encoding="utf-8"))
    assert sorted(doc["entries"]) == ["config/settings.json", "old_script.py", "scripts/backup.py"]
    verify = run_cli("verify-baseline", "--baseline", ws.baseline)
    assert verify.returncode == 0, verify.stderr
    assert digest in verify.stdout


def test_scan_unchanged_is_clean(based):
    proc = run_cli("scan", based.target, "--baseline", based.baseline)
    assert proc.returncode == 0, proc.stderr
    assert "CLEAN" in proc.stdout
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 0
    assert (report["status"], report["result"], report["findings"]) == ("clean", "clean", [])


def test_modified_file(based):
    (based.target / "config" / "settings.json").write_bytes(b'{"debug": true}')
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("MODIFIED", "config/settings.json")]
    assert report["findings"][0]["details"]["old_size"] == 16
    assert report["findings"][0]["details"]["new_size"] == 15


def test_added_file(based):
    (based.target / "scripts" / "new_task.py").write_bytes(b'print("new")\n')
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("ADDED", "scripts/new_task.py")]


def test_deleted_file(based):
    (based.target / "old_script.py").unlink()
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("DELETED", "old_script.py")]


@posix_only
def test_chmod_is_permissions_changed(based):
    script = based.target / "scripts" / "backup.py"
    script.chmod(script.stat().st_mode | 0o111)
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("PERMISSIONS_CHANGED", "scripts/backup.py")]


@posix_only
def test_content_and_mode_change(based):
    script = based.target / "scripts" / "backup.py"
    script.write_bytes(b"evil\n")
    script.chmod(0o4755)
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("MODIFIED", "scripts/backup.py")]
    assert report["findings"][0]["details"]["mode_changed"] is True


@posix_perms
def test_unreadable_subdirectory_real(ws):
    build_tree(ws.target / "private", {"keys.conf": "secret", "deep": {"x": "1"}})
    assert _init(ws).returncode == 0
    (ws.target / "private").chmod(0)
    try:
        proc = run_cli("scan", ws.target, "--baseline", ws.baseline)
        jproc, report = scan_json(ws.target, ws.baseline)
    finally:
        (ws.target / "private").chmod(0o700)
    assert proc.returncode == 4
    assert "NOT a clean result" in proc.stdout
    assert jproc.returncode == 4
    assert events(report) == [("UNVERIFIED", "private/deep/x"), ("UNVERIFIED", "private/keys.conf")]
    assert not any(f["event"] == "DELETED" for f in report["findings"])
    assert report["coverage"]["unverified_prefixes"] == ["private"]


def test_unreadable_subdirectory_injected(ws, run_main, monkeypatch):
    build_tree(ws.target / "private", {"keys.conf": "secret"})
    assert _init(ws).returncode == 0
    patch_scandir(monkeypatch, fail_dirs=[ws.target.resolve() / "private"])
    code, out, _ = run_main("scan", ws.target, "--baseline", ws.baseline, "--format", "json")
    report = json.loads(out)
    assert code == 4
    assert (report["status"], report["result"]) == ("incomplete", "clean")
    assert events(report) == [("UNVERIFIED", "private/keys.conf")]
    assert report["errors"][0]["kind"] == "DIR_UNREADABLE"


def test_corrupt_baseline_is_exit_3_and_writes_nothing(based):
    based.baseline.write_bytes(b'{"tool": "FileSift", ')
    report_path = based.reports / "scan.json"
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", report_path,
                   "--format", "json")
    assert proc.returncode == 3
    assert proc.stdout == ""                                  # E9: nothing on stdout in json mode
    assert "error:" in proc.stderr
    assert not report_path.exists()                           # E9: fatal outcomes write no report


def test_init_again_without_force_leaves_baseline_byte_identical(based):
    before = based.baseline.read_bytes()
    (based.target / "old_script.py").write_bytes(b"changed")
    proc = _init(based)
    assert proc.returncode == 2
    assert "--force" in proc.stderr
    assert based.baseline.read_bytes() == before


def test_init_force_replaces_and_keeps_backup(based):
    before = based.baseline.read_bytes()
    (based.target / "old_script.py").write_bytes(b"changed")
    proc = _init(based, "--force")
    assert proc.returncode == 0, proc.stderr
    assert Path(str(based.baseline) + ".bak").read_bytes() == before
    assert based.baseline.read_bytes() != before
    assert run_cli("scan", based.target, "--baseline", based.baseline).returncode == 0


def test_format_json_puts_only_the_report_on_stdout(based):
    (based.target / "old_script.py").unlink()
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--format", "json")
    assert proc.returncode == 1
    report = json.loads(proc.stdout)                          # the whole of stdout parses as one document
    assert report["envelope"]["tool"] == "FileSift"
    assert proc.stdout.lstrip().startswith("{") and proc.stdout.rstrip().endswith("}")


def test_report_inside_target_is_exit_2(based):
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", based.target / "r.json")
    assert proc.returncode == 2
    assert not (based.target / "r.json").exists()


def test_different_exclude_at_scan_is_exit_2(ws):
    assert _init(ws, "--exclude", "*.log").returncode == 0
    proc = run_cli("scan", ws.target, "--baseline", ws.baseline, "--exclude", "*.tmp")
    assert proc.returncode == 2
    assert "does not match" in proc.stderr


# ---------------------------------------------------------------- Spec §12.4 acceptance matrix (remaining rows)

@needs_symlink
def test_file_replaced_by_symlink(based):
    victim = based.target / "old_script.py"
    victim.unlink()
    os.symlink("scripts/backup.py", victim)
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("TYPE_CHANGED", "old_script.py")]


@needs_symlink
def test_symlink_retargeted(ws):
    os.symlink("scripts/backup.py", ws.target / "run")
    assert _init(ws).returncode == 0
    (ws.target / "run").unlink()
    os.symlink("/tmp/evil.py", ws.target / "run")
    proc, report = scan_json(ws.target, ws.baseline)
    assert proc.returncode == 1
    assert report["findings"][0]["details"] == {"old_target": "scripts/backup.py", "new_target": "/tmp/evil.py"}


def test_empty_directory_is_clean(tmp_path):
    (tmp_path / "empty").mkdir()
    baseline = tmp_path / "b.json"
    assert run_cli("init-baseline", tmp_path / "empty", "--baseline", baseline).returncode == 0
    proc, report = scan_json(tmp_path / "empty", baseline)
    assert proc.returncode == 0
    assert report["status"] == "clean"
    assert report["coverage"]["entries_inventoried"] == 0


def test_directory_replaced_by_file(based):
    shutil.rmtree(based.target / "config")
    (based.target / "config").write_bytes(b"now a file")
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 1
    assert events(report) == [("ADDED", "config"), ("DELETED", "config/settings.json")]


@posix_perms
def test_unreadable_file_without_changes_real(based):
    victim = based.target / "old_script.py"
    victim.chmod(0)
    try:
        proc, report = scan_json(based.target, based.baseline)
    finally:
        victim.chmod(0o600)
    assert proc.returncode == 4
    assert (report["status"], report["result"]) == ("incomplete", "clean")
    assert events(report) == [("UNREADABLE", "old_script.py")]


def test_unreadable_file_without_changes_injected(based, run_main, monkeypatch):
    patch_scandir(monkeypatch, fail_stat=[based.target.resolve() / "old_script.py"])
    code, out, _ = run_main("scan", based.target, "--baseline", based.baseline, "--format", "json")
    report = json.loads(out)
    assert code == 4
    assert (report["status"], report["result"]) == ("incomplete", "clean")
    assert events(report) == [("UNREADABLE", "old_script.py")]


def test_unreadable_subtree_plus_modified_file_writes_report(ws, run_main, monkeypatch):
    """Changes and coverage gaps together: exit 4, findings kept, and the report IS written (E9)."""
    build_tree(ws.target / "private", {"keys.conf": "secret"})
    assert _init(ws).returncode == 0
    (ws.target / "config" / "settings.json").write_bytes(b'{"debug": true}')
    patch_scandir(monkeypatch, fail_dirs=[ws.target.resolve() / "private"])
    report_path = ws.reports / "scan.json"
    code, out, _ = run_main("scan", ws.target, "--baseline", ws.baseline, "--report", report_path,
                            "--format", "json")
    assert code == 4
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report == json.loads(out)
    assert (report["status"], report["result"], report["coverage"]["complete"]) == \
        ("incomplete", "changes_detected", False)
    assert events(report) == [("MODIFIED", "config/settings.json"), ("UNVERIFIED", "private/keys.conf")]


def test_interrupted_scan_is_exit_130_without_report(based, run_main, monkeypatch):
    from filesift import scanner

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(scanner, "build_inventory", interrupted)
    report_path = based.reports / "scan.json"
    code, out, err = run_main("scan", based.target, "--baseline", based.baseline, "--report", report_path)
    assert code == 130
    assert "Interrupted" in err
    assert out == ""
    assert not report_path.exists()


def test_internal_crash_in_comparator_is_exit_4_not_1(based, run_main, monkeypatch):
    from filesift import comparator

    def crash(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(comparator, "compare", crash)
    (based.target / "old_script.py").unlink()                 # a real change exists, yet the crash must not look like 1
    code, out, err = run_main("scan", based.target, "--baseline", based.baseline)
    assert code == 4
    assert "internal error" in err and "boom" in err
    assert out == ""


def test_root_unreadable_is_fatal_exit_4(based, run_main, monkeypatch):
    patch_scandir(monkeypatch, fail_dirs=[based.target.resolve()])
    report_path = based.reports / "scan.json"
    code, out, err = run_main("scan", based.target, "--baseline", based.baseline, "--report", report_path,
                              "--format", "json")
    assert code == 4
    assert out == ""                                          # E9
    assert "cannot list target directory" in err
    assert not report_path.exists()


# ---------------------------------------------------------------- configuration and baseline errors

def test_missing_baseline_is_exit_3(ws):
    proc = run_cli("scan", ws.target, "--baseline", ws.baseline)
    assert proc.returncode == 3
    assert "init-baseline" in proc.stderr
    assert not ws.baseline.exists()                           # never auto-created


def test_missing_target_is_exit_2(ws):
    assert run_cli("init-baseline", ws.tmp / "nope", "--baseline", ws.baseline).returncode == 2


def test_target_is_a_file_is_exit_2(ws):
    assert run_cli("init-baseline", ws.target / "old_script.py", "--baseline", ws.baseline).returncode == 2


def test_missing_output_directory_is_exit_2(ws):
    proc = run_cli("init-baseline", ws.target, "--baseline", ws.tmp / "nope" / "b.json")
    assert proc.returncode == 2
    assert "output directory does not exist" in proc.stderr


def test_report_equal_to_baseline_is_exit_2(based):
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", based.baseline)
    assert proc.returncode == 2
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", str(based.baseline) + ".bak")
    assert proc.returncode == 2


def test_root_mismatch(based):
    moved = based.tmp / "moved"
    shutil.copytree(based.target, moved)
    proc = run_cli("scan", moved, "--baseline", based.baseline)
    assert proc.returncode == 2
    assert "--allow-root-mismatch" in proc.stderr
    proc, report = scan_json(moved, based.baseline, "--allow-root-mismatch")
    assert proc.returncode == 0
    assert report["baseline"]["root_match"] is False
    assert "mismatch" in proc.stderr


def test_baseline_inside_target_warns_and_is_excluded(ws):
    inside = ws.target / "baseline.json"
    proc = run_cli("init-baseline", ws.target, "--baseline", inside)
    assert proc.returncode == 0, proc.stderr
    assert "inside TARGET" in proc.stderr
    assert "baseline.json" not in json.loads(inside.read_text(encoding="utf-8"))["entries"]
    proc, report = scan_json(ws.target, inside)
    assert proc.returncode == 0
    assert report["coverage"]["artifacts_excluded"] == 1


def test_decoy_named_like_the_baseline_is_inventoried(ws):
    (ws.target / "scripts" / "baseline.json").write_bytes(b"payload")
    inside = ws.target / "baseline.json"
    assert run_cli("init-baseline", ws.target, "--baseline", inside).returncode == 0
    assert "scripts/baseline.json" in json.loads(inside.read_text(encoding="utf-8"))["entries"]
    (ws.target / "scripts" / "baseline.json").write_bytes(b"payload v2")
    proc, report = scan_json(ws.target, inside)
    assert proc.returncode == 1
    assert events(report) == [("MODIFIED", "scripts/baseline.json")]


def test_stored_exclusions_applied_and_reported(ws):
    (ws.target / "app.log").write_bytes(b"1")
    assert _init(ws, "--exclude", "*.log").returncode == 0
    (ws.target / "app.log").write_bytes(b"2")
    (ws.target / "new.log").write_bytes(b"3")
    proc, report = scan_json(ws.target, ws.baseline)
    assert proc.returncode == 0
    assert report["coverage"]["exclusions_applied"] == ["*.log"]
    assert report["coverage"]["excluded_by_pattern"] == 2


def test_invalid_exclude_pattern_is_exit_2(ws):
    assert _init(ws, "--exclude", "../escape").returncode == 2


# ---------------------------------------------------------------- errata

@needs_symlink
def test_e2_symlink_to_baseline_is_inventoried_as_symlink(ws):
    inside = ws.target / "baseline.json"
    os.symlink("baseline.json", ws.target / "link")
    assert run_cli("init-baseline", ws.target, "--baseline", inside).returncode == 0
    entries = json.loads(inside.read_text(encoding="utf-8"))["entries"]
    assert entries["link"] == {"type": "symlink", "target": "baseline.json"}
    assert "baseline.json" not in entries


def test_e4_gap_recorded_with_allow_incomplete_stays_unverified(ws, run_main, monkeypatch):
    build_tree(ws.target / "locked", {"inner.txt": "x"})
    with monkeypatch.context() as m:
        patch_scandir(m, fail_dirs=[ws.target.resolve() / "locked"])
        code, out, err = run_main("init-baseline", ws.target, "--baseline", ws.baseline)
        assert code == 4                                      # refused by default
        assert "baseline NOT written" in err and "locked" in err
        assert not ws.baseline.exists()
        code, out, err = run_main("init-baseline", ws.target, "--baseline", ws.baseline, "--allow-incomplete")
        assert code == 0
        assert "PARTIAL" in out
    doc = json.loads(ws.baseline.read_text(encoding="utf-8"))
    assert doc["coverage"] == {"complete": False, "unverified": ["locked"]}
    (ws.target / "locked" / "added.txt").write_bytes(b"new")
    proc, report = scan_json(ws.target, ws.baseline)          # now listable, but the baseline has nothing to compare
    assert proc.returncode == 4
    assert events(report) == [("UNVERIFIED", "locked/added.txt"), ("UNVERIFIED", "locked/inner.txt")]
    assert all(f["details"]["reason"] == "unverified in baseline" for f in report["findings"])


@linux_only
def test_e5_undecodable_name_baseline_is_never_complete(ws):
    fd = os.open(os.fsencode(str(ws.target)) + b"/bad\xff", os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    proc = _init(ws)
    assert proc.returncode == 4
    assert "not valid UTF-8" in proc.stderr
    assert not ws.baseline.exists()
    assert _init(ws, "--allow-incomplete").returncode == 0
    doc = json.loads(ws.baseline.read_text(encoding="utf-8"))
    assert doc["coverage"] == {"complete": False, "unverified": []}
    proc, report = scan_json(ws.target, ws.baseline)
    assert proc.returncode == 4
    assert report["status"] == "incomplete"
    assert [e["kind"] for e in report["errors"]] == ["UNDECODABLE_NAME"]


@posix_only
def test_e8_hostile_filenames_render_literally(based):
    for name in ("[red]alert.txt", ":smile:.txt", "esc\x1b[31m.txt"):
        (based.target / name).write_bytes(b"x")
    proc = run_cli("scan", based.target, "--baseline", based.baseline)
    assert proc.returncode == 1
    assert "[red]alert.txt" in proc.stdout
    assert ":smile:.txt" in proc.stdout
    assert "😄" not in proc.stdout
    assert "\x1b" not in proc.stdout
    assert "esc\\x1b[31m.txt" in proc.stdout
    proc, report = scan_json(based.target, based.baseline)
    assert ("ADDED", "esc\x1b[31m.txt") in events(report)     # preserved exactly in JSON


def test_e8_render_does_not_interpret_markup_or_emoji(capsys):
    report = {
        "target": {"label": "[bold]t"},
        "baseline": {"created_at": "2026-10-25T12:00:00Z", "authenticated": False, "root_match": True},
        "coverage": {"complete": True, "entries_inventoried": 2, "excluded_by_pattern": 0, "artifacts_excluded": 0,
                     "exclusions_applied": [], "unverified_prefixes": []},
        "findings": [
            {"event": "ADDED", "category": "integrity", "subject": ":smile:", "details": {"type": "file"}},
            {"event": "ADDED", "category": "integrity", "subject": "[red]x", "details": {"type": "file"}},
        ],
        "status": "changes_detected", "result": "changes_detected", "errors": [],
        "summary": {"added": 2, "modified": 0, "deleted": 0, "type_changed": 0, "permissions_changed": 0,
                    "unreadable": 0, "unstable": 0, "unverified": 0, "errors": 0},
    }
    render_scan(report, baseline_display="b.json", report_display=None, baseline_complete=True)
    out = capsys.readouterr().out
    assert ":smile:" in out and "😄" not in out
    assert "[red]x" in out
    assert "[bold]t" in out


def test_safe_display_escapes_control_characters():
    assert safe_display("a\x1b[31mb") == "a\\x1b[31mb"         # "[31m" cannot open a Rich tag
    assert safe_display("[red]x") == "\\[red]x"
    assert safe_display("tab\there\n") == "tab\\x09here\\x0a"
    assert safe_display("bidi\u202e") == "bidi\\u202e"
    assert safe_display("[link=http://x]y") == "\\[link=http://x]y"


def test_e9_config_error_in_json_mode_prints_nothing_on_stdout(based):
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--format", "json",
                   "--report", based.target / "r.json")
    assert proc.returncode == 2
    assert proc.stdout == ""


def test_e11_exclude_equal_set_in_any_order_is_accepted(ws):
    assert _init(ws, "--exclude", "*.log", "--exclude", "cache/*").returncode == 0
    same = run_cli("scan", ws.target, "--baseline", ws.baseline,
                   "--exclude", "cache/*", "--exclude", "*.log", "--exclude", "*.log")
    assert same.returncode == 0, same.stderr
    subset = run_cli("scan", ws.target, "--baseline", ws.baseline, "--exclude", "*.log")
    assert subset.returncode == 2
    absent = run_cli("scan", ws.target, "--baseline", ws.baseline)
    assert absent.returncode == 0


def test_e13_report_overwrite_guard(based):
    report_path = based.reports / "scan.json"
    report_path.write_bytes(b"do not clobber")
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", report_path)
    assert proc.returncode == 2
    assert report_path.read_bytes() == b"do not clobber"
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", report_path, "--force-report")
    assert proc.returncode == 0
    first = json.loads(report_path.read_text(encoding="utf-8"))
    proc = run_cli("scan", based.target, "--baseline", based.baseline, "--report", report_path)
    assert proc.returncode == 0                               # an existing FileSift report is overwritten
    assert json.loads(report_path.read_text(encoding="utf-8"))["envelope"]["run_id"] != first["envelope"]["run_id"]


def test_e14_hmac_matrix_via_cli(ws):
    keyed = {"FILESIFT_KEY": KEY}
    assert _init(ws, env=keyed).returncode == 0
    assert json.loads(ws.baseline.read_text(encoding="utf-8"))["integrity"]["algorithm"] == "hmac-sha256"

    proc = run_cli("scan", ws.target, "--baseline", ws.baseline, "--format", "json", env=keyed)
    assert proc.returncode == 0                               # MAC + key: verified
    assert json.loads(proc.stdout)["baseline"]["authenticated"] is True
    verify = run_cli("verify-baseline", "--baseline", ws.baseline, env=keyed)
    assert verify.returncode == 0 and "HMAC verified" in verify.stdout

    assert run_cli("scan", ws.target, "--baseline", ws.baseline).returncode == 3          # MAC, no key
    assert run_cli("verify-baseline", "--baseline", ws.baseline).returncode == 3
    assert run_cli("scan", ws.target, "--baseline", ws.baseline,
                   env={"FILESIFT_KEY": "x" * 32}).returncode == 3                        # wrong key

    doc = json.loads(ws.baseline.read_text(encoding="utf-8"))
    doc["entries"]["old_script.py"]["sha256"] = "0" * 64
    ws.baseline.write_text(json.dumps(doc), encoding="utf-8")
    assert run_cli("scan", ws.target, "--baseline", ws.baseline, env=keyed).returncode == 3  # tampered

    doc["integrity"] = None
    ws.baseline.write_text(json.dumps(doc), encoding="utf-8")
    proc = run_cli("scan", ws.target, "--baseline", ws.baseline, env=keyed)               # no MAC, key: downgrade
    assert proc.returncode == 3
    assert "downgrade" in proc.stderr


def test_e14_unkeyed_baseline_without_key_is_unauthenticated(based):
    proc, report = scan_json(based.target, based.baseline)
    assert proc.returncode == 0
    assert report["baseline"]["authenticated"] is False


@pytest.mark.parametrize("command", ["init-baseline", "scan", "verify-baseline"])
def test_e14_short_key_is_exit_2_for_every_command(based, command):
    args = ["--baseline", based.baseline] if command == "verify-baseline" else [based.target, "--baseline",
                                                                                 based.baseline]
    proc = run_cli(command, *args, env={"FILESIFT_KEY": "too-short"})
    assert proc.returncode == 2
    assert "at least 32 bytes" in proc.stderr


@needs_fifo
def test_fifo_does_not_hang_the_scan(ws):
    os.mkfifo(ws.target / "pipe")
    proc = _init(ws)                                          # subprocess timeout (60 s) proves no hang
    assert proc.returncode == 0, proc.stderr
    assert json.loads(ws.baseline.read_text(encoding="utf-8"))["entries"]["pipe"] == {"type": "special",
                                                                                      "kind": "fifo"}
    proc, report = scan_json(ws.target, ws.baseline)
    assert proc.returncode == 0


def test_incomplete_text_output_says_not_clean(based, run_main, monkeypatch):
    patch_scandir(monkeypatch, fail_dirs=[based.target.resolve() / "scripts"])
    code, out, _ = run_main("scan", based.target, "--baseline", based.baseline)
    assert code == 4
    assert "PARTIAL" in out
    assert "INCOMPLETE" in out
    assert "NOT a clean" in " ".join(out.split())             # robust to terminal-width wrapping
    assert "CLEAN ·" not in out


# ---------------------------------------------------------------- invariant 10

@pytest.mark.parametrize("module", CORE_MODULES)
def test_core_modules_import_neither_typer_nor_rich(module):
    import filesift
    source = (Path(filesift.__file__).parent / f"{module}.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        assert not any(n.split(".")[0] in ("typer", "rich", "click") for n in names), (module, names)
