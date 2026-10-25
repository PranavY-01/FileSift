"""Typer CLI: option parsing, orchestration, and exit-code mapping (Spec §7.3, §7.4, §9, E1, E9, E10, E11)."""

import functools
import hashlib
import os
import sys
import uuid
from enum import Enum
from pathlib import Path

import typer

from filesift import __version__, baseline as baseline_io, comparator, exclusions, integrity, outputs, reporter, \
    scanner
from filesift.errors import BaselineExistsError, ConfigError, FileSiftError
from filesift.models import utc_now
from filesift.paths import backup_path, root_fingerprint
from filesift.render import (err_console, out_console, render_gap_refusal, render_init, render_scan, render_verify,
                             safe_display, warn)

app = typer.Typer(pretty_exceptions_enable=False, add_completion=False, no_args_is_help=True,
                  help="FileSift: file integrity monitoring that never reports a partial scan as clean.")


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


def guarded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            code = fn(*args, **kwargs)                 # commands return an int exit code
        except typer.Exit:
            raise
        except KeyboardInterrupt:
            err_console.print("[fs.warn]▲ Interrupted.[/fs.warn]")
            code = 130
        except FileSiftError as exc:
            err_console.print(f"[fs.bad]✗ error:[/fs.bad] {safe_display(str(exc))}")
            code = exc.exit_code
        except Exception as exc:                       # never let a crash look like "changes detected"
            err_console.print(f"[fs.bad]✗ internal error:[/fs.bad] {safe_display(repr(exc))}")
            code = 4
        raise typer.Exit(code)
    return wrapper


def _version_callback(value: bool) -> None:
    if value:
        out_console.print(f"[fs.accent]filesift[/fs.accent] {__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True,
                                 help="Show the version and exit."),
) -> None:
    """FileSift: file integrity monitoring that never reports a partial scan as clean."""


def _artifact_keys(*paths: Path) -> set[str]:
    return {exclusions.artifact_key(p) for p in paths}


@app.command("init-baseline")
@guarded
def init_baseline(
    target: Path = typer.Argument(..., help="Directory to baseline."),
    baseline: Path = typer.Option(..., "--baseline", help="Where to write the baseline (store it outside TARGET)."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="fnmatch pattern on the relative POSIX path; "
                                             "repeatable; stored in the baseline."),
    force: bool = typer.Option(False, "--force", help="Atomically replace an existing baseline (kept as .bak)."),
    allow_incomplete: bool = typer.Option(False, "--allow-incomplete",
                                          help="Write despite coverage gaps; gaps are recorded as unverified."),
) -> int:
    """Record a trusted baseline of TARGET."""
    key = integrity.load_key()
    root_r = outputs.check_target(target)
    bpath = outputs.check_baseline_path(baseline, root_r, creating=True)
    if not force and os.path.lexists(bpath):
        raise BaselineExistsError(f"baseline already exists: {baseline} (use --force to replace it; "
                                  "the previous file is kept as .bak)")
    if outputs.inside_target(bpath, root_r):
        warn(f"baseline {baseline} is inside TARGET. It is excluded by its exact path, but anyone who can "
             "modify the target may also modify the baseline. Store it outside the monitored directory.")
    patterns = exclusions.validate_patterns(exclude or [])
    policy = exclusions.ExclusionPolicy(root_r, patterns, _artifact_keys(bpath, backup_path(bpath)))

    inv = scanner.build_inventory(root_r, policy)
    if not inv.complete:
        undecodable = [e.subject for e in inv.errors if e.kind == "UNDECODABLE_NAME"]
        if not allow_incomplete:
            render_gap_refusal(unreadable=inv.unreadable, unstable=inv.unstable, unlisted=inv.unverified_prefixes,
                               undecodable=undecodable)
            return 4
        warn(f"coverage gaps recorded in the baseline ({len(inv.gaps())} unverified path(s), "
             f"{len(undecodable)} undecodable name(s)); they will be reported as UNVERIFIED on every scan")

    doc = baseline_io.build_baseline_dict(root_r, inv, patterns, key)
    data = baseline_io.serialize_baseline(doc)
    baseline_io.write_baseline(bpath, data, force=force)
    render_init(label=root_r.name, baseline_display=str(baseline), entries=len(inv.entries),
                excluded=inv.excluded_by_pattern + inv.artifacts_excluded, gaps=inv.gaps(),
                undecodable=inv.undecodable, authenticated=key is not None,
                sha256=hashlib.sha256(data).hexdigest())
    return 0


@app.command("scan")
@guarded
def scan(
    target: Path = typer.Argument(..., help="Directory to compare against the baseline."),
    baseline: Path = typer.Option(..., "--baseline", help="Baseline file created by init-baseline."),
    report: Path | None = typer.Option(None, "--report", help="Write the JSON report to this path."),
    output_format: OutputFormat = typer.Option(OutputFormat.text, "--format",
                                               help="text: terminal summary; json: report on stdout."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Optional; must equal the stored set exactly."),
    allow_root_mismatch: bool = typer.Option(False, "--allow-root-mismatch",
                                             help="Compare against a moved or renamed directory."),
    force_report: bool = typer.Option(False, "--force-report",
                                      help="Overwrite an existing non-FileSift file at --report."),
) -> int:
    """Compare TARGET against a baseline and report changes and coverage."""
    key = integrity.load_key()
    root_r = outputs.check_target(target)
    bpath = outputs.check_baseline_path(baseline, root_r, creating=False)
    doc, raw, authenticated = baseline_io.load_baseline(bpath, key)

    root_match = root_fingerprint(root_r) == doc.root.fingerprint
    if not root_match:
        if not allow_root_mismatch:
            raise ConfigError(f"baseline was recorded for a different directory than {target} "
                              "(pass --allow-root-mismatch to compare a moved or renamed directory)")
        warn("root fingerprint mismatch: comparing against a different directory than the baseline recorded")

    stored = tuple(doc.policy.exclusions)
    if exclude:
        given = exclusions.validate_patterns(exclude)
        if given != stored:
            raise ConfigError(f"--exclude {list(given)} does not match the exclusions stored in the baseline "
                              f"{list(stored)}; omit --exclude to use the stored set")

    rpath = None
    if report is not None:
        rpath = outputs.check_report_path(report, root_r, bpath, stored, force_report=force_report)
    artifacts = [bpath, backup_path(bpath)] + ([rpath] if rpath is not None else [])
    policy = exclusions.ExclusionPolicy(root_r, stored, _artifact_keys(*artifacts))

    started_at = utc_now()
    inv = scanner.build_inventory(root_r, policy)
    findings = comparator.compare(doc, inv)
    outcome = comparator.derive(findings, inv, doc)
    result = reporter.build_report(
        run_id=str(uuid.uuid4()), started_at=started_at, completed_at=utc_now(), outcome=outcome,
        root_r=root_r, baseline=doc, baseline_sha256=hashlib.sha256(raw).hexdigest(),
        authenticated=authenticated, root_match=root_match, inv=inv, findings=findings)

    if rpath is not None:
        reporter.write_report(rpath, result, force_report=force_report)
    if output_format is OutputFormat.json:
        sys.stdout.write(reporter.dumps_report(result))
        sys.stdout.flush()
    else:
        render_scan(result, baseline_display=str(baseline),
                    report_display=str(report) if report is not None else None,
                    baseline_complete=doc.coverage.complete)
    return outcome.exit_code


@app.command("verify-baseline")
@guarded
def verify_baseline(
    baseline: Path = typer.Option(..., "--baseline", help="Baseline file to validate."),
) -> int:
    """Validate a baseline's structure (and MAC, if keyed) and print its digest."""
    key = integrity.load_key()
    bpath = outputs.check_baseline_path(baseline, None, creating=False)
    doc, raw, authenticated = baseline_io.load_baseline(bpath, key)
    render_verify(baseline_display=str(baseline), label=doc.root.label, created_at=doc.created_at,
                  entries=len(doc.entries), exclusions=list(doc.policy.exclusions),
                  unverified=len(doc.coverage.unverified), complete=doc.coverage.complete,
                  authenticated=authenticated, sha256=hashlib.sha256(raw).hexdigest())
    return 0


def _utf8_streams() -> None:
    # Filenames are arbitrary Unicode; never let a legacy console code page turn output into a crash.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


def main() -> None:                                   # console-script entry point
    _utf8_streams()
    app(prog_name="filesift")
