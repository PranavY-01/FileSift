# FileSift v1.0.0 — Build Notes

Built from `FileSift_MasterBuildDoc.md` (the Spec) plus errata E1–E17 from the build instructions. Precedence: errata > Spec.

## Tested environments

| OS | Python | User | `pytest -q` |
|---|---|---|---|
| Ubuntu 26.04 LTS on WSL2 (kernel 6.6.87.2-microsoft-standard-WSL2) | 3.14.4 | uid 1000 (non-root) | 300 passed, 1 skipped |
| Windows 11 Home 10.0.26300 | 3.12.0 | regular user, no symlink privilege | 275 passed, 26 skipped |

Library versions installed: typer 0.27.3, rich 15.0.0, pydantic 2.14.1 (pydantic-core 2.50.1), pytest 9.1.1.

`requires-python = ">=3.11"` follows the Spec, but no 3.11 interpreter was available, so 3.11 itself is **untested**.

## Decisions where the Spec was silent

1. **Symlink target not valid UTF-8, or `readlink` fails:** recorded as `UNREADABLE` (a coverage gap). Such a target cannot be serialized, and treating it as unreadable keeps coverage honest.
2. **`DirEntry.stat` fails for a pattern-excluded name:** counted as excluded, not unreadable, because the user excluded it explicitly.
3. **Canonical lists in the baseline:** `policy.exclusions` and `coverage.unverified` must be sorted and duplicate-free. Each item must pass `validate_rel_path`. This matches the Spec's "reject, don't normalize" rule for paths.
4. **`validate_rel_path` also rejects strings that are not encodable as UTF-8** (lone surrogates from JSON `\udcff` escapes). Such a path could never match an inventory entry.
5. **Strict literals:** Pydantic's strict mode still accepts `true` for `Literal[1]` and `0` for `Literal[False]` (verified). `schema_version` is therefore a strict `int` that must equal 1, and `follow_symlinks` is a strict `bool` that must be `false`.
6. **Timestamp/digest patterns use `[0-9]`, not `\d`.** `\d` also matches non-ASCII digits. Every valid E3 timestamp still matches.
7. **Report-overwrite guard (E13) runs twice:** once while validating paths, before the scan, so the run fails fast with exit 2; and again immediately before the atomic write, because the scan takes time.
8. **Non-regular files at output paths are always refused,** even with `--force` / `--force-report`. This covers a symlink, directory, FIFO or device at the baseline, `<baseline>.bak` or report path. The guard reads an existing report with `O_NOFOLLOW | O_NONBLOCK` and an `fstat` regular-file check, so a planted FIFO cannot hang it.
9. **`.bak` on `--force`** is written atomically (temp file + `fsync` + `os.replace`) instead of `shutil.copy2`. `copy2` would write through a planted `.bak` symlink.
10. **Reading a baseline through a symlink** (`scan`, `verify-baseline`) is refused with exit 2. This applies the §9.4 "not a symlink" row to the baseline in every command.
11. **`init-baseline` without `--force`** refuses an existing baseline before scanning (exit 2). `open(..., "xb")` remains the authoritative guard.
12. **Unreadable TARGET:** `check_target` checks only that the target exists and is a directory, which is exit 2. A root that cannot be listed is the fatal exit 4 from the walker, per Spec §6.8, §11.1 #16 and E9. Spec §7.3 step 1 mentions "readable → exit 2", but the more specific rules take precedence.
13. **Report inside TARGET** is allowed only when the report's relative path, or one of its ancestors, matches a stored exclusion pattern. Such a report is also excluded as an artifact.
14. **`check_baseline_path(path, root_r, *, creating)`:** `root_r` is used to reject a baseline path equal to the target itself, and is `None` for `verify-baseline`. Spec §7.3's "not inside an excluded-by-pattern path" check for the baseline was not implemented: the E5 contract signature carries no patterns, and the baseline is excluded by exact path anyway.
15. **Hash stat (E6):** `size_bytes`, `mode` and `mtime_ns` come from the post-hash `lstat` of the successful attempt. That `lstat` has been verified to match the pre-hash size, mtime and identity.
16. **Windows junctions** are recorded as symlinks via `DirEntry.is_junction()` (3.12+), or `st_reparse_tag == IO_REPARSE_TAG_MOUNT_POINT` (which also works on 3.11).
17. **Undecodable names:** the `errors[]` subject is `repr(rel)`, which is ASCII-escaped and JSON-safe. `inv.undecodable` counts them, and E5 then forces `coverage.complete = false`.
18. **Ordering:** findings are sorted by `(subject, event)` and `errors[]` by `(subject, kind)`. The report keeps the Spec's field order (not `sort_keys`). The baseline uses `sort_keys=True, ensure_ascii=False, indent=2` plus a trailing newline.
19. **`FILESIFT_KEY` that is not valid UTF-8** (possible on POSIX) is a config error, exit 2.
20. **Console encoding:** `main()` reconfigures stdout and stderr to UTF-8 with `errors="backslashreplace"`. Without this, a legacy Windows code page turned a non-Latin filename or the `→` glyph into a `UnicodeEncodeError`, which is exit 4. `--format json` writes the report with `sys.stdout.write`, not Rich, so no markup is ever interpreted.
21. **`--version`** prints `filesift 1.0.0`.
22. **Module imports:** `atomic_write` lives in `outputs.py` and is shared by `baseline.py` and `reporter.py`. `models.py`, `reporter.py` and `outputs.py` import `paths.py` (stdlib-only). This goes slightly beyond the Spec §7.2 "may import" table, but no core module imports `typer`, `rich` or `click`, and invariant 10 is enforced by a test.
23. **Opening files:** only `hasher.py` opens monitored entries. `baseline.py` opens the baseline file and `outputs.py` opens an existing report and temp files. These are tool artifacts, not monitored entries, even when the baseline lives inside TARGET.
24. **`init-baseline` with gaps and no `--allow-incomplete`** prints every gap to stderr and exits 4 without writing. With `--allow-incomplete` it writes the baseline, warns on stderr, and exits 0.
25. **Terminal UI (post-build redesign, at the owner's request):** `render.py` uses a Rich `Theme`, a
    three-row block-letter "FILESIFT" wordmark with a cyan-to-violet gradient (hand-drawn with Unicode block
    characters, no new dependency; terminals under 72 columns get a compact one-line header), a key/value grid,
    colored event badges in a rounded findings table, per-event summary chips, and a heavy-bordered verdict
    panel with a solid status badge. Constraints kept: every untrusted string still
    passes through `safe_display()`; both consoles keep `emoji=False, highlight=False` (E8), so styling uses
    literal Unicode glyphs (✓ ✗ ● ○ ▲ ◆), never `:emoji:` codes; `--format json` output is unchanged; error
    lines still start with `error:` / `internal error:`. No spinner or progress bar was added (out of scope).

## Deviations from the Spec, the errata or the build instructions

- **No git operations.** The build instructions (§7) asked for a commit per phase and an annotated `v1.0.0` tag. The repository owner explicitly forbade any git command, so none was run. The intended phase commit messages are listed below for the owner to use.
- **No demo recording.** Spec §16 and §17.4 ask for an asciinema/GIF recording. None was produced; the real terminal output is reproduced in the README instead.
- **Tests were run after the engine was complete, not strictly after each phase.** Every phase's tests exist and pass, but the per-phase "run, fix, commit" cadence was not followed literally.
- **Python 3.11 is untested** (see above).

Intended commit messages (Spec §13), in order:

1. `chore: initialize FileSift project`
2. `feat: add stability-checked hashing and inventory walker`
3. `feat: add baseline validation, exclusions, and comparator`
4. `feat: add CLI, JSON reporting, and terminal summary`
5. `test: cover integrity monitoring workflows`
6. `docs: add architecture, usage, and security guide`

## Skipped tests and why

**Linux (1 skipped):**
- `test_outputs.py::test_report_collision_is_case_insensitive_on_windows`: Windows-only behaviour.

**Windows (26 skipped):** these are all platform skips. Every permission-based test has a monkeypatched twin that runs on Windows.

| Reason | Count | Tests |
|---|---|---|
| Symlinks not permitted (no Developer Mode or admin) | 11 | symlink scanner/hasher/outputs/reporter tests, `test_file_replaced_by_symlink`, `test_symlink_retargeted`, `test_e2_…` |
| POSIX permissions as non-root (`chmod 000`) | 5 | real unreadable file/directory tests in hasher, scanner, CLI |
| POSIX filesystem semantics | 4 | `chmod +x` / setuid CLI tests, AF_UNIX socket, E8 hostile real filenames (`:` and control characters are invalid in Windows names) |
| `os.mkfifo` unavailable | 3 | FIFO scanner, hasher and CLI no-hang tests |
| Linux-only undecodable byte names | 2 | scanner and E5 CLI tests |
| Windows is always case-insensitive | 1 | `test_case_variants_allowed_on_case_sensitive_platform` |

No test is marked `xfail`, and no assertion was weakened to get a green run.
