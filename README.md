# FileSift

FileSift is a Python CLI file integrity monitor that detects file additions, modifications, deletions, type changes, and permission changes by comparing the filesystem against a SHA-256 baseline — and never reports a partial scan as clean.

Day 3 of the *7 Days – 7 Cybersecurity Projects* series.

## Why file integrity monitoring, and why honest coverage matters

Files change for legitimate reasons (updates, administration) and illegitimate ones (malware, tampering). A file integrity monitor (FIM) records a trusted baseline of a directory and later answers *"what changed, exactly?"*.

Naive FIM tools treat unreadable files as deleted, follow symlinks out of scope, or print "OK" after a crash. FileSift separates three statements that need different evidence:

| Statement | Evidence FileSift requires |
|---|---|
| "`config/settings.json` was modified" | Two stable SHA-256 digests that differ |
| "Nothing changed" | **Complete coverage**: every in-scope entry was listed, `lstat`ed, and hashed |
| "`private/` could not be verified" | A recorded failure, reported as `UNVERIFIED` / `UNREADABLE` / `UNSTABLE` |

> **A scan that cannot establish reliable coverage must never be presented as proof that no changes occurred.**

## Features

- Recursive inventory with a custom `os.scandir` walker; entries classified from `lstat` data only.
- Streaming SHA-256 with a stability protocol (`lstat` → `open(O_NOFOLLOW|O_NONBLOCK)` → `fstat` → hash → `lstat`, one retry, else `UNSTABLE`).
- Detects `ADDED`, `MODIFIED`, `DELETED`, `TYPE_CHANGED`, and `PERMISSIONS_CHANGED`.
- Symlinks are recorded by target string and never followed; FIFOs, sockets, and devices are recorded and never opened.
- **Listing-evidence rule:** `DELETED` is only claimed when the parent directory was listed successfully.
- Strict baseline validation (Pydantic v2 strict, unknown fields rejected, duplicate JSON keys rejected).
- Baseline is created with `O_EXCL`; `--force` replaces it atomically and keeps a `.bak`.
- Root fingerprint binds a baseline to its directory.
- Tool artifacts (baseline, `.bak`, report) are excluded by **exact path**, never by name. There are no default exclusions.
- User exclusion patterns are stored in the baseline and enforced at scan time.
- Optional HMAC-SHA256 baseline authentication with downgrade protection (`FILESIFT_KEY`).
- Rich terminal UI (gradient banner, colored event badges, verdict panels) with escaped filenames, plus a JSON report in the shared `7d7b-report` envelope.
- Documented exit codes; crashes exit `4`, never `1`.

## Architecture

```text
                                USER / CRON / CI
                                       │
                     ┌─────────────────▼──────────────────┐
                     │ cli.py (Typer) — exceptions → exit │
                     └─────────────────┬──────────────────┘
          ┌────────────────────────────┼─────────────────────────────┐
    init-baseline                    scan                     verify-baseline
          │                            │                             │
  ┌───────▼───────┐          ┌─────────▼────────┐         ┌──────────▼────────┐
  │ outputs.py    │          │ baseline.py      │◀────────│ integrity.py      │
  │ path safety   │          │ parse · validate │         │ HMAC sign/verify  │
  └───────┬───────┘          └─────────┬────────┘         └───────────────────┘
          └──────────────┬─────────────┘
          ┌──────────────▼───────────────────┐
          │ exclusions.py                    │
          │ artifacts (exact path) + stored  │
          │ user patterns                    │
          └──────────────┬───────────────────┘
          ┌──────────────▼───────────────────┐      ┌──────────────────────┐
          │ scanner.py (scandir walker)      │─────▶│ hasher.py            │
          │ classify · lstat · readlink      │      │ O_NOFOLLOW/NONBLOCK  │
          └──────────────┬───────────────────┘      │ stability protocol   │
                     Inventory                      └──────────────────────┘
            init ────────┴──────── scan
             ▼                       ▼
   baseline.py write          comparator.py
   (O_EXCL / atomic + .bak)   findings + derive(status, result, coverage)
                                     │
                       ┌─────────────┴─────────────┐
               reporter.py (JSON envelope)   render.py (Rich, escaped)
```

The core engine (`models`, `errors`, `paths`, `hasher`, `exclusions`, `scanner`, `baseline`, `integrity`, `comparator`, `reporter`, `outputs`) imports neither `typer` nor `rich`, so it can be used as a library.

## Installation

Requires Python 3.11 or newer (`hashlib.file_digest`).

```bash
git clone <this repository> FileSift && cd FileSift
python3 -m venv .venv && . .venv/bin/activate
pip install .                 # or: pip install -e ".[dev]" for development
filesift --version            # filesift 1.0.0
```

Runtime dependencies: `typer`, `rich`, `pydantic` (v2). FileSift makes no network calls and never modifies, deletes, or restores monitored files.

## Usage

> **New to FileSift?** The [User Guide](docs/USER_GUIDE.md) is a full manual: a five-minute quick start, every command and option, how to read results, automation with cron and CI, exclusions, baseline protection, and troubleshooting.

### `init-baseline`

```text
filesift init-baseline TARGET --baseline PATH
    [--exclude PATTERN]...      # repeatable; fnmatch on the relative POSIX path; stored in the baseline
    [--force]                   # atomic replace; previous kept as PATH.bak
    [--allow-incomplete]        # write despite coverage gaps; gaps recorded as unverified
```

`--baseline` is required. Any default location would be inside the monitored tree or somewhere the operator might not expect.

### `scan`

```text
filesift scan TARGET --baseline PATH
    [--report PATH]             # write the JSON report (must be outside TARGET, or pattern-excluded)
    [--format text|json]        # text (default): terminal summary; json: the report, and nothing else, on stdout
    [--exclude PATTERN]...      # optional; must equal the stored set exactly
    [--allow-root-mismatch]     # compare against a moved/renamed directory
    [--force-report]            # overwrite an existing non-FileSift file at --report
```

### `verify-baseline`

```text
filesift verify-baseline --baseline PATH
```

Validates the structure (and the MAC, if a key is set), then prints the baseline's SHA-256, creation time, entry count, exclusions, and authentication status.

## Example workflow

From [`examples/demo.sh`](examples/demo.sh):

```bash
mkdir -p demo-data/config demo-data/scripts state reports
printf '{"debug": false}' > demo-data/config/settings.json
printf 'print("backup")\n' > demo-data/scripts/backup.py
printf 'print("legacy")\n' > demo-data/old_script.py

filesift init-baseline demo-data --baseline state/baseline.json
filesift scan demo-data --baseline state/baseline.json            # exit 0

printf '{"debug": true}' > demo-data/config/settings.json
printf 'print("new")\n' > demo-data/scripts/new_task.py
rm demo-data/old_script.py
chmod +x demo-data/scripts/backup.py

filesift scan demo-data --baseline state/baseline.json --report reports/scan.json   # exit 1
```

## Sample terminal output

All output below was captured from real runs on Linux (Ubuntu 26.04 under WSL2, Python 3.14.4) with output
piped, so colors are not shown. In a real terminal the block-letter wordmark is a cyan-to-violet gradient,
events are colored badges, and the result is a solid badge in a heavy panel: green (clean), yellow (changes),
or red (incomplete). Terminals narrower than 72 columns get a compact one-line header instead of the wordmark.
Colors follow the `NO_COLOR` / `FORCE_COLOR` conventions.

**Baseline created** (exit `0`):

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  ██▀▀ ██ ██   ██▀▀ ██▀▀ ██ ██▀▀ ▀██▀    v1.0.0  ›  init-baseline             │
│  ██▀  ██ ██   ██▀▀ ▀▀██ ██ ██▀   ██     File integrity monitor               │
│  ▀▀   ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀ ▀▀    ▀▀     SHA-256 · honest coverage            │
│                                                                              │
│  Recording a trusted baseline of demo-data                                   │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
  Baseline    state/baseline.json · ✓ written
  Integrity   ○ unauthenticated
  Entries     3 recorded · 0 excluded
  Coverage    ✓ complete

╭─ SHA-256 ────────────────────────────────────────────────────────────────────╮
│ b5ada024401f0090e4bb6af098ed76e2ef36206cb9767f8aac045762a0ba9542             │
│ Record this digest somewhere the monitored host cannot write.                │
╰──────────────────────────────────────────────────────────────────────────────╯
```

**Clean scan** (exit `0`):

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  ██▀▀ ██ ██   ██▀▀ ██▀▀ ██ ██▀▀ ▀██▀    v1.0.0  ›  scan                      │
│  ██▀  ██ ██   ██▀▀ ▀▀██ ██ ██▀   ██     File integrity monitor               │
│  ▀▀   ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀ ▀▀    ▀▀     SHA-256 · honest coverage            │
│                                                                              │
│  Comparing demo-data against its baseline                                    │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
  Baseline    state/baseline.json · created 2026-10-25T17:09:50Z
  Integrity   ○ unauthenticated
  Coverage    ✓ complete · 3 entries inventoried · 0 excluded

┏━ Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃   ✓ CLEAN                                                                    ┃
┃                                                                              ┃
┃  No changes · every in-scope entry was inspected.                            ┃
┃                                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ exit 0 ━┛
```

**Changes detected** (exit `1`):

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  ██▀▀ ██ ██   ██▀▀ ██▀▀ ██ ██▀▀ ▀██▀    v1.0.0  ›  scan                      │
│  ██▀  ██ ██   ██▀▀ ▀▀██ ██ ██▀   ██     File integrity monitor               │
│  ▀▀   ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀ ▀▀    ▀▀     SHA-256 · honest coverage            │
│                                                                              │
│  Comparing demo-data against its baseline                                    │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
  Baseline    state/baseline.json · created 2026-10-25T17:09:50Z
  Integrity   ○ unauthenticated
  Coverage    ✓ complete · 3 entries inventoried · 0 excluded

  Findings
  ╭───────────────────────┬──────────────────────┬───────────────╮
  │ Event                 │ Path                 │ Detail        │
  ├───────────────────────┼──────────────────────┼───────────────┤
  │  MODIFIED             │ config/settings.json │ 16 → 15 bytes │
  │  DELETED              │ old_script.py        │ 16 bytes      │
  │  PERMISSIONS_CHANGED  │ scripts/backup.py    │ 0644 → 0755   │
  │  ADDED                │ scripts/new_task.py  │ 13 bytes      │
  ╰───────────────────────┴──────────────────────┴───────────────╯
   +1 added   ~1 modified   -1 deleted   ±1 permissions

┏━ Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃   ● CHANGES DETECTED                                                         ┃
┃                                                                              ┃
┃  4 findings · review them before re-baselining.                              ┃
┃                                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ exit 1 ━┛
  Report  → reports/scan.json
```

**Incomplete scan** (exit `4`). Here `private/` was made unlistable after the baseline was recorded and
`config/settings.json` was edited. The file under `private/` is `UNVERIFIED`, never `DELETED`:

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  ██▀▀ ██ ██   ██▀▀ ██▀▀ ██ ██▀▀ ▀██▀    v1.0.0  ›  scan                      │
│  ██▀  ██ ██   ██▀▀ ▀▀██ ██ ██▀   ██     File integrity monitor               │
│  ▀▀   ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀ ▀▀    ▀▀     SHA-256 · honest coverage            │
│                                                                              │
│  Comparing demo-data against its baseline                                    │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
  Baseline    state/baseline.json · created 2026-10-25T17:09:52Z
  Integrity   ○ unauthenticated
  Coverage    ✗ PARTIAL · 1 entry inventoried · 0 excluded

  Coverage gaps
    └ 1 directory could not be listed (private)
    └ 1 path unverified

  Findings
  ╭──────────────┬──────────────────────┬───────────────────────────────╮
  │ Event        │ Path                 │ Detail                        │
  ├──────────────┼──────────────────────┼───────────────────────────────┤
  │  MODIFIED    │ config/settings.json │ 16 → 15 bytes                 │
  │  UNVERIFIED  │ private/keys.conf    │ parent directory not listable │
  ╰──────────────┴──────────────────────┴───────────────────────────────╯
   ~1 modified   ?1 unverified

┏━ Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃   ✗ INCOMPLETE                                                               ┃
┃                                                                              ┃
┃  1 change found, and coverage gaps mean more may be undetected.              ┃
┃  This is NOT a clean result.                                                 ┃
┃                                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ exit 4 ━┛
```

**Baseline refused because of coverage gaps** (exit `4`, nothing written; printed on stderr):

```text
╭─ ✗ coverage gaps found — baseline NOT written ───────────────────────────────╮
│ directory not listable  locked                                               │
│                                                                              │
│ Fix access and re-run, or pass --allow-incomplete to record these paths as   │
│ unverified.                                                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
```

**Verifying a baseline** (exit `0`):

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  ██▀▀ ██ ██   ██▀▀ ██▀▀ ██ ██▀▀ ▀██▀    v1.0.0  ›  verify-baseline           │
│  ██▀  ██ ██   ██▀▀ ▀▀██ ██ ██▀   ██     File integrity monitor               │
│  ▀▀   ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀ ▀▀    ▀▀     SHA-256 · honest coverage            │
│                                                                              │
│  Validating state/baseline.json                                              │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
  Valid       ✓ structure OK
  Integrity   ○ unauthenticated (no MAC, no key)
  Root        demo-data
  Created     2026-10-25T17:09:50Z
  Entries     3
  Exclusions  none
  Coverage    ✓ complete

╭─ SHA-256 ────────────────────────────────────────────────────────────────────╮
│ b5ada024401f0090e4bb6af098ed76e2ef36206cb9767f8aac045762a0ba9542             │
│ Compare with the digest recorded when the baseline was created.              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Report format and shared envelope

`scan --report PATH` writes, and `scan --format json` prints, a JSON report in the shared `7d7b-report` envelope used across the series. A complete real report from the demo is in [`examples/sample-report.json`](examples/sample-report.json).

| Field | Meaning |
|---|---|
| `envelope` | `schema` (`7d7b-report`), `schema_version`, `tool`, `tool_version`, `run_id` (UUID4), `started_at`, `completed_at` (UTC, `Z`) |
| `status` | `clean`, `changes_detected`, or `incomplete` (derived from `result` + coverage) |
| `result` | `clean` or `changes_detected`: what was found in the inspected scope |
| `target` | `label` (directory name) and `root_fingerprint` |
| `baseline` | SHA-256 of the baseline file, `created_at`, `authenticated`, `root_match` |
| `coverage` | `complete`, `entries_inventoried`, `excluded_by_pattern`, `artifacts_excluded`, `exclusions_applied`, `unverified_prefixes` |
| `summary` | Counts per event, plus `errors` |
| `findings[]` | `{event, category, subject, details}`, sorted by `subject` |
| `errors[]` | `{kind, subject, message}`: `DIR_UNREADABLE`, `UNDECODABLE_NAME` |

| Event | Category | Meaning |
|---|---|---|
| `ADDED` | integrity | Present now, absent from the baseline |
| `MODIFIED` | integrity | File digest differs (with `mode_changed`), or symlink target differs |
| `DELETED` | integrity | In the baseline, and missing from a successful parent listing |
| `TYPE_CHANGED` | integrity | File ↔ symlink ↔ special, or a special file changed kind |
| `PERMISSIONS_CHANGED` | integrity | Same content, different permission bits |
| `UNREADABLE` | coverage | Listed (so it exists) but could not be `stat`ed or opened |
| `UNSTABLE` | coverage | Changed while being hashed, on both attempts |
| `UNVERIFIED` | coverage | Under a directory that could not be listed, or recorded as a gap in the baseline |

Fatal runs (exit `2`, `3`, a fatal `4` such as an unreadable root, or `130`) write no report and print nothing on stdout in `--format json` mode.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete scan, no changes (or successful `init-baseline` / `verify-baseline`) |
| `1` | Complete scan, changes detected |
| `2` | Invalid arguments or configuration: bad target, path collision, existing baseline without `--force`, exclusion mismatch, root mismatch, missing output directory, invalid key |
| `3` | Baseline missing, corrupt, invalid, incompatible, or failed authentication |
| `4` | Incomplete scan or operational failure: coverage gaps, root unreadable, write failure, any unexpected exception |
| `130` | Interrupted (Ctrl+C) |

**Precedence:** `2` and `3` end the run before scanning. After scanning, `4` (partial coverage) beats `1` (changes), which beats `0`. A run that found changes **and** had coverage gaps exits `4`, and the findings are still in the report. For automation: treat any non-zero exit as "needs attention".

## Baseline storage and protection

A baseline is only as trustworthy as the moment and place it was created. A baseline recorded after a compromise faithfully encodes the compromise as "expected".

- Store baselines in a dedicated directory **outside** the target, e.g. `/var/lib/filesift/` or `~/.filesift/`.
- POSIX permissions: directory `0700`, baseline `0400` or `0600`.
- Record the SHA-256 printed by `init-baseline` somewhere the monitored host cannot write, and compare it with `verify-baseline` output later.
- If the baseline must live inside the target, FileSift warns and excludes it by its exact path. Anyone who can modify the target can then also modify the baseline.

### Optional HMAC authentication

Set `FILESIFT_KEY` (at least 32 bytes after UTF-8 encoding) to sign baselines at `init-baseline` and require a valid MAC at `scan` and `verify-baseline`:

| Baseline has MAC | Key set | Behaviour |
|---|---|---|
| Yes | Yes | Verify; mismatch → exit `3` |
| Yes | No | Exit `3`: cannot verify an authenticated baseline |
| No | Yes | Exit `3`: possible stripped MAC (downgrade) |
| No | No | Proceed; report `authenticated: false` |

Real output after the `integrity` field was stripped from a signed baseline:

```text
$ filesift scan demo-data --baseline state/signed.json   # integrity field stripped
✗ error: baseline has no MAC but FILESIFT_KEY is set: refusing a possibly
stripped (downgraded) baseline
```

An environment variable is visible to other processes of the same user. The key only gives real protection when it is not stored on the monitored host (for example, injected as a CI secret).

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

Results for this release:

| Platform | Python | Result |
|---|---|---|
| Ubuntu 26.04 LTS (WSL2, kernel 6.6.87.2), non-root | 3.14.4 | 300 passed, 1 skipped (Windows-only case-insensitivity test) |
| Windows 11 Home 10.0.26300 | 3.12.0 | 275 passed, 26 skipped (POSIX permissions, FIFOs, sockets, undecodable names, symlinks without Developer Mode) |

Permission-based tests have a monkeypatched twin that injects `PermissionError`, so the behaviour is still tested when running as root (where `chmod 000` does not block reads) or on Windows.

## Security considerations and limitations

- A matching digest proves the bytes are identical to the baseline. It does not prove the file is benign.
- An attacker who can modify both the files and an unauthenticated baseline can hide changes.
- A scan is not an atomic snapshot. The stability protocol detects many concurrent changes, but not all of them.
- `mtime` is attacker-controllable and is never used as evidence (it is stored for information only).
- Directories are not stored as entries: an empty directory being added or removed is not detected.
- Ownership (uid/gid), extended attributes, ACLs, and alternate data streams are not tracked.
- Baselines are not portable across operating systems (Unicode normalization, case sensitivity, permission semantics).
- **Windows:** `mode` reflects little more than the read-only attribute, so permission tracking is meaningful on POSIX only. `O_NOFOLLOW` does not exist, so a file swapped for a symlink between listing and open can be followed in that narrow race. Junctions are recorded as symlinks.
- Filenames that are not valid UTF-8 cannot be stored. They are reported as `UNDECODABLE_NAME` errors and make coverage partial.
- A `clean` result means no changes were detected within the fully inspected scope. It does not mean the system is secure, and FileSift does not judge whether a change is malicious.

## Roadmap

- **V1.1:** `accept` command for reviewed findings; opt-in fast mode; timestomp signal; progress indicator; ownership tracking.
- **V1.2:** real-time monitoring, scheduled scans, notifications, baseline history.
- **V2:** asymmetric baseline signatures (Ed25519), centralized report collection, signed releases.

## License

MIT. See [LICENSE](LICENSE).
