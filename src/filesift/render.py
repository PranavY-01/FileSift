"""Rich terminal output. Every untrusted string goes through ``safe_display`` (Spec §10.5, E8).

Styling uses literal Unicode glyphs, never ``:emoji:`` codes: both consoles run with ``emoji=False`` and
``highlight=False`` so that filenames can never be reinterpreted.
"""

from collections.abc import Iterable
from typing import Any

from rich import box
from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from filesift import __version__

THEME = Theme({
    "fs.accent": "bold #a78bfa",
    "fs.border": "#7c6ff0",
    "fs.label": "#8b90a7",
    "fs.dim": "#6b7088",
    "fs.path": "#7dd3fc",
    "fs.digest": "bold",                 # terminal foreground: readable on light and dark themes
    "fs.ok": "bold #4ade80",
    "fs.warn": "bold #facc15",
    "fs.bad": "bold #f87171",
})

out_console = Console(highlight=False, emoji=False, theme=THEME)
err_console = Console(stderr=True, highlight=False, emoji=False, theme=THEME)

MAX_WIDTH = 88
BANNER_MIN_WIDTH = 72                    # below this the block-letter banner would wrap; use the compact header
SEP = " [fs.dim]·[/fs.dim] "

# Block-letter wordmark, three rows tall, two-column stems.
_LOGO = (
    "██▀▀ ██ ██   ██▀▀ ██▀▀ ██ ██▀▀ ▀██▀",
    "██▀  ██ ██   ██▀▀ ▀▀██ ██ ██▀   ██ ",
    "▀▀   ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀ ▀▀    ▀▀ ",
)
_BRAND_STOPS = ("#22d3ee", "#818cf8", "#c084fc")      # cyan → indigo → violet

_VERDICT = {
    "clean": (" ✓ CLEAN ", "bold #052e16 on #4ade80", "#4ade80"),
    "changes_detected": (" ● CHANGES DETECTED ", "bold #2a1f00 on #facc15", "#facc15"),
    "incomplete": (" ✗ INCOMPLETE ", "bold #ffffff on #dc2626", "#f87171"),
}

_BADGE = {
    "ADDED": "bold #052e16 on #4ade80",
    "MODIFIED": "bold #2a1f00 on #facc15",
    "DELETED": "bold #ffffff on #ef4444",
    "TYPE_CHANGED": "bold #ffffff on #a855f7",
    "PERMISSIONS_CHANGED": "bold #2a1300 on #fb923c",
    "UNREADABLE": "bold #fecaca on #7f1d1d",
    "UNSTABLE": "bold #fecaca on #7f1d1d",
    "UNVERIFIED": "bold #fecaca on #7f1d1d",
}

# (summary key, sign, colour, label) for the chips under the findings table
_CHIPS = (
    ("added", "+", "#4ade80", "added"),
    ("modified", "~", "#facc15", "modified"),
    ("deleted", "-", "#ef4444", "deleted"),
    ("type_changed", "*", "#c084fc", "type changed"),
    ("permissions_changed", "±", "#fb923c", "permissions"),
    ("unreadable", "!", "#f87171", "unreadable"),
    ("unstable", "!", "#f87171", "unstable"),
    ("unverified", "?", "#f87171", "unverified"),
)


def safe_display(s: str) -> str:
    out = []
    for ch in s:
        if ch.isprintable():
            out.append(ch)
        else:
            cp = ord(ch)
            out.append(f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}")
    return escape("".join(out))


def warn(message: str) -> None:
    err_console.print(f"[fs.warn]▲ warning:[/fs.warn] {safe_display(message)}")


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _joined(items: Iterable[str], limit: int = 5) -> str:
    items = list(items)
    shown = ", ".join(safe_display(i) for i in items[:limit])
    return shown + (f", … (+{len(items) - limit})" if len(items) > limit else "")


def _path(s: str) -> str:
    return f"[fs.path]{safe_display(s)}[/fs.path]"


def _width(c: Console) -> int:
    return min(c.width, MAX_WIDTH)


# ---------------------------------------------------------------- building blocks

def _blend(t: float, stops: tuple[str, ...] = _BRAND_STOPS) -> str:
    """Colour at position ``t`` (0..1) along a multi-stop gradient."""
    span = len(stops) - 1
    seg = min(int(t * span), span - 1)
    local = t * span - seg
    a = [int(stops[seg][i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(stops[seg + 1][i:i + 2], 16) for i in (1, 3, 5)]
    r, g, bl = (round(x + (y - x) * local) for x, y in zip(a, b))
    return f"#{r:02x}{g:02x}{bl:02x}"


def _gradient(text: str) -> Text:
    steps = max(len(text) - 1, 1)
    out = Text()
    for i, ch in enumerate(text):
        out.append(ch, style=f"bold {_blend(i / steps)}")
    return out


def _logo_rows() -> list[Text]:
    width = max(len(row) for row in _LOGO)
    rows = []
    for row in _LOGO:
        line = Text()
        for col, ch in enumerate(row):
            line.append(ch, style=f"bold {_blend(col / (width - 1))}" if ch != " " else "")
        rows.append(line)
    return rows


def _header(c: Console, command: str, subtitle: str) -> None:
    """Banner panel. ``subtitle`` is markup whose untrusted parts are already escaped."""
    caption = Text.from_markup(f"[fs.label]{subtitle}[/fs.label]")
    if c.width < BANNER_MIN_WIDTH:
        title = Text.assemble(("◆ ", "fs.accent"), _gradient("FileSift"), (f" v{__version__}", "fs.dim"),
                              ("  ›  ", "fs.dim"), (command, "bold"))
        c.print(Panel(Group(title, caption), box=box.ROUNDED, border_style="fs.border", padding=(0, 1),
                      width=_width(c)))
        return
    side = [
        Text.assemble((f"v{__version__}", "fs.accent"), ("  ›  ", "fs.dim"), (command, "bold")),
        Text("File integrity monitor", style="bold"),
        Text("SHA-256 · honest coverage", style="fs.label"),
    ]
    banner = Table.grid(padding=(0, 4))
    banner.add_column(no_wrap=True)
    banner.add_column(no_wrap=True)
    for logo_row, side_row in zip(_logo_rows(), side):
        banner.add_row(logo_row, side_row)
    c.print(Panel(Group(banner, Text(), caption), box=box.ROUNDED, border_style="fs.border", padding=(1, 2),
                  width=_width(c)))


def _grid(rows: list[tuple[str, str]]) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="fs.label", no_wrap=True, min_width=10)
    grid.add_column(overflow="fold")
    for label, value in rows:
        grid.add_row(label, value)
    return Padding(grid, (0, 0, 0, 2), expand=False)


def _bullets(title: str, lines: list[str], style: str) -> RenderableType:
    body = [Text.from_markup(f"[{style}]{title}[/{style}]")]
    body += [Text.from_markup(f"  [fs.dim]└[/fs.dim] {line}") for line in lines]
    return Padding(Group(*body), (0, 0, 0, 2), expand=False)


def _verdict(c: Console, *, status: str, lines: list[str], exit_code: int) -> None:
    label, badge_style, border = _VERDICT[status]
    body = [Text(label, style=badge_style), Text()]
    body += [Text.from_markup(f"[fs.label]{line}[/fs.label]") for line in lines]
    c.print(Panel(Group(*body), title="[bold]Result[/bold]", title_align="left",
                  subtitle=f"[fs.dim]exit {exit_code}[/fs.dim]", subtitle_align="right",
                  box=box.HEAVY, border_style=border, padding=(1, 2), width=_width(c)))


def _digest_panel(c: Console, sha256: str, hint: str | None) -> None:
    body = [Text(sha256, style="fs.digest")]
    if hint:
        body.append(Text(hint, style="fs.label"))
    c.print(Panel(Group(*body), title="[fs.accent]SHA-256[/fs.accent]", title_align="left", box=box.ROUNDED,
                  border_style="fs.border", padding=(0, 1), width=_width(c)))


def _auth(authenticated: bool, verified_word: str = "HMAC verified") -> str:
    if authenticated:
        return f"[fs.ok]●[/fs.ok] authenticated ({verified_word})"
    return "[fs.label]○ unauthenticated[/fs.label]"


# ---------------------------------------------------------------- scan

def _detail(f: dict[str, Any]) -> str:
    d = f["details"]
    event = f["event"]
    arrow = " [fs.dim]→[/fs.dim] "
    if event == "MODIFIED" and "old_target" in d:
        return f"{safe_display(d['old_target'])}{arrow}{safe_display(d['new_target'])}"
    if event == "MODIFIED":
        text = f"{d['old_size']}{arrow}{d['new_size']} bytes"
        return text + " [fs.warn]· mode changed[/fs.warn]" if d["mode_changed"] else text
    if event == "PERMISSIONS_CHANGED":
        return f"{d['old_mode']}{arrow}[fs.warn]{d['new_mode']}[/fs.warn]"
    if event == "TYPE_CHANGED":
        return f"{d['old_type']}{arrow}{d['new_type']}"
    if event in ("ADDED", "DELETED") and d["type"] == "symlink":
        return f"symlink{arrow}{safe_display(d['target'])}"
    if event in ("ADDED", "DELETED") and d["type"] == "special":
        return f"special ({d['kind']})"
    if event in ("ADDED", "DELETED"):
        return f"[fs.dim]{d['size_bytes']} bytes[/fs.dim]" if "size_bytes" in d else ""
    if event == "UNREADABLE":
        return safe_display(d["error"])
    if event == "UNSTABLE":
        return "changed while being hashed (twice)"
    return safe_display(d["reason"])                      # UNVERIFIED


def _partial_reasons(report: dict[str, Any], baseline_complete: bool) -> list[str]:
    cov, summary = report["coverage"], report["summary"]
    reasons = []
    dirs = cov["unverified_prefixes"]
    if dirs:
        reasons.append(f"{_plural(len(dirs), 'directory', 'directories')} could not be listed ({_joined(dirs)})")
    if summary["unreadable"]:
        reasons.append(f"{_plural(summary['unreadable'], 'entry', 'entries')} unreadable")
    if summary["unstable"]:
        reasons.append(f"{_plural(summary['unstable'], 'file')} unstable")
    undecodable = sum(1 for e in report["errors"] if e["kind"] == "UNDECODABLE_NAME")
    if undecodable:
        reasons.append(f"{_plural(undecodable, 'name')} not valid UTF-8")
    if not baseline_complete:
        reasons.append("baseline was recorded with coverage gaps")
    if summary["unverified"]:
        reasons.append(f"{_plural(summary['unverified'], 'path')} unverified")
    return reasons


def _findings_table(findings: list[dict[str, Any]]) -> Table:
    table = Table(box=box.ROUNDED, border_style="fs.border", header_style="fs.accent", pad_edge=True,
                  title="[fs.accent]Findings[/fs.accent]", title_justify="left")
    table.add_column("Event", no_wrap=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Detail", overflow="fold")
    for f in findings:
        table.add_row(Text(f" {f['event']} ", style=_BADGE[f["event"]]), _path(f["subject"]), _detail(f))
    return table


def _chips(summary: dict[str, int]) -> str:
    chips = [f"[bold {colour}]{sign}{summary[key]}[/bold {colour}] [fs.label]{label}[/fs.label]"
             for key, sign, colour, label in _CHIPS if summary.get(key)]
    return "   ".join(chips)


def render_scan(report: dict[str, Any], *, baseline_display: str, report_display: str | None,
                baseline_complete: bool) -> None:
    c = out_console
    cov, base = report["coverage"], report["baseline"]
    findings = report["findings"]
    excluded = cov["excluded_by_pattern"] + cov["artifacts_excluded"]
    counts = (f"{_plural(cov['entries_inventoried'], 'entry', 'entries')} inventoried{SEP}"
              f"{excluded} excluded")

    _header(c, "scan", f"Comparing {_path(report['target']['label'])} against its baseline")
    rows = [
        ("Baseline", f"{_path(baseline_display)}{SEP}[fs.label]created {safe_display(base['created_at'])}[/fs.label]"),
        ("Integrity", _auth(base["authenticated"])),
    ]
    if not base["root_match"]:
        rows.append(("Root", "[fs.warn]▲ MISMATCH[/fs.warn] baseline was recorded for a different directory"))
    if cov["complete"]:
        rows.append(("Coverage", f"[fs.ok]✓ complete[/fs.ok]{SEP}{counts}"))
    else:
        rows.append(("Coverage", f"[fs.bad]✗ PARTIAL[/fs.bad]{SEP}{counts}"))
    if cov["exclusions_applied"]:
        rows.append(("Exclusions", _joined(cov["exclusions_applied"], limit=20)))
    c.print(_grid(rows))
    if not cov["complete"]:
        c.print()
        c.print(_bullets("Coverage gaps", _partial_reasons(report, baseline_complete), "fs.bad"))

    if findings:
        c.print()
        c.print(Padding(_findings_table(findings), (0, 0, 0, 2), expand=False))
        c.print(Padding(Text.from_markup(_chips(report["summary"])), (0, 0, 0, 3), expand=False))
    c.print()

    status = report["status"]
    changes = sum(1 for f in findings if f["category"] == "integrity")
    if status == "clean":
        _verdict(c, status="clean", exit_code=0,
                 lines=["No changes · every in-scope entry was inspected."])
    elif status == "changes_detected":
        _verdict(c, status="changes_detected", exit_code=1,
                 lines=[f"{_plural(len(findings), 'finding')} · review them before re-baselining."])
    elif report["result"] == "changes_detected":
        _verdict(c, status="incomplete", exit_code=4,
                 lines=[f"{_plural(changes, 'change')} found, and coverage gaps mean more may be undetected.",
                        "This is NOT a clean result."])
    else:
        _verdict(c, status="incomplete", exit_code=4,
                 lines=["No changes found in the inspected scope — this is NOT a clean result."])
    if report_display is not None:
        c.print(f"  [fs.label]Report[/fs.label]  [fs.dim]→[/fs.dim] {_path(report_display)}")


# ---------------------------------------------------------------- init-baseline / verify-baseline

def render_init(*, label: str, baseline_display: str, entries: int, excluded: int, gaps: list[str],
                undecodable: int, authenticated: bool, sha256: str) -> None:
    c = out_console
    _header(c, "init-baseline", f"Recording a trusted baseline of {_path(label)}")
    if gaps or undecodable:
        parts = []
        if gaps:
            parts.append(f"{_plural(len(gaps), 'path')} recorded as unverified")
        if undecodable:
            parts.append(f"{_plural(undecodable, 'name')} not valid UTF-8 (not recordable)")
        coverage = f"[fs.bad]✗ PARTIAL[/fs.bad]{SEP}{SEP.join(parts)}"
    else:
        coverage = "[fs.ok]✓ complete[/fs.ok]"
    signing = "[fs.ok]●[/fs.ok] HMAC-signed" if authenticated else "[fs.label]○ unauthenticated[/fs.label]"
    c.print(_grid([
        ("Baseline", f"{_path(baseline_display)}{SEP}[fs.ok]✓ written[/fs.ok]"),
        ("Integrity", signing),
        ("Entries", f"{entries} recorded{SEP}{excluded} excluded"),
        ("Coverage", coverage),
    ]))
    c.print()
    _digest_panel(c, sha256, "Record this digest somewhere the monitored host cannot write.")


def render_gap_refusal(*, unreadable: dict[str, str], unstable: Iterable[str], unlisted: Iterable[str],
                       undecodable: Iterable[str]) -> None:
    c = err_console
    rows = Table.grid(padding=(0, 2))
    rows.add_column(style="fs.bad", no_wrap=True)
    rows.add_column(overflow="fold")
    for rel in sorted(unlisted):
        rows.add_row("directory not listable", _path(rel))
    for rel, err in sorted(unreadable.items()):
        rows.add_row("unreadable", f"{_path(rel)} [fs.dim]({safe_display(err)})[/fs.dim]")
    for rel in sorted(unstable):
        rows.add_row("unstable", _path(rel))
    for name in undecodable:
        rows.add_row("name not valid UTF-8", safe_display(name))
    hint = Text.from_markup("[fs.label]Fix access and re-run, or pass [bold]--allow-incomplete[/bold] to record "
                            "these paths as unverified.[/fs.label]")
    c.print(Panel(Group(rows, Text(), hint), title="[fs.bad]✗ coverage gaps found — baseline NOT written[/fs.bad]",
                  title_align="left", box=box.ROUNDED, border_style="#f87171", padding=(0, 1), width=_width(c)))


def render_verify(*, baseline_display: str, label: str, created_at: str, entries: int, exclusions: list[str],
                  unverified: int, complete: bool, authenticated: bool, sha256: str) -> None:
    c = out_console
    _header(c, "verify-baseline", f"Validating {_path(baseline_display)}")
    auth = _auth(True) if authenticated else "[fs.label]○ unauthenticated (no MAC, no key)[/fs.label]"
    if complete:
        coverage = "[fs.ok]✓ complete[/fs.ok]"
    else:
        coverage = f"[fs.bad]✗ PARTIAL[/fs.bad]{SEP}{_plural(unverified, 'path')} recorded as unverified"
    c.print(_grid([
        ("Valid", "[fs.ok]✓ structure OK[/fs.ok]"),
        ("Integrity", auth),
        ("Root", _path(label)),
        ("Created", safe_display(created_at)),
        ("Entries", str(entries)),
        ("Exclusions", _joined(exclusions, limit=20) if exclusions else "[fs.label]none[/fs.label]"),
        ("Coverage", coverage),
    ]))
    c.print()
    _digest_panel(c, sha256, "Compare with the digest recorded when the baseline was created.")
