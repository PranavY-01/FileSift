from pydantic import TypeAdapter

from conftest import SHA_A, SHA_B, baseline_dict, file_entry
from filesift.comparator import compare, derive
from filesift.models import BaselineDocument, Entry
from filesift.scanner import Inventory

_ENTRY = TypeAdapter(Entry)


def _doc(entries, **kwargs) -> BaselineDocument:
    return BaselineDocument.model_validate(baseline_dict(entries, **kwargs))


def _inv(entries, **attrs) -> Inventory:
    inv = Inventory()
    inv.entries = {k: _ENTRY.validate_python(v) for k, v in entries.items()}
    for name, value in attrs.items():
        setattr(inv, name, value)
    return inv


def _events(findings):
    return [(f.event, f.subject) for f in findings]


def link(target):
    return {"type": "symlink", "target": target}


def special(kind):
    return {"type": "special", "kind": kind}


def test_identical_produces_no_findings():
    entries = {"a": file_entry(), "b": link("a"), "c": special("fifo")}
    assert compare(_doc(entries), _inv(entries)) == []


def test_added():
    findings = compare(_doc({}), _inv({"new": file_entry(SHA_B, 3)}))
    assert _events(findings) == [("ADDED", "new")]
    assert findings[0].category == "integrity"
    assert findings[0].details == {"type": "file", "sha256": SHA_B, "size_bytes": 3}


def test_deleted():
    findings = compare(_doc({"old": file_entry()}), _inv({}))
    assert _events(findings) == [("DELETED", "old")]
    assert findings[0].details == {"type": "file", "sha256": SHA_A, "size_bytes": 1}


def test_modified_file():
    findings = compare(_doc({"f": file_entry(SHA_A, 16)}), _inv({"f": file_entry(SHA_B, 15)}))
    assert _events(findings) == [("MODIFIED", "f")]
    assert findings[0].details == {"old_sha256": SHA_A, "new_sha256": SHA_B, "old_size": 16, "new_size": 15,
                                   "mode_changed": False}


def test_content_and_mode_changed_is_one_modified_finding():
    findings = compare(_doc({"f": file_entry(SHA_A)}), _inv({"f": file_entry(SHA_B, mode="0755")}))
    assert _events(findings) == [("MODIFIED", "f")]
    assert findings[0].details["mode_changed"] is True


def test_permissions_changed():
    findings = compare(_doc({"f": file_entry(mode="0644")}), _inv({"f": file_entry(mode="4755")}))
    assert _events(findings) == [("PERMISSIONS_CHANGED", "f")]
    assert findings[0].details == {"old_mode": "0644", "new_mode": "4755"}


def test_symlink_retargeted():
    findings = compare(_doc({"l": link("a")}), _inv({"l": link("/etc/shadow")}))
    assert _events(findings) == [("MODIFIED", "l")]
    assert findings[0].details == {"old_target": "a", "new_target": "/etc/shadow"}


def test_file_replaced_by_symlink():
    findings = compare(_doc({"f": file_entry()}), _inv({"f": link("x")}))
    assert _events(findings) == [("TYPE_CHANGED", "f")]
    assert findings[0].details == {"old_type": "file", "new_type": "symlink"}


def test_special_kind_change():
    findings = compare(_doc({"s": special("fifo")}), _inv({"s": special("char_device")}))
    assert _events(findings) == [("TYPE_CHANGED", "s")]
    assert findings[0].details == {"old_type": "fifo", "new_type": "char_device"}


def test_unreadable_and_unstable():
    findings = compare(_doc({"a": file_entry(), "b": file_entry()}),
                       _inv({}, unreadable={"a": "Permission denied"}, unstable={"b"}))
    assert _events(findings) == [("UNREADABLE", "a"), ("UNSTABLE", "b")]
    assert all(f.category == "coverage" for f in findings)


def test_unverified_not_deleted_under_unlisted_parent():
    findings = compare(_doc({"private/keys.conf": file_entry(), "private/deep/x": file_entry(), "gone": file_entry()}),
                       _inv({}, unverified_prefixes={"private"}))
    assert _events(findings) == [("DELETED", "gone"), ("UNVERIFIED", "private/deep/x"),
                                 ("UNVERIFIED", "private/keys.conf")]
    assert findings[1].details == {"reason": "parent directory not listable"}


def test_directory_replaced_by_file():
    findings = compare(_doc({"a/x": file_entry(), "a/y": file_entry()}), _inv({"a": file_entry()}))
    assert _events(findings) == [("ADDED", "a"), ("DELETED", "a/x"), ("DELETED", "a/y")]


def test_baseline_gap_stays_unverified_never_added():
    """E4: a current path at or under a baseline gap is UNVERIFIED, never ADDED."""
    findings = compare(_doc({"a": file_entry()}, unverified=["secret"]),
                       _inv({"a": file_entry(), "secret/new.txt": file_entry()}))
    assert _events(findings) == [("UNVERIFIED", "secret/new.txt")]
    assert findings[0].details == {"reason": "unverified in baseline"}


def test_baseline_gap_with_nothing_beneath_is_still_reported():
    findings = compare(_doc({"a": file_entry()}, unverified=["locked", "z.txt"]), _inv({"a": file_entry()}))
    assert _events(findings) == [("UNVERIFIED", "locked"), ("UNVERIFIED", "z.txt")]


def test_baseline_gap_path_itself_observed():
    findings = compare(_doc({}, unverified=["f"]), _inv({"f": file_entry()}))
    assert _events(findings) == [("UNVERIFIED", "f")]


def test_findings_sorted_by_subject():
    findings = compare(_doc({"z": file_entry(), "m": file_entry(), "b/c": file_entry()}),
                       _inv({"a": file_entry(), "m": file_entry(SHA_B)}))
    assert [f.subject for f in findings] == ["a", "b/c", "m", "z"]


# derive(): all rows of the Spec §6.7 status table (the fatal "error" row is covered in test_cli.py)

def test_derive_clean():
    doc, inv = _doc({"a": file_entry()}), _inv({"a": file_entry()})
    outcome = derive(compare(doc, inv), inv, doc)
    assert (outcome.status, outcome.result, outcome.coverage_complete, outcome.exit_code) == \
        ("clean", "clean", True, 0)


def test_derive_changes_detected():
    doc, inv = _doc({"a": file_entry()}), _inv({"a": file_entry(SHA_B)})
    outcome = derive(compare(doc, inv), inv, doc)
    assert (outcome.status, outcome.result, outcome.coverage_complete, outcome.exit_code) == \
        ("changes_detected", "changes_detected", True, 1)


def test_derive_incomplete_without_changes():
    doc, inv = _doc({"a": file_entry()}), _inv({}, unreadable={"a": "denied"})
    outcome = derive(compare(doc, inv), inv, doc)
    assert (outcome.status, outcome.result, outcome.coverage_complete, outcome.exit_code) == \
        ("incomplete", "clean", False, 4)


def test_derive_incomplete_with_changes():
    doc = _doc({"private/a": file_entry(), "b": file_entry()})
    inv = _inv({"b": file_entry(SHA_B)}, unverified_prefixes={"private"})
    outcome = derive(compare(doc, inv), inv, doc)
    assert (outcome.status, outcome.result, outcome.coverage_complete, outcome.exit_code) == \
        ("incomplete", "changes_detected", False, 4)


def test_derive_incomplete_baseline_without_findings():
    """E5: a baseline recorded with gaps (e.g. undecodable names only) can never yield a clean scan."""
    doc, inv = _doc({"a": file_entry()}, complete=False), _inv({"a": file_entry()})
    findings = compare(doc, inv)
    assert findings == []
    outcome = derive(findings, inv, doc)
    assert (outcome.status, outcome.exit_code) == ("incomplete", 4)


def test_derive_undecodable_names_are_partial_coverage():
    doc, inv = _doc({"a": file_entry()}), _inv({"a": file_entry()}, undecodable=1)
    assert derive(compare(doc, inv), inv, doc).status == "incomplete"


def test_derive_unlisted_new_directory_is_partial_coverage():
    doc, inv = _doc({"a": file_entry()}), _inv({"a": file_entry()}, unverified_prefixes={"newdir"})
    findings = compare(doc, inv)
    assert findings == []
    assert derive(findings, inv, doc).exit_code == 4
