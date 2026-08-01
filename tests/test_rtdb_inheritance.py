"""Unit tests for permission-inheritance analysis."""

from __future__ import annotations

from scanner.json_locator import scan_json_string_values
from scanner.rtdb_inheritance import analyze_inheritance
from scanner.rtdb_tree import build_rtdb_tree


def _analyze(text: str):
    entries = scan_json_string_values(text)
    tree = build_rtdb_tree(entries)
    return analyze_inheritance(tree)


def test_owner_check_under_permissive_read_root_is_reported():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "auth != null",\n'
        '    "users": {\n'
        '      "$uid": {\n'
        '        ".read": "$uid === auth.uid"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "read"
    assert finding.severity == "HIGH"
    assert finding.child_path == ("users", "$uid")
    assert finding.ancestor_path == ()
    assert finding.ancestor_expr.expression == "auth != null"
    assert finding.child_expr.expression == "$uid === auth.uid"


def test_owner_check_under_true_root_is_reported():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "true",\n'
        '    "users": {\n'
        '      "$uid": {\n'
        '        ".read": "$uid === auth.uid"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert len(findings) == 1
    assert findings[0].ancestor_expr.expression == "true"


def test_write_inheritance_is_reported_independently_from_read():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".write": "auth != null",\n'
        '    "posts": {\n'
        '      "$postId": {\n'
        '        ".write": "$postId == auth.uid"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    kinds = sorted(f.kind for f in findings)
    assert kinds == ["write"]


def test_double_equals_owner_check_still_matches():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "true",\n'
        '    "$uid": { ".read": "$uid == auth.uid" }\n'
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert len(findings) == 1


def test_reversed_owner_check_still_matches():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "true",\n'
        '    "$uid": { ".read": "auth.uid === $uid" }\n'
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert len(findings) == 1


def test_strict_ancestor_does_not_trigger_finding():
    # No permissive ancestor at all, so the descendant's owner check is
    # meaningful. No finding must be produced.
    text = (
        "{\n"
        '  "rules": {\n'
        '    "users": {\n'
        '      "$uid": {\n'
        '        ".read": "$uid === auth.uid"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    )
    assert _analyze(text) == []


def test_permissive_ancestor_without_owner_check_child_does_not_trigger():
    # The child's rule is not an owner check, so we do not have enough
    # evidence to say the descendant was *meant* to be stricter.
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "auth != null",\n'
        '    "users": {\n'
        '      ".read": "auth != null"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    assert _analyze(text) == []


def test_child_permissive_rule_does_not_trigger_on_itself():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "true",\n'
        '    "users": { ".read": "true" }\n'
        "  }\n"
        "}"
    )
    assert _analyze(text) == []


def test_read_and_write_are_tracked_separately():
    # Permissive read at root, strict-looking write at descendant. The
    # descendant's write is not shadowed by anything, so no finding
    # should be produced for write. Read side is fine too.
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "true",\n'
        '    "$uid": {\n'
        '        ".write": "$uid === auth.uid"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert findings == []


def test_deeper_nesting_still_detects_root_level_permissive():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "auth != null",\n'
        '    "a": { "b": { "c": { "$uid": { ".read": "$uid === auth.uid" } } } }\n'
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert len(findings) == 1
    assert findings[0].child_path == ("a", "b", "c", "$uid")


def test_whitespace_variations_in_permissive_are_recognised():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "auth  !=  null",\n'
        '    "$uid": { ".read": "$uid === auth.uid" }\n'
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    assert len(findings) == 1


def test_unrecognised_ancestor_expression_produces_no_finding():
    # Even though the descendant looks like an owner check, we cannot
    # prove the ancestor is broader, so the analyzer stays quiet.
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "root.child(\'admins\').hasChild(auth.uid)",\n'
        '    "$uid": { ".read": "$uid === auth.uid" }\n'
        "  }\n"
        "}"
    )
    assert _analyze(text) == []


def test_source_positions_are_preserved_on_finding():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "auth != null",\n'
        '    "$uid": {\n'
        '      ".read": "$uid === auth.uid"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    findings = _analyze(text)
    finding = findings[0]
    assert finding.ancestor_expr.line == 3
    assert finding.child_expr.line == 5
