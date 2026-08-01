"""Integration tests for bare boolean values in Firebase rules.

Firebase Realtime Database rules commonly use bare booleans
(``".read": true``) instead of the string form (``".read": "true"``).
Phase 1's dangerous-key scan and Phase 2's inheritance analyzer must
both fire on the bare-boolean form. These tests exercise the full
path through :func:`scan_config_file` and
:func:`normalize_finding`.
"""

from __future__ import annotations

from safecode_auditor.reporters.common import normalize_finding
from scanner.config_checker import scan_config_file
from scanner.json_locator import scan_json_leaf_values
from scanner.rtdb_inheritance import analyze_inheritance
from scanner.rtdb_tree import build_rtdb_tree


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return str(path)


# ── Dangerous-key detection with bare booleans ──────────────────────────────


def test_bare_true_read_triggers_unrestricted_read(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        ("{\n" '  "rules": {\n' '    ".read": true\n' "  }\n" "}\n"),
    )
    findings = scan_config_file(path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule"] == "Firebase: Unrestricted read access"
    assert finding["line"] == 3
    assert isinstance(finding["column"], int)


def test_bare_true_write_triggers_unrestricted_write(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        ("{\n" '  "rules": {\n' '    ".write": true\n' "  }\n" "}\n"),
    )
    findings = scan_config_file(path)
    assert len(findings) == 1
    assert findings[0]["rule"] == "Firebase: Unrestricted write access"
    assert findings[0]["line"] == 3


def test_bare_false_does_not_trigger(tmp_path):
    # ``.read: false`` denies access. It must not be reported.
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"rules": {".read": false}}\n',
    )
    assert scan_config_file(path) == []


def test_bare_and_string_true_can_coexist_in_one_file(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        ("{\n" '  "rules": {\n' '    ".read": true,\n' '    ".write": "true"\n' "  }\n" "}\n"),
    )
    findings = scan_config_file(path)
    rules = sorted(f["rule"] for f in findings)
    assert rules == [
        "Firebase: Unrestricted read access",
        "Firebase: Unrestricted write access",
    ]


def test_normalized_finding_for_bare_true_uses_cfg006(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"rules": {".read": true}}\n',
    )
    findings = scan_config_file(path)
    normalized = normalize_finding(findings[0])
    assert normalized["rule_id"] == "CFG006"
    assert normalized["severity"] == "HIGH"


# ── Permission inheritance with bare booleans ───────────────────────────────


def test_bare_true_root_makes_child_owner_check_ineffective(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    ".read": true,\n'
            '    "users": {\n'
            '      "$uid": {\n'
            '        ".read": "$uid === auth.uid"\n'
            "      }\n"
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )
    findings = scan_config_file(path)
    inheritance = [
        f
        for f in findings
        if f["rule"] == "Firebase: Overridden child rule under permissive ancestor"
    ]
    assert len(inheritance) == 1
    assert "true" in inheritance[0]["content"]


def test_bare_false_root_does_not_trigger_inheritance_finding(tmp_path):
    # ``.read: false`` is a denial, not a permissive ancestor. The
    # descendant owner check is meaningful. Nothing must be reported
    # about inheritance.
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    ".read": false,\n'
            '    "users": {\n'
            '      "$uid": {\n'
            '        ".read": "$uid === auth.uid"\n'
            "      }\n"
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )
    findings = [
        f
        for f in scan_config_file(path)
        if f["rule"] == "Firebase: Overridden child rule under permissive ancestor"
    ]
    assert findings == []


# ── Tree model directly accepts primitive leaves ────────────────────────────


def test_rtdb_tree_records_bare_true_as_expression_string():
    text = "{\n" '  "rules": {\n' '    ".read": true\n' "  }\n" "}"
    entries = scan_json_leaf_values(text)
    root = build_rtdb_tree(entries)
    assert root.read_rule is not None
    # Bare ``true`` in the source must appear as the string ``"true"``
    # inside the tree so that downstream analyzers can compare against
    # a single normalized form.
    assert root.read_rule.expression == "true"
    assert root.read_rule.line == 3


def test_analyze_inheritance_accepts_tree_built_from_leaf_values():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": true,\n'
        '    "$uid": {\n'
        '      ".read": "$uid === auth.uid"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    entries = scan_json_leaf_values(text)
    root = build_rtdb_tree(entries)
    findings = analyze_inheritance(root)
    assert len(findings) == 1
    assert findings[0].ancestor_expr.expression == "true"
