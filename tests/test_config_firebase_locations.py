"""Integration tests for Firebase Realtime Database rule locations.

These tests verify that ``config_checker.scan_config_file`` reports
accurate ``line`` and ``column`` numbers for dangerous keys in
``database.rules.json`` / ``firebase.json`` inputs, and that
``normalize_finding`` propagates those positions into the reporter
location model that SARIF consumes.
"""

from __future__ import annotations

from safecode_auditor.reporters.common import normalize_finding
from scanner.config_checker import scan_config_file


def _write(tmp_path, name, text):
    path = tmp_path / name
    # ``newline=""`` preserves any ``\r\n`` present in ``text`` so that
    # the CRLF test exercises real Windows-style line endings on disk.
    path.write_text(text, encoding="utf-8", newline="")
    return str(path)


def test_flat_rules_report_real_line_and_column(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        ("{\n" '  "rules": {\n' '    ".read": "true",\n' '    ".write": "true"\n' "  }\n" "}\n"),
    )

    findings = scan_config_file(path)

    by_rule = {f["rule"]: f for f in findings}
    assert "Firebase: Unrestricted read access" in by_rule
    assert "Firebase: Unrestricted write access" in by_rule

    read = by_rule["Firebase: Unrestricted read access"]
    write = by_rule["Firebase: Unrestricted write access"]

    # ``line`` must be a real int, not the legacy sentinel ``"N/A"``.
    assert isinstance(read["line"], int)
    assert isinstance(write["line"], int)
    assert read["line"] == 3
    assert write["line"] == 4
    # Both keys are indented four spaces, so the opening quote sits at
    # column 5 (1-based).
    assert read["column"] == 5
    assert write["column"] == 5


def test_nested_paths_with_duplicate_key_names_report_distinct_lines(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    "a": {\n'
            '      ".read": "true"\n'
            "    },\n"
            '    "b": {\n'
            '      ".read": "true"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )

    findings = [
        f for f in scan_config_file(path) if f["rule"] == "Firebase: Unrestricted read access"
    ]

    lines = sorted(f["line"] for f in findings)
    assert lines == [4, 7]


def test_string_content_that_looks_like_a_rule_is_not_flagged(tmp_path):
    # A ``.read`` sequence appears only inside a string value. It must
    # not be recognised as a key, so no finding should be produced.
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"note": "example of a bad rule: \\".read\\": \\"true\\""}\n',
    )

    findings = scan_config_file(path)
    assert findings == []


def test_crlf_line_endings_produce_correct_line_number(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        ("{\r\n" '  "rules": {\r\n' '    ".read": "true"\r\n' "  }\r\n" "}\r\n"),
    )

    findings = scan_config_file(path)
    assert len(findings) == 1
    assert findings[0]["line"] == 3


def test_malformed_json_falls_back_to_legacy_regex_scan(tmp_path):
    # Missing closing brace makes the JSON invalid. The scanner should
    # still flag the dangerous key via the legacy whole-file regex
    # path, with ``line`` reported as the ``"N/A"`` sentinel.
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"rules": {".read": "true"',
    )

    findings = scan_config_file(path)
    assert len(findings) == 1
    assert findings[0]["rule"] == "Firebase: Unrestricted read access"
    assert findings[0]["line"] == "N/A"


def test_rule_with_safe_value_is_not_flagged(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"rules": {".read": "auth != null"}}\n',
    )

    assert scan_config_file(path) == []


def test_normalized_finding_carries_column_into_location(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        ("{\n" '  "rules": {\n' '    ".read": "true"\n' "  }\n" "}\n"),
    )

    findings = scan_config_file(path)
    assert len(findings) == 1
    normalized = normalize_finding(findings[0])

    location = normalized["location"]
    assert location["start_line"] == 3
    assert location["start_column"] == 5


def test_normalized_finding_legacy_fallback_has_line_one(tmp_path):
    # Malformed JSON -> raw finding has ``line: "N/A"``.
    # ``normalize_finding`` must not crash; it downgrades to line 1
    # so that SARIF still gets a valid location.
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"rules": {".read": "true"',
    )

    findings = scan_config_file(path)
    assert len(findings) == 1
    normalized = normalize_finding(findings[0])
    assert normalized["location"]["start_line"] == 1
    assert normalized["location"]["start_column"] == 1


def test_firebase_json_filename_is_also_scanned(tmp_path):
    # The scanner accepts both ``database.rules.json`` and any file
    # whose name contains ``firebase``.
    path = _write(
        tmp_path,
        "firebase.json",
        ("{\n" '  "rules": {\n' '    ".write": "true"\n' "  }\n" "}\n"),
    )

    findings = scan_config_file(path)
    assert len(findings) == 1
    assert findings[0]["rule"] == "Firebase: Unrestricted write access"
    assert findings[0]["line"] == 3


def test_empty_rules_object_produces_no_findings(tmp_path):
    path = _write(tmp_path, "database.rules.json", '{"rules": {}}\n')
    assert scan_config_file(path) == []
