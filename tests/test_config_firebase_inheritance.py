"""End-to-end tests for Firebase permission-inheritance findings.

Exercises the full path from raw JSON text through
``scan_config_file`` all the way to a normalized reporter finding.
Confirms that:

* The new inheritance analysis fires as part of the normal config scan.
* Findings carry accurate ``line`` and ``column`` from the child rule.
* ``normalize_finding`` maps the new rule to stable ID ``CFG008`` and
  keeps position data intact for SARIF.
* The dangerous-key scan and inheritance scan compose: a rules file
  that triggers both must produce both.
* A well-formed but strict rules file still produces zero findings.
"""

from __future__ import annotations

from safecode_auditor.reporters.common import normalize_finding
from scanner.config_checker import scan_config_file


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return str(path)


def test_owner_check_under_auth_permissive_root_is_reported(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    ".read": "auth != null",\n'
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
    finding = inheritance[0]
    # The reported position points at the *child* rule so that the
    # SARIF annotation lands on the rule the developer wrote and
    # believed to be effective.
    assert finding["line"] == 6
    assert finding["column"] == 9
    assert "auth != null" in finding["content"]
    assert "line 3" in finding["content"]
    assert "line 3" in finding["fix"]


def test_dangerous_key_and_inheritance_findings_compose(tmp_path):
    # Root ``.read: "true"`` triggers CFG006 *and* is a permissive
    # ancestor. A descendant owner check must be reported by CFG008
    # in the same scan.
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    ".read": "true",\n'
            '    "$uid": {\n'
            '      ".read": "$uid === auth.uid"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )

    findings = scan_config_file(path)
    rules = {f["rule"] for f in findings}
    assert "Firebase: Unrestricted read access" in rules
    assert "Firebase: Overridden child rule under permissive ancestor" in rules


def test_strict_root_produces_no_inheritance_finding(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
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
    assert findings == []


def test_inheritance_finding_normalizes_to_cfg008(tmp_path):
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    ".read": "auth != null",\n'
            '    "$uid": {\n'
            '      ".read": "$uid === auth.uid"\n'
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )

    findings = scan_config_file(path)
    inheritance = next(
        f
        for f in findings
        if f["rule"] == "Firebase: Overridden child rule under permissive ancestor"
    )
    normalized = normalize_finding(inheritance)
    assert normalized["rule_id"] == "CFG008"
    assert normalized["severity"] == "HIGH"
    assert normalized["location"]["start_line"] == 5
    assert normalized["location"]["start_column"] == 7
    assert normalized["category"] == "configuration"


def test_malformed_json_still_falls_back_to_legacy_scan(tmp_path):
    # Malformed input skips both the JSON locator and inheritance
    # analysis, but must still flag the dangerous key via the legacy
    # regex path. This confirms Phase 2 did not break Phase 1's
    # fallback behavior.
    path = _write(
        tmp_path,
        "database.rules.json",
        '{"rules": {".read": "true"',
    )

    findings = scan_config_file(path)
    assert len(findings) == 1
    assert findings[0]["rule"] == "Firebase: Unrestricted read access"
    assert findings[0]["line"] == "N/A"


def test_normalized_inheritance_finding_is_not_redacted(tmp_path):
    # CFG008 does not carry user credentials, so the description
    # must show the actual advisory text, not the redaction sentinel.
    path = _write(
        tmp_path,
        "database.rules.json",
        (
            "{\n"
            '  "rules": {\n'
            '    ".read": "true",\n'
            '    "$uid": { ".read": "$uid === auth.uid" }\n'
            "  }\n"
            "}\n"
        ),
    )

    findings = scan_config_file(path)
    inheritance = next(
        f
        for f in findings
        if f["rule"] == "Firebase: Overridden child rule under permissive ancestor"
    )
    normalized = normalize_finding(inheritance)
    assert "REDACTED" not in normalized["description"]
    assert "REDACTED" not in normalized["explanation"]
