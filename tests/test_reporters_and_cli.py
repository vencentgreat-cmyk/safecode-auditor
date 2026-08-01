import json

import pytest

from safecode_auditor import __version__, cli
from safecode_auditor.baseline import load_baseline
from safecode_auditor.reporters.json_reporter import build_json_report
from safecode_auditor.reporters.sarif import build_sarif_report
from safecode_auditor.reporters.terminal import print_secret_finding
from scanner.firebase_analyzer import FirebaseRuleAnalyzer


def _finding(filepath="firestore.rules"):
    return FirebaseRuleAnalyzer().analyze(
        "match /public/{docId} { allow read: if true; }",
        filepath,
    )[0]


def test_json_report_has_stable_versioned_shape():
    report = build_json_report([_finding()])

    assert report["schema_version"] == "1.0.0"
    assert report["summary"]["total"] == 1
    assert report["findings"][0]["rule_id"] == "FIRE001"
    assert report["findings"][0]["location"]["start_line"] == 1


def test_json_report_uses_package_version():
    report = build_json_report([])

    assert report["tool"]["version"] == __version__


def test_sarif_report_contains_rule_and_physical_location():
    report = build_sarif_report([_finding("app/firestore.rules")])
    run = report["runs"][0]

    assert report["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "FIRE001"
    result = run["results"][0]
    assert result["ruleId"] == "FIRE001"
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "app/firestore.rules"
    assert physical["region"]["startLine"] == 1


def test_sarif_report_uses_package_version():
    report = build_sarif_report([])

    assert report["runs"][0]["tool"]["driver"]["version"] == __version__


def test_cli_scans_single_rules_file_as_json(tmp_path, capsys):
    rules_file = tmp_path / "firestore.rules"
    rules_file.write_text(
        "match /public/{docId} { allow read: if true; }",
        encoding="utf-8",
    )

    result = cli.main([str(rules_file), "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    assert result is None
    assert report["summary"]["total"] == 1
    assert report["findings"][0]["rule_id"] == "FIRE001"


def test_fail_on_threshold_returns_two_for_matching_finding(tmp_path, capsys):
    rules_file = tmp_path / "firestore.rules"
    rules_file.write_text(
        "match /public/{docId} { allow read: if true; }",
        encoding="utf-8",
    )

    result = cli.main([str(rules_file), "--format", "json", "--fail-on", "high"])
    capsys.readouterr()

    assert result == 2


def test_baseline_suppresses_existing_finding(tmp_path, capsys):
    rules_file = tmp_path / "firestore.rules"
    baseline = tmp_path / "baseline.json"
    rules_file.write_text(
        "match /public/{docId} { allow read: if true; }",
        encoding="utf-8",
    )

    cli.main(
        [
            str(rules_file),
            "--format",
            "json",
            "--generate-baseline",
            str(baseline),
        ]
    )
    capsys.readouterr()
    result = cli.main(
        [
            str(rules_file),
            "--format",
            "json",
            "--baseline",
            str(baseline),
            "--fail-on",
            "low",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert load_baseline(str(baseline))
    assert result is None
    assert report["summary"]["total"] == 0


def test_ignore_rule_suppresses_selected_rule(tmp_path, capsys):
    rules_file = tmp_path / "firestore.rules"
    rules_file.write_text(
        "match /public/{docId} { allow read: if true; }",
        encoding="utf-8",
    )

    cli.main(
        [
            str(rules_file),
            "--format",
            "json",
            "--ignore-rule",
            "fire001",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert report["summary"]["total"] == 0


def _secret_finding(secret):
    return {
        "file": "app.py",
        "line": 3,
        "rule": "OpenAI API Key",
        "content": f'OPENAI_API_KEY = "{secret}"',
        "fix": "Move the credential to an environment variable.",
    }


def test_json_report_redacts_secret_source_content():
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz"

    report = build_json_report([_secret_finding(secret)])
    serialized = json.dumps(report)

    assert secret not in serialized
    assert report["findings"][0]["description"].startswith("[REDACTED")
    assert report["findings"][0]["explanation"].startswith("[REDACTED")


def test_sarif_report_redacts_secret_source_content():
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz"

    report = build_sarif_report([_secret_finding(secret)])

    assert secret not in json.dumps(report)


def test_terminal_report_redacts_secret_source_content(capsys):
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz"

    print_secret_finding(1, _secret_finding(secret))
    output = capsys.readouterr().out

    assert secret not in output
    assert "[REDACTED" in output


def test_list_rules_lists_all_supported_ids(capsys):
    result = cli.main([".", "--list-rules"])
    output = capsys.readouterr().out

    assert result is None
    assert "FIRE001" in output
    assert "CFG008" in output
    assert "SEC001" in output


def test_explain_known_rule_prints_detail(capsys):
    result = cli.main([".", "--explain", "fire001"])
    output = capsys.readouterr().out

    assert result is None
    assert "FIRE001" in output
    assert "Public access" in output
    assert "CRITICAL" in output


def test_explain_unknown_rule_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        cli.main([".", "--explain", "NONEXISTENT"])

    assert exc_info.value.code == 1


def test_explain_does_not_require_valid_target(capsys, tmp_path):
    result = cli.main(["/nonexistent/path", "--explain", "CFG008"])
    output = capsys.readouterr().out

    assert result is None
    assert "CFG008" in output
    assert "Permission Inheritance" in output


def test_sarif_partial_fingerprints_no_collision():
    """Two findings with different semantic identities must not collide."""
    from safecode_auditor.core.models import Confidence, Finding, Fix, Location, Severity

    f1 = Finding(
        rule_id="FIRE001", rule_name="OpenAccess",
        title="Open", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        description="Open.", explanation="Open.",
        location=Location(file="firestore.rules", start_line=3, start_column=1),
        path="/a/{x}", operations=("read",), condition="true",
        fix=Fix(description="Fix."),
    )
    f2 = Finding(
        rule_id="FIRE001", rule_name="OpenAccess",
        title="Open", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        description="Open.", explanation="Open.",
        location=Location(file="firestore.rules", start_line=3, start_column=1),
        path="/b/{y}", operations=("write",), condition="true",
        fix=Fix(description="Fix."),
    )

    report = build_sarif_report([f1, f2])
    fps = [
        r["partialFingerprints"]["primaryLocationLineHash"]
        for r in report["runs"][0]["results"]
    ]
    assert fps[0] != fps[1], (
        "Partial fingerprints must distinguish findings with different "
        "semantic identities even at the same file and line"
    )
