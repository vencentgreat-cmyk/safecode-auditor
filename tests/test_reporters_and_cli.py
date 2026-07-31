import json
from safecode_auditor.reporters.terminal import print_secret_finding
from safecode_auditor import cli
from safecode_auditor.baseline import load_baseline
from safecode_auditor.reporters.json_reporter import build_json_report
from safecode_auditor.reporters.sarif import build_sarif_report
from scanner.firebase_analyzer import FirebaseRuleAnalyzer
from safecode_auditor import __version__


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
