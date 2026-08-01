import sys

import pytest

from safecode_auditor import cli
from scanner.firebase_analyzer import FirebaseRuleAnalyzer

OPEN_ACCESS_EXPLANATION = (
    "Using 'if true' allows anyone on the internet to read or write data "
    "without any credentials."
)


def _analyze(source, filepath="firestore.rules"):
    return FirebaseRuleAnalyzer().analyze(source, filepath)


def test_open_access_finding_preserves_current_public_shape():
    source = """
    match /public/{docId} {
      allow read, write: if true;
    }
    """

    assert _analyze(source, "app/firestore.rules") == [
        {
            "file": "app/firestore.rules",
            "path": "/public/{docId}",
            "operations": ["read", "write"],
            "condition": "true",
            "vuln_type": "OpenAccess",
            "severity": "CRITICAL",
            "description": (
                "Collection is fully open to the public, no authentication " "required."
            ),
            "explanation": OPEN_ACCESS_EXPLANATION,
            "fix": (
                "Replace 'if true' with an authentication check:\n"
                "  allow read: if request.auth != null "
                "&& request.auth.uid == docId;"
            ),
        }
    ]


def test_bare_write_rule_is_currently_open_access():
    source = """
    match /public/{docId} {
      allow create, update;
    }
    """

    finding = _analyze(source)[0]

    assert finding["vuln_type"] == "OpenAccess"
    assert finding["operations"] == ["create", "update"]
    assert finding["condition"] is None
    assert finding["severity"] == "CRITICAL"


def test_false_condition_does_not_report_open_access():
    source = """
    match /public/{docId} {
      allow read, write: if false;
    }
    """

    assert _analyze(source) == []


@pytest.mark.parametrize(
    "commented_rule",
    [
        "// allow read: if true;",
        "/* allow read: if true; */",
    ],
)
def test_commented_open_access_rule_is_ignored(commented_rule):
    source = f"""
    match /public/{{docId}} {{
      {commented_rule}
      allow read: if false;
    }}
    """

    assert _analyze(source) == []


def test_open_access_findings_follow_source_order():
    source = """
    match /first/{firstId} {
      allow read: if true;
    }
    match /second/{secondId} {
      allow write: if true;
    }
    """

    findings = _analyze(source)

    assert [finding["path"] for finding in findings] == [
        "/first/{firstId}",
        "/second/{secondId}",
    ]
    assert [finding["operations"] for finding in findings] == [
        ["read"],
        ["write"],
    ]


def test_terminal_firebase_finding_format_is_preserved(capsys):
    finding = _analyze(
        """
        match /public/{docId} {
          allow read, write: if true;
        }
        """
    )[0]

    cli.print_firebase_finding(1, finding)

    assert capsys.readouterr().out == (
        "\n  [1] 🔴 CRITICAL — OpenAccess\n"
        "       Path : /public/{docId}\n"
        "       Ops  : read, write\n"
        f"       Why  : {OPEN_ACCESS_EXPLANATION}\n"
        "       Fix  : Replace 'if true' with an authentication check:\n"
    )


def test_cli_reports_firebase_finding_and_returns_success(monkeypatch, capsys):
    finding = _analyze(
        """
        match /public/{docId} {
          allow read: if true;
        }
        """
    )[0]

    monkeypatch.setattr(sys, "argv", ["safecode", "project"])
    monkeypatch.setattr(cli.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(cli, "scan_directory", lambda _path: [])
    monkeypatch.setattr(cli, "scan_config_directory", lambda _path: [])
    monkeypatch.setattr(cli, "scan_firebase_directory", lambda _path: [finding])

    result = cli.main()
    output = capsys.readouterr().out

    assert result is None
    assert "🔴 CRITICAL — OpenAccess" in output
    assert "Path : /public/{docId}" in output
    assert "CRITICAL : 1" in output
    assert "TOTAL       : 1 issue(s) found" in output


def test_cli_missing_target_preserves_exit_code_one(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["safecode"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1
    assert "Usage  : safecode <path_to_scan>" in capsys.readouterr().out
