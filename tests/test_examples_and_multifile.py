"""Tests that example files produce expected findings."""

from __future__ import annotations

import os

from safecode_auditor import cli
from scanner.config_checker import scan_config_file
from scanner.firebase_analyzer import scan_firebase_file

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


class TestVulnerableExamples:
    """Vulnerable example files must produce findings."""

    def test_vulnerable_database_produces_unrestricted_read(self):
        path = os.path.join(EXAMPLES_DIR, "firebase-vulnerable-database.rules.json")
        findings = scan_config_file(path)
        rules = {f["rule"] for f in findings}
        assert "Firebase: Unrestricted read access" in rules

    def test_fixed_database_produces_no_findings(self):
        path = os.path.join(EXAMPLES_DIR, "firebase-fixed-database.rules.json")
        findings = scan_config_file(path)
        assert findings == []

    def test_vulnerable_firestore_produces_open_access(self):
        path = os.path.join(EXAMPLES_DIR, "vulnerable-firestore.rules")
        findings = scan_firebase_file(path)
        rule_ids = {f["rule_id"] for f in findings}
        assert "FIRE001" in rule_ids

    def test_fixed_firestore_produces_no_findings(self):
        path = os.path.join(EXAMPLES_DIR, "fixed-firestore.rules")
        findings = scan_firebase_file(path)
        assert findings == []

    def test_all_example_files_exist(self):
        expected = [
            "firebase-vulnerable-database.rules.json",
            "firebase-fixed-database.rules.json",
            "vulnerable-firestore.rules",
            "fixed-firestore.rules",
        ]
        for name in expected:
            assert os.path.isfile(os.path.join(EXAMPLES_DIR, name)), f"Missing: {name}"


class TestMultiFileConsistency:
    """Scanning multiple files must produce deterministic, aggregated results."""

    def test_directory_scan_finds_all_rules_files(self, tmp_path):
        (tmp_path / "firestore.rules").write_text(
            "match /x/{y} { allow read: if true; }", encoding="utf-8"
        )
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "database.rules.json").write_text(
            '{"rules": {".read": "true"}}', encoding="utf-8"
        )
        findings = scan_firebase_file(str(tmp_path / "firestore.rules")) + scan_config_file(
            str(tmp_path / "sub" / "database.rules.json")
        )
        assert len(findings) >= 2

    def test_json_and_sarif_show_same_finding_count(self, capsys, tmp_path):
        (tmp_path / "firestore.rules").write_text(
            "match /x/{y} { allow read: if true; }", encoding="utf-8"
        )
        import json as _json

        cli.main([str(tmp_path), "--format", "json"])
        json_report = _json.loads(capsys.readouterr().out)
        json_count = json_report["summary"]["total"]

        cli.main([str(tmp_path), "--format", "sarif"])
        sarif_report = _json.loads(capsys.readouterr().out)
        sarif_count = len(sarif_report["runs"][0]["results"])

        assert json_count == sarif_count
        assert json_count > 0
