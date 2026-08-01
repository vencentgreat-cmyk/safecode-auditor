"""Tests for robustness and input hardening."""

from __future__ import annotations

import pytest

from safecode_auditor import cli
from scanner.config_checker import scan_config_file
from scanner.firebase_analyzer import FirebaseRuleAnalyzer
from scanner.json_locator import JsonScanError, scan_json_leaf_values
from scanner.secret_sniffer import scan_file as sniffer_scan_file


class TestMalformedJSONFallback:
    """Malformed JSON must fall back to legacy regex, never crash."""

    def test_truncated_json_falls_back(self, tmp_path):
        path = tmp_path / "database.rules.json"
        path.write_text('{"rules": {".read": "true"', encoding="utf-8")
        findings = scan_config_file(str(path))
        assert len(findings) >= 1
        assert findings[0]["line"] == "N/A"

    def test_empty_json_object_no_crash(self, tmp_path):
        path = tmp_path / "database.rules.json"
        path.write_text("{}", encoding="utf-8")
        findings = scan_config_file(str(path))
        assert findings == []

    def test_empty_rules_object_no_crash(self, tmp_path):
        path = tmp_path / "database.rules.json"
        path.write_text('{"rules": {}}', encoding="utf-8")
        findings = scan_config_file(str(path))
        assert findings == []


class TestEmptyAndEdgeInputs:
    """Edge case inputs must not crash."""

    def test_empty_firestore_input(self):
        findings = FirebaseRuleAnalyzer().analyze("")
        assert findings == []

    def test_whitespace_only_firestore_input(self):
        findings = FirebaseRuleAnalyzer().analyze("   \n  \n  ")
        assert findings == []

    def test_only_comments(self):
        findings = FirebaseRuleAnalyzer().analyze(
            "// this is a comment\n/* block comment */"
        )
        assert findings == []

    def test_empty_file_sniffer(self, tmp_path):
        path = tmp_path / "empty.py"
        path.write_text("", encoding="utf-8")
        findings = sniffer_scan_file(str(path))
        assert findings == []


class TestScanNonexistentPath:
    """Scanning nonexistent paths must return empty, not crash."""

    def test_sniffer_nonexistent_file(self):
        findings = sniffer_scan_file("/nonexistent/path/xyz.py")
        assert findings == []

    def test_config_nonexistent_file(self):
        findings = scan_config_file("/nonexistent/path/.env")
        assert findings == []

    def test_firebase_nonexistent_file(self):
        from scanner.firebase_analyzer import scan_firebase_file

        findings = scan_firebase_file("/nonexistent/path/firestore.rules")
        assert findings == []


class TestCLIErrorHandling:
    """CLI must handle errors with consistent exit codes."""

    def test_missing_target_exit_code(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main([])
        assert exc.value.code == 1

    def test_nonexistent_target_terminal(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["/nonexistent/path"])
        assert exc.value.code == 1

    def test_nonexistent_target_json(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["/nonexistent/path", "--format", "json"])
        assert exc.value.code == 1

    def test_output_without_machine_format(self, capsys, tmp_path):
        # Create empty dir to scan quickly.
        (tmp_path / "dummy").mkdir()
        with pytest.raises(SystemExit) as exc:
            cli.main([str(tmp_path / "dummy"), "--output", "out.txt", "--format", "terminal"])
        assert exc.value.code == 1

    def test_invalid_baseline(self, capsys, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            cli.main([".", "--baseline", str(path)])
        assert exc.value.code == 1


class TestJSONLocatorRobustness:
    """JSON locator must handle edge cases gracefully."""

    def test_empty_input_raises(self):
        with pytest.raises(JsonScanError):
            scan_json_leaf_values("")

    def test_only_whitespace_raises(self):
        with pytest.raises(JsonScanError):
            scan_json_leaf_values("   \n  ")

    def test_trailing_comma_raises(self):
        with pytest.raises(JsonScanError):
            scan_json_leaf_values('{"key": "value",}')

    def test_unquoted_key_raises(self):
        with pytest.raises(JsonScanError):
            scan_json_leaf_values("{key: value}")
