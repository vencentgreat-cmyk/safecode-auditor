"""Tests for firebase.json project discovery."""

from __future__ import annotations

from scanner.firebase_analyzer import discover_from_firebase_json


def _write_json(tmp_path, name, data):
    import json

    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(tmp_path)


def test_standard_firebase_json_discovers_database_rules(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": {"rules": "database.rules.json"}}', encoding="utf-8"
    )
    (project / "database.rules.json").write_text(
        '{"rules": {".read": "true"}}', encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert len(discovered) == 1
    assert discovered[0].endswith("database.rules.json")


def test_standard_firebase_json_discovers_firestore_rules(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"firestore": {"rules": "firestore.rules"}}', encoding="utf-8"
    )
    (project / "firestore.rules").write_text(
        "match /x/{y} { allow read: if true; }", encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert len(discovered) == 1
    assert discovered[0].endswith("firestore.rules")


def test_both_database_and_firestore_are_discovered(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": {"rules": "db.rules.json"},'
        ' "firestore": {"rules": "fs.rules"}}',
        encoding="utf-8",
    )
    (project / "db.rules.json").write_text(
        '{"rules": {}}', encoding="utf-8"
    )
    (project / "fs.rules").write_text(
        "match /x/{y} { allow read: if true; }", encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert len(discovered) == 2


def test_missing_rules_file_is_not_included(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": {"rules": "nonexistent.rules.json"}}', encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []


def test_path_that_escapes_project_is_rejected(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": {"rules": "../../etc/passwd"}}', encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []


def test_malformed_json_is_handled_gracefully(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text("not json", encoding="utf-8")

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []


def test_non_dict_section_is_ignored(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": "just a string"}', encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []


def test_non_string_rules_path_is_ignored(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": {"rules": 123}}', encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []


def test_empty_rules_path_is_ignored(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "firebase.json").write_text(
        '{"database": {"rules": ""}}', encoding="utf-8"
    )

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []


def test_missing_firebase_json_returns_empty(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    discovered = discover_from_firebase_json(str(project))
    assert discovered == []
