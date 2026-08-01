"""Unit tests for the Realtime Database rules tree."""

from __future__ import annotations

from scanner.json_locator import scan_json_string_values
from scanner.rtdb_tree import (
    RtdbNode,
    RtdbRuleExpr,
    build_rtdb_tree,
)


def _build(text: str) -> RtdbNode:
    return build_rtdb_tree(scan_json_string_values(text))


def test_root_read_rule_is_recorded_on_root_node():
    text = "{\n" '  "rules": {\n' '    ".read": "auth != null"\n' "  }\n" "}"
    root = _build(text)
    assert root.path == ()
    assert root.read_rule is not None
    assert root.read_rule.expression == "auth != null"
    assert root.read_rule.line == 3
    assert root.write_rule is None
    assert root.validate_rule is None
    assert root.children == ()


def test_write_and_validate_are_recorded_alongside_read():
    text = (
        "{\n"
        '  "rules": {\n'
        '    ".read": "true",\n'
        '    ".write": "auth != null",\n'
        '    ".validate": "newData.isString()"\n'
        "  }\n"
        "}"
    )
    root = _build(text)
    assert root.read_rule.expression == "true"
    assert root.write_rule.expression == "auth != null"
    assert root.validate_rule.expression == "newData.isString()"


def test_nested_child_appears_as_child_node_with_relative_path():
    text = (
        "{\n"
        '  "rules": {\n'
        '    "users": {\n'
        '      ".read": "auth != null"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    root = _build(text)
    assert root.read_rule is None
    assert len(root.children) == 1
    users = root.children[0]
    assert users.path == ("users",)
    assert users.read_rule is not None
    assert users.read_rule.expression == "auth != null"


def test_two_children_are_sorted_by_key_deterministically():
    text = (
        "{\n"
        '  "rules": {\n'
        '    "z": { ".read": "true" },\n'
        '    "a": { ".read": "true" }\n'
        "  }\n"
        "}"
    )
    root = _build(text)
    assert [c.path[-1] for c in root.children] == ["a", "z"]


def test_intermediate_nodes_without_own_rules_are_still_present():
    # ``users`` has no rules of its own; only its ``$uid`` child does.
    # The tree must still expose ``users`` as a child of the root so
    # that inheritance analysis can walk through it.
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
    root = _build(text)
    assert len(root.children) == 1
    users = root.children[0]
    assert users.path == ("users",)
    assert users.read_rule is None
    assert len(users.children) == 1
    uid_node = users.children[0]
    assert uid_node.path == ("users", "$uid")
    assert uid_node.read_rule is not None
    assert uid_node.read_rule.expression == "$uid === auth.uid"


def test_ancestor_and_descendant_can_both_carry_rules():
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
    root = _build(text)
    assert root.read_rule is not None
    users = root.children[0]
    uid_node = users.children[0]
    assert uid_node.read_rule is not None
    assert uid_node.read_rule.expression == "$uid === auth.uid"


def test_entries_outside_rules_are_ignored():
    # A ``firebase.json`` may have unrelated top-level keys such as
    # ``hosting``. Those must not become tree nodes.
    text = (
        "{\n"
        '  "hosting": { "public": "web" },\n'
        '  "rules": {\n'
        '    ".read": "true"\n'
        "  }\n"
        "}"
    )
    root = _build(text)
    # Only the ``rules`` root; nothing from ``hosting``.
    assert root.read_rule is not None
    assert root.children == ()


def test_empty_rules_object_produces_empty_root():
    text = '{"rules": {}}'
    root = _build(text)
    assert root == RtdbNode(path=())


def test_line_and_column_are_preserved_from_locator():
    text = (
        "{\n"
        '  "rules": {\n'
        '    "users": {\n'
        '      ".read": "auth != null"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    root = _build(text)
    users = root.children[0]
    assert users.read_rule == RtdbRuleExpr(
        expression="auth != null",
        line=4,
        column=7,
    )
