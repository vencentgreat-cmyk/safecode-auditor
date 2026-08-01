"""Tests for boolean and null leaf detection in the JSON locator.

The original :func:`scan_json_string_values` only surfaces string
leaves. Firebase Realtime Database rules very commonly use bare
booleans (``".read": true``) instead of the string form
(``".read": "true"``), so downstream analysis needs a locator that
can also see boolean and null literals.

These tests exercise :func:`scan_json_leaf_values`, which returns the
same string entries plus :class:`JsonPrimitiveValue` entries for
``true``, ``false``, and ``null``.
"""

from __future__ import annotations

import pytest

from scanner.json_locator import (
    JsonPrimitiveValue,
    JsonScanError,
    JsonStringValue,
    scan_json_leaf_values,
    scan_json_string_values,
)


def test_bare_true_is_reported_with_position():
    text = '{".read": true}'
    results = scan_json_leaf_values(text)
    assert results == [
        JsonPrimitiveValue(
            path=(".read",),
            key=".read",
            value="true",
            line=1,
            column=2,
        )
    ]


def test_bare_false_and_null_are_reported():
    text = '{".read": false, ".write": null}'
    results = scan_json_leaf_values(text)
    values = [(r.key, r.value) for r in results]
    assert values == [(".read", "false"), (".write", "null")]


def test_string_and_bare_boolean_can_coexist_in_output():
    text = '{".read": "auth != null", ".write": true}'
    results = scan_json_leaf_values(text)
    assert len(results) == 2
    read, write = results
    assert isinstance(read, JsonStringValue)
    assert read.value == "auth != null"
    assert isinstance(write, JsonPrimitiveValue)
    assert write.value == "true"


def test_nested_bare_boolean_carries_full_path():
    text = "{\n" '  "rules": {\n' '    "users": {\n' '      ".read": true\n' "    }\n" "  }\n" "}"
    results = scan_json_leaf_values(text)
    assert len(results) == 1
    entry = results[0]
    assert entry.path == ("rules", "users", ".read")
    assert entry.value == "true"
    assert entry.line == 4


def test_numbers_are_still_not_reported():
    # ``.timeout: 30`` is not a permission-carrying value; leaving
    # numbers unemitted keeps the output focused on what analyzers
    # actually consume.
    text = '{".read": true, "timeout": 30}'
    results = scan_json_leaf_values(text)
    kinds = [type(r).__name__ for r in results]
    assert kinds == ["JsonPrimitiveValue"]


def test_string_only_scanner_ignores_bare_booleans():
    # Backward-compatibility guard: ``scan_json_string_values`` must
    # keep its original behavior of returning only string leaves.
    # Callers that already rely on it (dangerous-key scan for
    # ``".read": "true"``) must not start seeing new entries.
    text = '{".read": true, ".write": "true"}'
    results = scan_json_string_values(text)
    assert len(results) == 1
    assert results[0].value == "true"
    assert results[0].key == ".write"


def test_identifier_that_starts_with_true_is_not_matched():
    # A key whose value is a longer identifier such as ``trueish``
    # must not be silently accepted as ``true``. Any such input is
    # malformed JSON and should raise.
    with pytest.raises(JsonScanError):
        scan_json_leaf_values('{".read": trueish}')


def test_boolean_at_end_of_object_without_trailing_space_is_matched():
    text = '{".read":true}'
    results = scan_json_leaf_values(text)
    assert len(results) == 1
    assert results[0].value == "true"


def test_boolean_in_array_position_is_not_emitted():
    # Bare booleans inside arrays are consumed but not emitted, mirroring
    # how bare string array elements are handled. Callers only care
    # about key/value pairs.
    text = '{"flags": [true, false, null]}'
    results = scan_json_leaf_values(text)
    assert results == []


def test_line_position_after_multi_line_boolean_stays_accurate():
    text = "{\n" '  ".read": true,\n' '  ".write": true\n' "}"
    results = scan_json_leaf_values(text)
    assert [r.line for r in results] == [2, 3]
