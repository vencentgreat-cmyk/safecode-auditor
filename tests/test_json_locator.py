"""Unit tests for the JSON locator.

Covers happy path, nested paths, duplicate key names at different paths,
strings containing text that looks like keys (must not be recognised as
keys), CRLF line endings, empty containers, escape sequences, and
malformed input.
"""

import pytest

from scanner.json_locator import (
    JsonScanError,
    JsonStringValue,
    scan_json_string_values,
)


def test_flat_object_records_key_position():
    text = '{".read": "true"}'
    results = scan_json_string_values(text)
    assert results == [
        JsonStringValue(
            path=(".read",),
            key=".read",
            value="true",
            line=1,
            column=2,
        )
    ]


def test_nested_object_records_full_path():
    text = '{"rules": {"users": {".read": "true"}}}'
    results = scan_json_string_values(text)
    assert len(results) == 1
    assert results[0].path == ("rules", "users", ".read")
    assert results[0].key == ".read"
    assert results[0].value == "true"


def test_key_position_across_multiple_lines():
    text = "{\n" '  "rules": {\n' '    ".read": "true"\n' "  }\n" "}"
    results = scan_json_string_values(text)
    assert len(results) == 1
    entry = results[0]
    assert entry.line == 3
    # opening quote of ".read" is at column 5 (four spaces of indent)
    assert entry.column == 5


def test_duplicate_keys_at_different_paths_stay_distinct():
    text = "{\n" '  "a": {".read": "true"},\n' '  "b": {".read": "true"}\n' "}"
    results = scan_json_string_values(text)
    assert len(results) == 2
    paths = {r.path for r in results}
    assert paths == {("a", ".read"), ("b", ".read")}
    lines = sorted(r.line for r in results)
    assert lines == [2, 3]


def test_string_content_that_looks_like_a_key_is_not_a_key():
    # The inner text contains an escaped ".read": "true" sequence. It
    # must be treated as opaque string content, not as a separate pair.
    text = '{"note": "here is text with \\".read\\": \\"true\\" inside"}'
    results = scan_json_string_values(text)
    assert len(results) == 1
    assert results[0].key == "note"
    assert results[0].value == 'here is text with ".read": "true" inside'


def test_crlf_line_endings_are_counted_once():
    text = "{\r\n" + '  ".read": "true"\r\n' + "}"
    results = scan_json_string_values(text)
    assert len(results) == 1
    assert results[0].line == 2


def test_empty_object_returns_no_results():
    assert scan_json_string_values("{}") == []


def test_empty_array_returns_no_results():
    assert scan_json_string_values('{"list": []}') == []


def test_array_of_objects_records_each_entry_with_index_in_path():
    text = '{"list": [{"a": "x"}, {"a": "y"}]}'
    results = scan_json_string_values(text)
    paths_and_values = [(r.path, r.value) for r in results]
    assert paths_and_values == [
        (("list", 0, "a"), "x"),
        (("list", 1, "a"), "y"),
    ]


def test_bare_string_element_in_array_is_not_emitted():
    # Current callers only care about key/value pairs. Bare string
    # array elements are consumed but not emitted.
    text = '{"tags": ["a", "b"]}'
    assert scan_json_string_values(text) == []


def test_non_string_values_are_ignored():
    text = '{"n": 1, "b": true, "z": null, "arr": [1, 2, 3]}'
    assert scan_json_string_values(text) == []


def test_escape_sequences_do_not_break_position_tracking():
    # After a string containing an escaped newline, subsequent keys
    # must still report the correct source line — the escape is a
    # character in the string, not a real newline in the source.
    text = "{\n" '  "note": "line \\n continues",\n' '  ".read": "true"\n' "}"
    results = scan_json_string_values(text)
    read_entry = next(r for r in results if r.key == ".read")
    assert read_entry.line == 3


def test_unicode_escape_is_decoded():
    text = '{"k": "a\\u00e9b"}'
    results = scan_json_string_values(text)
    assert results[0].value == "aéb"


def test_invalid_json_raises_json_scan_error():
    with pytest.raises(JsonScanError):
        scan_json_string_values('{"unterminated": ')


def test_trailing_data_raises_json_scan_error():
    with pytest.raises(JsonScanError):
        scan_json_string_values('{"a": "b"} garbage')


def test_empty_input_raises_json_scan_error():
    with pytest.raises(JsonScanError):
        scan_json_string_values("")


def test_unterminated_string_raises_json_scan_error():
    with pytest.raises(JsonScanError):
        scan_json_string_values('{"k": "no close')
