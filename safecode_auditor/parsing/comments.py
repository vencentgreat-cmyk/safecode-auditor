"""Comment handling that preserves source offsets."""

from __future__ import annotations


def strip_comments_preserve_offsets(source: str) -> str:
    """Replace comment characters with spaces while preserving length/newlines.

    Quote-delimited strings are retained verbatim, so URL-like values containing
    ``//`` are not mistaken for comments.
    """

    result = list(source)
    state = "code"
    quote = ""
    escaped = False
    i = 0

    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char in {"'", '"'}:
                state = "string"
                quote = char
                escaped = False
            elif char == "/" and next_char == "/":
                result[i] = " "
                result[i + 1] = " "
                state = "line_comment"
                i += 1
            elif char == "/" and next_char == "*":
                result[i] = " "
                result[i + 1] = " "
                state = "block_comment"
                i += 1
        elif state == "string":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                result[i] = " "
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                result[i] = " "
                result[i + 1] = " "
                state = "code"
                i += 1
            elif char not in {"\n", "\r"}:
                result[i] = " "
        i += 1

    cleaned = "".join(result)
    assert len(cleaned) == len(source)
    return cleaned
