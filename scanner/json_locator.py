"""Locate string-valued leaves in a JSON document with source positions.

The Python standard :mod:`json` module parses JSON but does not expose
the line and column where each key or value appears in the source. This
module provides a small hand-written scanner that yields the source
position of every string-valued leaf, using nothing outside the standard
library.

The output is designed to feed configuration-file security checks that
need to point at the exact location of a dangerous key/value pair, e.g.
``.read: "true"`` in ``database.rules.json``.

Two public entry points are provided:

* :func:`scan_json_string_values` returns only string leaves. This is
  the original API and its behavior is preserved unchanged.
* :func:`scan_json_leaf_values` additionally emits boolean and null
  leaves as :class:`JsonPrimitiveValue`. Firebase Realtime Database
  rules commonly use bare booleans (``.read: true``) instead of the
  string form, and this second entry point lets downstream analysis
  see both without a second parse.
"""

from __future__ import annotations

from dataclasses import dataclass


class JsonScanError(ValueError):
    """Raised when the input is not well-formed JSON."""


@dataclass(frozen=True)
class JsonStringValue:
    """A string-valued leaf in a JSON document, with its source location.

    ``path`` is the JSON path from the document root. Object keys appear
    as ``str`` elements, array indices as ``int`` elements. The last
    element of ``path`` is the same string as ``key``.

    ``line`` and ``column`` are 1-based and point at the opening quote
    of the *key*, because that is where a human reader visually locates
    a key/value pair.
    """

    path: tuple
    key: str
    value: str
    line: int
    column: int


@dataclass(frozen=True)
class JsonPrimitiveValue:
    """A boolean- or null-valued leaf in a JSON document, with source location.

    Firebase Realtime Database rules commonly use bare boolean literals
    (``".read": true``) instead of the equivalent string form
    (``".read": "true"``). :class:`JsonStringValue` covers the second
    form; this class covers the first, together with ``false`` and
    ``null``, so callers can reason about both without a second parse.

    ``value`` is the raw JSON literal as text — ``"true"``, ``"false"``,
    or ``"null"`` — not a Python bool. Keeping it as text lets the same
    downstream code path treat ``".read": "true"`` (string) and
    ``".read": true`` (bare) uniformly.

    ``line`` and ``column`` follow the same 1-based convention as
    :class:`JsonStringValue`: they point at the opening quote of the
    *key*.
    """

    path: tuple
    key: str
    value: str
    line: int
    column: int


def scan_json_string_values(text: str) -> list[JsonStringValue]:
    """Return every string-valued leaf reachable from the root value.

    Traverses nested objects and arrays. Numbers, booleans, and null
    values are skipped because the current callers only compare against
    string values. String elements that appear as bare array items (not
    inside an object) are also skipped for the same reason.

    Raises :class:`JsonScanError` on malformed input, including trailing
    data after the root value.
    """

    scanner = _Scanner(text, include_primitives=False)
    scanner.run()
    return scanner.results


def scan_json_leaf_values(text: str) -> list:
    """Return every string, boolean, or null leaf reachable from the root.

    Same walking rules as :func:`scan_json_string_values`, but also
    emits :class:`JsonPrimitiveValue` entries for ``true``, ``false``,
    and ``null``. Numbers are still skipped: current callers only
    reason about permission-carrying values.

    The returned list preserves discovery order and may mix
    :class:`JsonStringValue` and :class:`JsonPrimitiveValue` instances.
    """

    scanner = _Scanner(text, include_primitives=True)
    scanner.run()
    return scanner.results


class _Scanner:
    __slots__ = (
        "text",
        "n",
        "pos",
        "line",
        "col",
        "results",
        "include_primitives",
    )

    def __init__(self, text: str, include_primitives: bool = False) -> None:
        self.text = text
        self.n = len(text)
        self.pos = 0
        self.line = 1
        self.col = 1
        self.results: list = []
        self.include_primitives = include_primitives

    def run(self) -> None:
        self._skip_ws()
        if self.pos >= self.n:
            raise JsonScanError("empty input")
        self._parse_value(())
        self._skip_ws()
        if self.pos != self.n:
            raise JsonScanError(f"unexpected data at line {self.line}, column {self.col}")

    # ---- character advancement -------------------------------------

    def _advance(self, count: int = 1) -> None:
        # Advance ``count`` characters, updating line and column.
        # ``\r\n`` counts as a single newline; a lone ``\r`` also counts
        # as a newline (JSON does not standardise this, but treating it
        # consistently is safer than counting it as a plain character).
        for _ in range(count):
            if self.pos >= self.n:
                return
            ch = self.text[self.pos]
            if ch == "\r":
                self.line += 1
                self.col = 1
                self.pos += 1
                if self.pos < self.n and self.text[self.pos] == "\n":
                    self.pos += 1
            elif ch == "\n":
                self.line += 1
                self.col = 1
                self.pos += 1
            else:
                self.col += 1
                self.pos += 1

    def _skip_ws(self) -> None:
        while self.pos < self.n and self.text[self.pos] in " \t\n\r":
            self._advance()

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < self.n else ""

    def _expect(self, ch: str) -> None:
        if self._peek() != ch:
            raise JsonScanError(f"expected {ch!r} at line {self.line}, column {self.col}")
        self._advance()

    def _starts_with(self, literal: str) -> bool:
        return self.text.startswith(literal, self.pos)

    def _peek_primitive_literal(self) -> str | None:
        """Return ``"true"``, ``"false"``, or ``"null"`` if one starts here.

        The literal must be terminated by a JSON structural character
        (``,``, ``]``, ``}``, or whitespace) or end-of-input. Otherwise
        an identifier like ``trueish`` would be misparsed as the boolean
        ``true`` followed by garbage.
        """
        for literal in ("true", "false", "null"):
            if self._starts_with(literal):
                end = self.pos + len(literal)
                if end == self.n or self.text[end] in ",]} \t\n\r":
                    return literal
        return None

    # ---- value dispatch --------------------------------------------

    def _parse_value(self, path: tuple) -> None:
        self._skip_ws()
        ch = self._peek()
        if ch == "{":
            self._parse_object(path)
        elif ch == "[":
            self._parse_array(path)
        elif ch == '"':
            # Bare string at value position — reachable only from an
            # array element. Consumed but not emitted: current callers
            # only care about object key/string-value pairs.
            self._read_string()
        elif ch == "-" or ch.isdigit():
            self._skip_number()
        elif self._starts_with("true"):
            self._advance(4)
        elif self._starts_with("false"):
            self._advance(5)
        elif self._starts_with("null"):
            self._advance(4)
        else:
            raise JsonScanError(
                f"unexpected character {ch!r} at line {self.line}, column {self.col}"
            )

    def _skip_number(self) -> None:
        start = self.pos
        while self.pos < self.n and self.text[self.pos] in "-+0123456789.eE":
            self._advance()
        if self.pos == start:
            raise JsonScanError(f"invalid number at line {self.line}, column {self.col}")

    def _parse_object(self, path: tuple) -> None:
        self._expect("{")
        self._skip_ws()
        if self._peek() == "}":
            self._advance()
            return
        while True:
            self._skip_ws()
            if self._peek() != '"':
                raise JsonScanError(f"expected string key at line {self.line}, column {self.col}")
            key_line, key_col = self.line, self.col
            key = self._read_string()
            self._skip_ws()
            self._expect(":")
            self._skip_ws()
            child_path = path + (key,)
            if self._peek() == '"':
                value = self._read_string()
                self.results.append(
                    JsonStringValue(
                        path=child_path,
                        key=key,
                        value=value,
                        line=key_line,
                        column=key_col,
                    )
                )
            elif self.include_primitives:
                literal = self._peek_primitive_literal()
                if literal is not None:
                    self.results.append(
                        JsonPrimitiveValue(
                            path=child_path,
                            key=key,
                            value=literal,
                            line=key_line,
                            column=key_col,
                        )
                    )
                    self._advance(len(literal))
                else:
                    self._parse_value(child_path)
            else:
                self._parse_value(child_path)
            self._skip_ws()
            if self._peek() == ",":
                self._advance()
                continue
            if self._peek() == "}":
                self._advance()
                return
            raise JsonScanError(f"expected ',' or '}}' at line {self.line}, column {self.col}")

    def _parse_array(self, path: tuple) -> None:
        self._expect("[")
        self._skip_ws()
        if self._peek() == "]":
            self._advance()
            return
        index = 0
        while True:
            self._parse_value(path + (index,))
            self._skip_ws()
            if self._peek() == ",":
                self._advance()
                index += 1
                continue
            if self._peek() == "]":
                self._advance()
                return
            raise JsonScanError(f"expected ',' or ']' at line {self.line}, column {self.col}")

    # ---- string reader ---------------------------------------------

    def _read_string(self) -> str:
        # Called with the cursor at the opening ``"``. Returns the
        # unescaped string value. Position is advanced past the closing
        # ``"``. Raises :class:`JsonScanError` on unterminated strings
        # or invalid escapes.
        self._expect('"')
        chars: list[str] = []
        while self.pos < self.n:
            ch = self.text[self.pos]
            if ch == '"':
                self._advance()
                return "".join(chars)
            if ch == "\\":
                self._advance()
                if self.pos >= self.n:
                    raise JsonScanError(
                        f"unterminated escape at line {self.line}, column {self.col}"
                    )
                esc = self.text[self.pos]
                mapping = {
                    '"': '"',
                    "\\": "\\",
                    "/": "/",
                    "b": "\b",
                    "f": "\f",
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                }
                if esc in mapping:
                    chars.append(mapping[esc])
                    self._advance()
                elif esc == "u":
                    self._advance()
                    if self.pos + 4 > self.n:
                        raise JsonScanError(
                            f"truncated \\u escape at line {self.line}, column {self.col}"
                        )
                    hex4 = self.text[self.pos : self.pos + 4]
                    try:
                        codepoint = int(hex4, 16)
                    except ValueError as exc:
                        raise JsonScanError(
                            f"invalid \\u escape at line {self.line}, column {self.col}"
                        ) from exc
                    chars.append(chr(codepoint))
                    self._advance(4)
                else:
                    raise JsonScanError(
                        f"invalid escape \\{esc} at line {self.line}, column {self.col}"
                    )
            elif ch in "\n\r":
                raise JsonScanError(f"unterminated string at line {self.line}, column {self.col}")
            else:
                chars.append(ch)
                self._advance()
        raise JsonScanError(f"unterminated string at line {self.line}, column {self.col}")
