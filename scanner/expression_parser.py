from dataclasses import dataclass


class ExpressionSyntaxError(ValueError):
    """Raised when a Firebase rule expression cannot be tokenized or parsed."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: object
    position: int


@dataclass(frozen=True)
class Identifier:
    name: str


@dataclass(frozen=True)
class Literal:
    value: object


@dataclass(frozen=True)
class UnaryOp:
    operator: str
    operand: object


@dataclass(frozen=True)
class BinaryOp:
    operator: str
    left: object
    right: object


@dataclass(frozen=True)
class MemberAccess:
    obj: object
    property: object
    computed: bool = False


@dataclass(frozen=True)
class Call:
    callee: object
    arguments: list


@dataclass(frozen=True)
class ArrayLiteral:
    elements: list


KEYWORDS = {
    "true": True,
    "false": False,
    "null": None,
}

MULTI_CHAR_TOKENS = {
    "&&": "AND",
    "||": "OR",
    "==": "EQ",
    "!=": "NE",
    "<=": "LE",
    ">=": "GE",
}

SINGLE_CHAR_TOKENS = {
    "(": "LPAREN",
    ")": "RPAREN",
    "[": "LBRACKET",
    "]": "RBRACKET",
    ",": "COMMA",
    ".": "DOT",
    "!": "NOT",
    "<": "LT",
    ">": "GT",
}


def tokenize(expression):
    tokens = []
    i = 0

    while i < len(expression):
        char = expression[i]

        if char.isspace():
            i += 1
            continue

        two_char = expression[i:i + 2]
        if two_char in MULTI_CHAR_TOKENS:
            tokens.append(Token(MULTI_CHAR_TOKENS[two_char], two_char, i))
            i += 2
            continue

        if char in SINGLE_CHAR_TOKENS:
            tokens.append(Token(SINGLE_CHAR_TOKENS[char], char, i))
            i += 1
            continue

        if char in "\"'":
            token, i = _read_string(expression, i)
            tokens.append(token)
            continue

        if char.isdigit():
            token, i = _read_number(expression, i)
            tokens.append(token)
            continue

        if char.isalpha() or char in "_$":
            token, i = _read_identifier(expression, i)
            tokens.append(token)
            continue

        raise ExpressionSyntaxError(
            f"Unexpected character {char!r} at position {i}"
        )

    tokens.append(Token("EOF", None, len(expression)))
    return tokens


def _read_string(expression, start):
    quote = expression[start]
    chars = []
    i = start + 1

    while i < len(expression):
        char = expression[i]
        if char == "\\":
            i += 1
            if i >= len(expression):
                break
            escape = expression[i]
            chars.append(
                {
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "\\": "\\",
                    "'": "'",
                    '"': '"',
                }.get(escape, escape)
            )
            i += 1
            continue
        if char == quote:
            return Token("STRING", "".join(chars), start), i + 1
        chars.append(char)
        i += 1

    raise ExpressionSyntaxError(f"Unterminated string starting at position {start}")


def _read_number(expression, start):
    i = start
    has_dot = False

    while i < len(expression):
        char = expression[i]
        if char == "." and not has_dot:
            has_dot = True
            i += 1
            continue
        if not char.isdigit():
            break
        i += 1

    raw = expression[start:i]
    value = float(raw) if "." in raw else int(raw)
    return Token("NUMBER", value, start), i


def _read_identifier(expression, start):
    i = start
    while i < len(expression):
        char = expression[i]
        if not (char.isalnum() or char in "_$"):
            break
        i += 1

    raw = expression[start:i]
    if raw in KEYWORDS:
        kind = "BOOLEAN" if isinstance(KEYWORDS[raw], bool) else "NULL"
        return Token(kind, KEYWORDS[raw], start), i
    if raw == "in":
        return Token("IN", raw, start), i
    return Token("IDENT", raw, start), i


class ExpressionParser:
    def __init__(self, expression):
        self.expression = expression
        self.tokens = tokenize(expression)
        self.index = 0

    def parse(self):
        node = self._parse_or()
        if not self._match("EOF"):
            token = self._peek()
            raise ExpressionSyntaxError(
                f"Unexpected token {token.value!r} at position {token.position}"
            )
        return node

    def _parse_or(self):
        node = self._parse_and()
        while self._match("OR"):
            operator = self._previous().value
            right = self._parse_and()
            node = BinaryOp(operator, node, right)
        return node

    def _parse_and(self):
        node = self._parse_equality()
        while self._match("AND"):
            operator = self._previous().value
            right = self._parse_equality()
            node = BinaryOp(operator, node, right)
        return node

    def _parse_equality(self):
        node = self._parse_in()
        while self._match("EQ", "NE"):
            operator = self._previous().value
            right = self._parse_in()
            node = BinaryOp(operator, node, right)
        return node

    def _parse_in(self):
        node = self._parse_comparison()
        while self._match("IN"):
            operator = self._previous().value
            right = self._parse_comparison()
            node = BinaryOp(operator, node, right)
        return node

    def _parse_comparison(self):
        node = self._parse_unary()
        while self._match("LT", "LE", "GT", "GE"):
            operator = self._previous().value
            right = self._parse_unary()
            node = BinaryOp(operator, node, right)
        return node

    def _parse_unary(self):
        if self._match("NOT"):
            operator = self._previous().value
            return UnaryOp(operator, self._parse_unary())
        return self._parse_postfix()

    def _parse_postfix(self):
        node = self._parse_primary()

        while True:
            if self._match("DOT"):
                token = self._consume("IDENT", "Expected property name after '.'.")
                node = MemberAccess(node, Identifier(token.value))
                continue

            if self._match("LBRACKET"):
                property_node = self._parse_or()
                self._consume("RBRACKET", "Expected ']' after computed property.")
                node = MemberAccess(node, property_node, computed=True)
                continue

            if self._match("LPAREN"):
                arguments = []
                if not self._check("RPAREN"):
                    while True:
                        arguments.append(self._parse_or())
                        if not self._match("COMMA"):
                            break
                self._consume("RPAREN", "Expected ')' after arguments.")
                node = Call(node, arguments)
                continue

            return node

    def _parse_primary(self):
        if self._match("BOOLEAN", "NULL", "NUMBER", "STRING"):
            return Literal(self._previous().value)

        if self._match("IDENT"):
            return Identifier(self._previous().value)

        if self._match("LPAREN"):
            node = self._parse_or()
            self._consume("RPAREN", "Expected ')' after expression.")
            return node

        if self._match("LBRACKET"):
            elements = []
            if not self._check("RBRACKET"):
                while True:
                    elements.append(self._parse_or())
                    if not self._match("COMMA"):
                        break
            self._consume("RBRACKET", "Expected ']' after array literal.")
            return ArrayLiteral(elements)

        token = self._peek()
        raise ExpressionSyntaxError(
            f"Unexpected token {token.value!r} at position {token.position}"
        )

    def _match(self, *kinds):
        if self._check(*kinds):
            self.index += 1
            return True
        return False

    def _check(self, *kinds):
        return self._peek().kind in kinds

    def _consume(self, kind, message):
        if self._check(kind):
            self.index += 1
            return self._previous()
        token = self._peek()
        raise ExpressionSyntaxError(f"{message} Found {token.value!r} at position {token.position}")

    def _peek(self):
        return self.tokens[self.index]

    def _previous(self):
        return self.tokens[self.index - 1]


def parse_expression(expression):
    return ExpressionParser(expression).parse()


def ast_to_dict(node):
    if isinstance(node, Identifier):
        return {"type": "Identifier", "name": node.name}
    if isinstance(node, Literal):
        return {"type": "Literal", "value": node.value}
    if isinstance(node, UnaryOp):
        return {
            "type": "UnaryOp",
            "operator": node.operator,
            "operand": ast_to_dict(node.operand),
        }
    if isinstance(node, BinaryOp):
        return {
            "type": "BinaryOp",
            "operator": node.operator,
            "left": ast_to_dict(node.left),
            "right": ast_to_dict(node.right),
        }
    if isinstance(node, MemberAccess):
        return {
            "type": "MemberAccess",
            "object": ast_to_dict(node.obj),
            "property": ast_to_dict(node.property),
            "computed": node.computed,
        }
    if isinstance(node, Call):
        return {
            "type": "Call",
            "callee": ast_to_dict(node.callee),
            "arguments": [ast_to_dict(argument) for argument in node.arguments],
        }
    if isinstance(node, ArrayLiteral):
        return {
            "type": "ArrayLiteral",
            "elements": [ast_to_dict(element) for element in node.elements],
        }
    return {"type": type(node).__name__}
