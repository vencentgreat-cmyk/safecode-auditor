import json
import os
import re

from safecode_auditor.parsing.comments import strip_comments_preserve_offsets
from safecode_auditor.rules.firestore import FIRESTORE_RULES, RuleContext

try:
    from .expression_parser import (
        ArrayLiteral,
        BinaryOp,
        Call,
        ExpressionSyntaxError,
        Identifier,
        Literal,
        MemberAccess,
        UnaryOp,
        parse_expression,
    )
except ImportError:
    from expression_parser import (
        ArrayLiteral,
        BinaryOp,
        Call,
        ExpressionSyntaxError,
        Identifier,
        Literal,
        MemberAccess,
        UnaryOp,
        parse_expression,
    )


class MatchBlock:
    """Represents a single match block in Firebase Rules."""

    def __init__(self, path, wildcards, rules, children, offset):
        self.path = path
        self.wildcards = wildcards
        self.rules = rules
        self.children = children
        self.offset = offset

    def __repr__(self):
        return f"MatchBlock(path={self.path}, " f"wildcards={self.wildcards}, rules={self.rules})"


class FirebaseRuleAnalyzer:
    """
    Parses Firebase Security Rules and detects logical vulnerabilities.

    Goes beyond simple keyword matching to understand rule structure
    and context.
    """

    def __init__(self):
        self.findings = []
        self._source = ""
        self._filepath = "firestore.rules"

    def parse(self, content):
        """Parse raw rules content into a list of MatchBlock trees."""
        self._source = content
        cleaned = strip_comments_preserve_offsets(content)
        return self._parse_blocks(cleaned, base_offset=0)

    def _extract_block(self, content, start):
        """
        Return block content and the index immediately after its
        closing brace.
        """
        depth = 1
        i = start
        quote = None
        escaped = False

        while i < len(content) and depth > 0:
            char = content[i]

            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1

            i += 1

        return content[start : i - 1], i

    def _parse_blocks(self, content, base_offset=0):
        """Recursively parse all match blocks in content."""
        blocks = []
        pattern = re.compile(r"match\s+((?:/[\w{}\-=*]+)+)\s*\{")

        i = 0
        while i < len(content):
            match = pattern.search(content, i)
            if not match:
                break

            path = match.group(1)
            block_start = match.end()
            block_content, block_end = self._extract_block(content, block_start)
            absolute_block_start = base_offset + block_start

            if "/databases/" in path and "/documents" in path:
                blocks.extend(
                    self._parse_blocks(
                        block_content,
                        absolute_block_start,
                    )
                )
                i = block_end
                continue

            wildcards = re.findall(r"\{(\w+)(?:=\*\*)?\}", path)
            rules = self._parse_rules(
                block_content,
                absolute_block_start,
            )
            children = self._parse_blocks(
                block_content,
                absolute_block_start,
            )

            blocks.append(
                MatchBlock(
                    path,
                    wildcards,
                    rules,
                    children,
                    base_offset + match.start(),
                )
            )
            i = block_end

        return blocks

    def _mask_nested_matches(self, content):
        """Blank nested match blocks without changing offsets."""
        result = list(content)
        pattern = re.compile(r"match\s+((?:/[\w{}\-=*]+)+)\s*\{")
        i = 0

        while True:
            match = pattern.search(content, i)
            if not match:
                break

            _, end = self._extract_block(content, match.end())

            for index in range(match.start(), end):
                if result[index] not in {"\n", "\r"}:
                    result[index] = " "

            i = end

        return "".join(result)

    def _parse_rules(self, content, base_offset):
        """Extract allow rules from a block, ignoring nested blocks."""
        clean = self._mask_nested_matches(content)

        rules = []
        pattern = re.compile(
            r"allow\s+([\w,\s]+)\s*:\s*if\s+(.+?);",
            re.DOTALL,
        )

        for match in pattern.finditer(clean):
            operations = [operation.strip() for operation in match.group(1).split(",")]
            condition = match.group(2).strip()

            rules.append(
                {
                    "operations": operations,
                    "condition": condition,
                    "condition_ast": self._parse_condition_ast(condition),
                    "offset": base_offset + match.start(),
                }
            )

        bare = re.compile(r"allow\s+([\w,\s]+)\s*;")

        for match in bare.finditer(clean):
            preceding = clean[max(0, match.start() - 5) : match.end()]
            if ": if" in preceding:
                continue

            operations = [operation.strip() for operation in match.group(1).split(",")]

            rules.append(
                {
                    "operations": operations,
                    "condition": None,
                    "condition_ast": None,
                    "offset": base_offset + match.start(),
                }
            )

        return rules

    def _parse_condition_ast(self, condition):
        """Parse a condition string into an AST node."""
        if not condition:
            return None

        try:
            return parse_expression(condition)
        except ExpressionSyntaxError:
            return None

    def analyze(self, content, filepath="firestore.rules"):
        """Main entry point: parse and analyze a rules file."""
        self.findings = []
        self._filepath = filepath
        blocks = self.parse(content)

        for block in blocks:
            self._analyze_block(block, filepath)

        return self.findings

    def _analyze_block(self, block, filepath):
        """Analyze a single MatchBlock for vulnerabilities."""
        for rule in block.rules:
            condition = rule["condition"]
            operations = rule["operations"]
            condition_ast = rule.get("condition_ast")
            offset = rule["offset"]
            line, column = self._line_column(offset)

            signals = self._condition_signals(
                condition,
                condition_ast,
                block.path,
                block.wildcards,
            )

            context = RuleContext(
                file=filepath,
                path=block.path,
                wildcards=tuple(block.wildcards),
                operations=tuple(operations),
                condition=condition,
                condition_ast=condition_ast,
                offset=offset,
                line=line,
                column=column,
                ast_parsed=(condition is None or condition_ast is not None),
                signals=signals,
            )

            for definition in FIRESTORE_RULES:
                finding = definition.evaluate(context)
                if finding is not None:
                    self.findings.append(finding)
                    break

        for child in block.children:
            self._analyze_block(child, filepath)

    def _line_column(self, offset):
        line_start = self._source.rfind("\n", 0, offset)
        line = self._source.count("\n", 0, offset) + 1
        column = offset - line_start
        return line, column

    def _condition_signals(
        self,
        condition,
        condition_ast,
        path,
        wildcards,
    ):
        path_context = f"{path} {' '.join(wildcards)}".lower()
        is_user_path = any(
            keyword in path_context
            for keyword in [
                "user",
                "member",
                "account",
                "profile",
                "person",
            ]
        )

        if condition is None:
            return {
                "literal_true": True,
                "has_auth": False,
                "has_owner": False,
                "has_weak_uid": False,
                "has_validation": False,
                "has_custom_function": False,
                "is_user_path": is_user_path,
            }

        if condition_ast is not None:
            return {
                "literal_true": self._is_unconditionally_true(condition_ast),
                "has_auth": self._has_auth_check(condition_ast),
                "has_owner": self._has_owner_check(
                    condition_ast,
                    wildcards,
                ),
                "has_weak_uid": self._has_weak_uid_check(condition_ast),
                "has_validation": self._has_write_validation(condition_ast),
                "has_custom_function": (self._has_custom_function_call(condition_ast)),
                "is_user_path": is_user_path,
            }

        compact = re.sub(r"\s+", "", condition)

        has_owner = any(
            f"request.auth.uid=={wildcard}" in compact or f"{wildcard}==request.auth.uid" in compact
            for wildcard in wildcards
        )

        has_validation = bool(
            re.search(
                r"request\.resource\.data(?:\.\w+|\[)",
                compact,
            )
        )

        return {
            "literal_true": compact == "true",
            "has_auth": "request.auth" in compact,
            "has_owner": has_owner,
            "has_weak_uid": ("request.auth.uid!=null" in compact),
            "has_validation": has_validation,
            "has_custom_function": bool(
                re.search(
                    r"\b(?!request|resource)\w+\s*\(",
                    condition,
                )
            ),
            "is_user_path": is_user_path,
        }

    def _is_unconditionally_true(self, node):
        """Return whether an AST expression is always true."""
        if isinstance(node, Literal):
            return node.value is True

        if isinstance(node, UnaryOp) and node.operator == "!":
            return self._is_unconditionally_false(node.operand)

        if isinstance(node, BinaryOp):
            if node.operator == "||":
                return self._is_unconditionally_true(node.left) or self._is_unconditionally_true(
                    node.right
                )

            if node.operator == "&&":
                return self._is_unconditionally_true(node.left) and self._is_unconditionally_true(
                    node.right
                )

        return False

    def _is_unconditionally_false(self, node):
        """Return whether an AST expression is always false."""
        if isinstance(node, Literal):
            return node.value is False

        if isinstance(node, UnaryOp) and node.operator == "!":
            return self._is_unconditionally_true(node.operand)

        if isinstance(node, BinaryOp):
            if node.operator == "&&":
                return self._is_unconditionally_false(node.left) or self._is_unconditionally_false(
                    node.right
                )

            if node.operator == "||":
                return self._is_unconditionally_false(node.left) and self._is_unconditionally_false(
                    node.right
                )

        return False

    def _condition_guarantees(self, node, predicate):
        """
        Determine whether a security predicate is guaranteed on every
        logical path that can make the condition true.
        """
        if node is None:
            return False

        if isinstance(node, UnaryOp):
            if node.operator == "!":
                return False

            return self._condition_guarantees(
                node.operand,
                predicate,
            )

        if isinstance(node, BinaryOp):
            if node.operator == "&&":
                return self._condition_guarantees(
                    node.left,
                    predicate,
                ) or self._condition_guarantees(
                    node.right,
                    predicate,
                )

            if node.operator == "||":
                return self._condition_guarantees(
                    node.left,
                    predicate,
                ) and self._condition_guarantees(
                    node.right,
                    predicate,
                )

        if predicate(node):
            return True

        for current, negated in self._walk_with_negation(node):
            if current is node or negated:
                continue

            if predicate(current):
                return True

        return False

    def _has_write_validation(self, node):
        """
        Return whether every successful logical branch guarantees
        a recognized write-data validation.
        """
        validation_methods = {
            "hasOnly",
            "hasAll",
            "hasAny",
            "matches",
            "size",
        }

        def is_validation(current):
            if not isinstance(current, Call):
                return False

            if not isinstance(current.callee, MemberAccess):
                return False

            property_node = current.callee.property
            if not isinstance(property_node, Identifier):
                return False

            if property_node.name not in validation_methods:
                return False

            return self._contains_reference(
                current,
                ["request", "resource", "data"],
            )

        return self._condition_guarantees(
            node,
            is_validation,
        )

    def _has_auth_check(self, node):
        """Check if the AST contains an authentication check."""
        for current in self._walk(node):
            if not isinstance(current, BinaryOp):
                continue

            if current.operator == "!=":
                if self._is_auth_null_pair(
                    current.left,
                    current.right,
                ):
                    return True

                if self._is_auth_null_pair(
                    current.right,
                    current.left,
                ):
                    return True

            if current.operator == "==":
                left_is_uid = self._node_has_path(
                    current.left,
                    ["request", "auth", "uid"],
                )
                right_is_uid = self._node_has_path(
                    current.right,
                    ["request", "auth", "uid"],
                )

                if left_is_uid and isinstance(current.right, Identifier):
                    return True

                if right_is_uid and isinstance(current.left, Identifier):
                    return True

        return False

    def _has_owner_check(self, node, wildcards):
        """
        Return whether every successful logical branch guarantees
        an ownership equality.
        """

        def is_owner_check(current):
            if not isinstance(current, BinaryOp) or current.operator != "==":
                return False

            return (
                self._is_uid_owner_pair(
                    current.left,
                    current.right,
                    wildcards,
                )
                or self._is_uid_owner_pair(
                    current.right,
                    current.left,
                    wildcards,
                )
                or self._is_uid_resource_owner_field_pair(
                    current.left,
                    current.right,
                )
                or self._is_uid_resource_owner_field_pair(
                    current.right,
                    current.left,
                )
            )

        return self._condition_guarantees(
            node,
            is_owner_check,
        )

    def _has_weak_uid_check(self, node):
        """Check if the AST contains a weak UID check."""
        for current in self._walk(node):
            if isinstance(current, BinaryOp) and current.operator in {"==", "!="}:
                if self._is_uid_null_pair(
                    current.left,
                    current.right,
                ):
                    return True

                if self._is_uid_null_pair(
                    current.right,
                    current.left,
                ):
                    return True

            if isinstance(current, UnaryOp) and self._node_has_path(
                current.operand,
                ["request", "auth", "uid"],
            ):
                return True

        return False

    def _has_custom_function_call(self, node):
        """Check if the AST contains a custom function call."""
        for current in self._walk(node):
            if not isinstance(current, Call):
                continue

            root_name = self._root_identifier_name(current.callee)

            if root_name not in {"request", "resource"}:
                return True

        return False

    def _contains_reference(self, node, path_prefix):
        """Check whether the AST contains a path prefix."""
        for current in self._walk(node):
            if self._node_has_prefix(current, path_prefix):
                return True

        return False

    def _is_uid_owner_pair(self, left, right, wildcards):
        """
        Check if left is request.auth.uid and right is a path
        wildcard.
        """
        if not self._node_has_path(
            left,
            ["request", "auth", "uid"],
        ):
            return False

        return isinstance(right, Identifier) and right.name in set(wildcards)

    def _is_uid_resource_owner_field_pair(
        self,
        left,
        right,
    ):
        """
        Check whether left is request.auth.uid and right is an
        owner field in resource.data.
        """
        owner_field_paths = (
            ["resource", "data", "uid"],
            ["resource", "data", "userId"],
            ["resource", "data", "ownerId"],
            ["resource", "data", "accountId"],
            ["resource", "data", "memberId"],
            ["resource", "data", "profileId"],
        )

        return (
            self._node_has_path(
                left,
                ["request", "auth", "uid"],
            )
            and self._node_path(right) in owner_field_paths
        )

    def _is_uid_null_pair(self, left, right):
        """Check if left is request.auth.uid and right is null."""
        return (
            self._node_has_path(
                left,
                ["request", "auth", "uid"],
            )
            and isinstance(right, Literal)
            and right.value is None
        )

    def _is_auth_null_pair(self, left, right):
        """Check if left is request.auth or its UID and right is null."""
        auth_is_null = (
            self._node_has_path(
                left,
                ["request", "auth"],
            )
            and isinstance(right, Literal)
            and right.value is None
        )

        uid_is_null = (
            self._node_has_path(
                left,
                ["request", "auth", "uid"],
            )
            and isinstance(right, Literal)
            and right.value is None
        )

        return auth_is_null or uid_is_null

    def _node_has_path(self, node, path):
        """Check if node represents exactly the given path."""
        return self._node_path(node) == path

    def _node_has_prefix(self, node, path_prefix):
        """Check if the node path starts with the given prefix."""
        path = self._node_path(node)
        return path is not None and path[: len(path_prefix)] == path_prefix

    def _node_path(self, node):
        """Extract the path of a node as a list of strings."""
        if isinstance(node, Identifier):
            return [node.name]

        if isinstance(node, MemberAccess):
            base = self._node_path(node.obj)
            if base is None:
                return None

            if isinstance(node.property, Identifier):
                return base + [node.property.name]

            if (
                node.computed
                and isinstance(node.property, Literal)
                and isinstance(node.property.value, str)
            ):
                return base + [node.property.value]

        return None

    def _root_identifier_name(self, node):
        """Get the root identifier name of a node."""
        path = self._node_path(node)
        if path:
            return path[0]

        if isinstance(node, Call):
            return self._root_identifier_name(node.callee)

        if isinstance(node, MemberAccess):
            return self._root_identifier_name(node.obj)

        return None

    def _walk_with_negation(self, node, negated=False):
        """Walk the AST while tracking logical negation."""
        if node is None:
            return

        yield node, negated

        if isinstance(node, UnaryOp):
            child_negated = negated
            if node.operator == "!":
                child_negated = not negated

            yield from self._walk_with_negation(
                node.operand,
                child_negated,
            )

        elif isinstance(node, BinaryOp):
            yield from self._walk_with_negation(
                node.left,
                negated,
            )
            yield from self._walk_with_negation(
                node.right,
                negated,
            )

        elif isinstance(node, MemberAccess):
            yield from self._walk_with_negation(
                node.obj,
                negated,
            )
            yield from self._walk_with_negation(
                node.property,
                negated,
            )

        elif isinstance(node, Call):
            yield from self._walk_with_negation(
                node.callee,
                negated,
            )

            for argument in node.arguments:
                yield from self._walk_with_negation(
                    argument,
                    negated,
                )

        elif isinstance(node, ArrayLiteral):
            for element in node.elements:
                yield from self._walk_with_negation(
                    element,
                    negated,
                )

    def _walk(self, node):
        """Walk the AST tree, yielding all nodes."""
        if node is None:
            return

        yield node

        if isinstance(node, UnaryOp):
            yield from self._walk(node.operand)

        elif isinstance(node, BinaryOp):
            yield from self._walk(node.left)
            yield from self._walk(node.right)

        elif isinstance(node, MemberAccess):
            yield from self._walk(node.obj)
            yield from self._walk(node.property)

        elif isinstance(node, Call):
            yield from self._walk(node.callee)

            for argument in node.arguments:
                yield from self._walk(argument)

        elif isinstance(node, ArrayLiteral):
            for element in node.elements:
                yield from self._walk(element)


# ── Module-level entry points ──────────────────────────────────────────


def scan_firebase_file(filepath):
    """Entry point compatible with the rest of the scanner pipeline."""
    try:
        with open(
            filepath,
            encoding="utf-8",
            errors="ignore",
        ) as file:
            content = file.read()
    except Exception:
        return []

    analyzer = FirebaseRuleAnalyzer()
    return analyzer.analyze(content, filepath)


def scan_firebase_directory(directory):
    """Scan a directory for all Firebase rules files."""
    if os.path.isfile(directory):
        return scan_firebase_file(directory)

    findings = []
    target_names = {
        "firestore.rules",
        "database.rules.json",
        "firebase.rules",
    }

    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(
            directory_name
            for directory_name in dirs
            if directory_name
            not in {
                "node_modules",
                ".git",
                "__pycache__",
            }
        )

        for filename in sorted(files):
            if filename.lower() in target_names or filename.endswith(".rules"):
                filepath = os.path.join(root, filename)
                findings.extend(scan_firebase_file(filepath))

    return findings


def discover_from_firebase_json(project_dir: str) -> list[str]:
    """Return the list of discovered rules file paths from firebase.json.

    Supports the standard ``"database"`` and ``"firestore"`` keys
    whose values are objects with a ``"rules"`` property pointing at a
    relative path.  Returns an empty list when ``firebase.json`` does
    not exist, is malformed, or contains no recognised rules paths.

    Path containment is verified via ``os.path.realpath`` and
    ``os.path.commonpath``, which correctly rejects sibling-prefix
    attacks (``project`` vs ``project-escape``), ``..`` traversal,
    absolute paths pointing outside the project, and symlink escapes.
    """
    config_path = os.path.join(project_dir, "firebase.json")
    if not os.path.isfile(config_path):
        return []

    try:
        with open(config_path, encoding="utf-8", errors="ignore") as fh:
            payload = json.loads(fh.read())
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(payload, dict):
        return []

    rules_files: list[str] = []
    seen: set[str] = set()
    real_project = os.path.realpath(project_dir)

    for section_key in ("database", "firestore"):
        section = payload.get(section_key)
        if not isinstance(section, dict):
            continue
        rules_path = section.get("rules")
        if not isinstance(rules_path, str) or not rules_path.strip():
            continue
        # Resolve relative to the firebase.json directory.
        candidate = os.path.normpath(
            os.path.join(project_dir, rules_path)
        )
        # Resolve to real path (follows symlinks) and check containment
        # using common-path semantics, which correctly rejects sibling-
        # prefix attacks (e.g. project vs project-escape), .. traversal,
        # absolute paths outside the project, and symlink escapes.
        try:
            resolved = os.path.realpath(candidate)
        except OSError:
            continue
        try:
            common = os.path.commonpath([real_project, resolved])
        except ValueError:
            # Paths on different drives on Windows — reject.
            continue
        if common != real_project:
            continue
        if os.path.isfile(candidate) and candidate not in seen:
            seen.add(candidate)
            rules_files.append(candidate)

    return rules_files
