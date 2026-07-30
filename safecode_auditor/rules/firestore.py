"""Canonical Firestore rule definitions and finding construction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from safecode_auditor.core.models import (
    Confidence,
    Finding,
    Fix,
    Location,
    Severity,
)


@dataclass(frozen=True)
class RuleContext:
    file: str
    path: str
    wildcards: tuple[str, ...]
    operations: tuple[str, ...]
    condition: str | None
    condition_ast: Any
    offset: int
    line: int
    column: int
    ast_parsed: bool
    signals: dict[str, bool]


Predicate = Callable[[RuleContext], bool]


@dataclass(frozen=True)
class FirestoreRule:
    rule_id: str
    name: str
    title: str
    severity: Severity
    description: str
    explanation: str
    predicate: Predicate

    def evaluate(self, context: RuleContext) -> Finding | None:
        if not self.predicate(context):
            return None
        confidence = Confidence.HIGH if context.ast_parsed else Confidence.LOW
        if context.condition is None:
            confidence = Confidence.HIGH
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            title=self.title,
            severity=self.severity,
            confidence=confidence,
            description=self.description,
            explanation=self.explanation,
            location=Location(
                file=context.file,
                start_line=context.line,
                start_column=context.column,
            ),
            fix=Fix(_fix_for(self.name, context.wildcards)),
            path=context.path,
            operations=context.operations,
            condition=context.condition,
        )


def _is_open(context: RuleContext) -> bool:
    return context.condition is None or context.signals["literal_true"]


def _weak_uid(context: RuleContext) -> bool:
    return context.signals["has_weak_uid"] and not context.signals["has_owner"]


def _auth_no_owner(context: RuleContext) -> bool:
    return (
        context.signals["has_auth"]
        and not context.signals["has_owner"]
        and context.signals["is_user_path"]
        and not context.signals["has_custom_function"]
        and bool({"read", "get", "list"} & set(context.operations))
    )


def _write_no_validation(context: RuleContext) -> bool:
    return (
        bool({"write", "create", "update"} & set(context.operations))
        and context.signals["has_auth"]
        and not context.signals["has_custom_function"]
        and not context.signals["has_validation"]
    )


FIRESTORE_RULES = (
    FirestoreRule(
        "FIRE001",
        "OpenAccess",
        "Public access is allowed",
        Severity.CRITICAL,
        "Collection is fully open to the public, no authentication required.",
        "Using 'if true' allows anyone on the internet to read or write data without any credentials.",
        _is_open,
    ),
    FirestoreRule(
        "FIRE004",
        "WeakUidCheck",
        "UID existence is used as authorization",
        Severity.MEDIUM,
        "UID check uses != null instead of == userId.",
        "'request.auth.uid != null' only checks that a UID exists, not that it matches the resource owner. Any logged-in user passes this check.",
        _weak_uid,
    ),
    FirestoreRule(
        "FIRE002",
        "AuthButNoOwner",
        "Authenticated users are not restricted to owned data",
        Severity.HIGH,
        "Authentication is required but any logged-in user can access all other users' data.",
        "Checking 'request.auth != null' only verifies the user is logged in. It does NOT prevent user A from reading user B's private data.",
        _auth_no_owner,
    ),
    FirestoreRule(
        "FIRE003",
        "WriteWithoutValidation",
        "Writes are accepted without data validation",
        Severity.HIGH,
        "Write operation has no data validation.",
        "Allowing writes without validating request.resource.data means users can write any data structure, including malicious payloads.",
        _write_no_validation,
    ),
)


def _fix_for(name: str, wildcards: tuple[str, ...]) -> str:
    uid_var = wildcards[-1] if wildcards else "userId"
    if name == "OpenAccess":
        return (
            "Replace 'if true' with an authentication check:\n"
            f"  allow read: if request.auth != null && request.auth.uid == {uid_var};"
        )
    if name == "AuthButNoOwner":
        return (
            "Add owner check to bind the user to their own data:\n"
            "  // Current (vulnerable):  if request.auth != null\n"
            "  // Fixed:\n"
            f"  allow read: if request.auth != null && request.auth.uid == {uid_var};"
        )
    if name == "WeakUidCheck":
        return (
            "Replace '!= null' with an equality check against the path variable:\n"
            "  // Current (vulnerable):  if request.auth.uid != null\n"
            "  // Fixed:\n"
            f"  allow read: if request.auth.uid == {uid_var};"
        )
    if name == "WriteWithoutValidation":
        return (
            "Add data validation to write rules:\n"
            f"  allow write: if request.auth.uid == {uid_var}\n"
            "               && request.resource.data.keys().hasOnly(['field1', 'field2']);"
        )
    return "Review this rule manually."
