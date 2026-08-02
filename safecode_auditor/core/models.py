"""Stable, typed finding models used by SafeCode Auditor."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Location:
    file: str
    start_line: int
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "file": self.file,
            "start_line": self.start_line,
            "start_column": self.start_column,
        }
        if self.end_line is not None:
            result["end_line"] = self.end_line
        if self.end_column is not None:
            result["end_column"] = self.end_column
        return result


@dataclass(frozen=True)
class Fix:
    description: str

    def to_dict(self) -> dict[str, str]:
        return {"description": self.description}


@dataclass(frozen=True, eq=False)
class Finding(Mapping[str, Any]):
    """A stable finding with a compatibility mapping for the original API."""

    rule_id: str
    rule_name: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    explanation: str
    location: Location
    fix: Fix
    path: str
    operations: tuple[str, ...]
    condition: str | None
    category: str = "firebase-security-rules"

    def to_legacy_dict(self) -> dict[str, Any]:
        """Return the public dictionary shape used by versions through 0.1."""
        return {
            "file": self.location.file,
            "path": self.path,
            "operations": list(self.operations),
            "condition": self.condition,
            "vuln_type": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "explanation": self.explanation,
            "fix": self.fix.description,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the versioned JSON representation used by reporters."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "description": self.description,
            "explanation": self.explanation,
            "location": self.location.to_dict(),
            "path": self.path,
            "operations": list(self.operations),
            "condition": self.condition,
            "fix": self.fix.to_dict(),
        }

    def __getitem__(self, key: str) -> Any:
        if key == "rule_id":
            return self.rule_id
        if key == "confidence":
            return self.confidence.value
        if key == "location":
            return self.location.to_dict()
        if key == "line":
            return self.location.start_line
        return self.to_legacy_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_legacy_dict())

    def __len__(self) -> int:
        return len(self.to_legacy_dict())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Finding):
            return self.to_dict() == other.to_dict()
        if isinstance(other, Mapping):
            return self.to_legacy_dict() == dict(other)
        return NotImplemented
