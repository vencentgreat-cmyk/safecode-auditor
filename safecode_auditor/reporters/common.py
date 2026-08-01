"""Shared conversion helpers for reporters."""

from __future__ import annotations

import os
from typing import Any

from safecode_auditor.core.models import Finding

SECRET_RULE_IDS = {
    "OpenAI API Key": "SEC001",
    "AWS Access Key": "SEC002",
    "AWS Secret Key": "SEC003",
    "GitHub Token": "SEC004",
    "Hardcoded Password": "SEC005",
    "Database URL": "SEC006",
    "Generic Secret": "SEC007",
}

CONFIG_RULE_IDS = {
    "Exposed ENV Secret": "CFG001",
    "Exposed Database URL": "CFG002",
    "Exposed Password in ENV": "CFG003",
    "Docker Hardcoded Password": "CFG004",
    "Docker Hardcoded Secret": "CFG005",
    "Firebase: Unrestricted read access": "CFG006",
    "Firebase: Unrestricted write access": "CFG007",
    "Firebase: Overridden child rule under permissive ancestor": "CFG008",
}

SENSITIVE_RULE_IDS = {
    "SEC001",
    "SEC002",
    "SEC003",
    "SEC004",
    "SEC005",
    "SEC006",
    "SEC007",
    "CFG001",
    "CFG002",
    "CFG003",
    "CFG004",
    "CFG005",
}

REDACTED_SECRET = "[REDACTED: sensitive value omitted]"


def redact_finding_content(rule_id: str, content: Any) -> str:
    """Hide source text for findings that may contain credentials."""
    if rule_id in SENSITIVE_RULE_IDS:
        return REDACTED_SECRET
    return str(content)


def normalize_finding(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(finding, Finding):
        normalized = finding.to_dict()
        rule_id = normalized["rule_id"]
        normalized["description"] = redact_finding_content(
            rule_id,
            normalized["description"],
        )
        normalized["explanation"] = redact_finding_content(
            rule_id,
            normalized["explanation"],
        )
        return normalized

    rule_name = str(finding.get("rule", "Unknown"))
    rule_id = SECRET_RULE_IDS.get(rule_name) or CONFIG_RULE_IDS.get(rule_name)
    if rule_id is None:
        rule_id = "GEN001"

    raw_line = finding.get("line", 1)
    line = raw_line if isinstance(raw_line, int) else 1
    raw_column = finding.get("column", 1)
    column = raw_column if isinstance(raw_column, int) else 1
    category = "secret" if rule_id.startswith("SEC") else "configuration"
    severity = str(finding.get("severity", "HIGH")).upper()
    safe_content = redact_finding_content(
        rule_id,
        finding.get("content", ""),
    )

    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "title": rule_name,
        "severity": severity,
        "confidence": "HIGH",
        "category": category,
        "description": safe_content,
        "explanation": safe_content,
        "location": {
            "file": str(finding.get("file", "")),
            "start_line": line,
            "start_column": column,
        },
        "path": None,
        "operations": [],
        "condition": None,
        "fix": {"description": str(finding.get("fix", ""))},
    }


def sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = finding["location"]
    return (
        os.path.normcase(location["file"]),
        location["start_line"],
        location.get("start_column", 1),
        finding["rule_id"],
    )
