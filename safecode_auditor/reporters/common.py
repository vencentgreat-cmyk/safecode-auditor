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
}


def normalize_finding(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(finding, Finding):
        return finding.to_dict()

    rule_name = str(finding.get("rule", "Unknown"))
    rule_id = SECRET_RULE_IDS.get(rule_name) or CONFIG_RULE_IDS.get(rule_name)
    if rule_id is None:
        rule_id = "GEN001"
    raw_line = finding.get("line", 1)
    line = raw_line if isinstance(raw_line, int) else 1
    category = "secret" if rule_id.startswith("SEC") else "configuration"
    severity = str(finding.get("severity", "HIGH")).upper()
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "title": rule_name,
        "severity": severity,
        "confidence": "HIGH",
        "category": category,
        "description": str(finding.get("content", "")),
        "explanation": str(finding.get("content", "")),
        "location": {
            "file": str(finding.get("file", "")),
            "start_line": line,
            "start_column": 1,
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
